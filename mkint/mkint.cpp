#include "log.hpp"
#include "smt.hpp"

#include <llvm/ADT/SetVector.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

#include <array>
#include <iostream>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace llvm;

// TODO: consider constraints from annotation;
// TODO: consider sink annotation;

constexpr const char* MKINT_IR_TAINT = "mkint.taint";
constexpr const char* MKINT_IR_SINK = "mkint.sink";
constexpr const char* MKINT_IR_ERR = "mkint.err";

template <typename V, typename... Vs>
static constexpr std::array<V, sizeof...(Vs)> mkarray(Vs&&... vs) noexcept
{
    return std::array<V, sizeof...(Vs)> { vs... };
}

constexpr auto MKINT_SINKS = mkarray<std::pair<std::string_view, size_t>>(
    std::pair { "kmalloc", 0 },
    std::pair { "kzalloc", 0 },
    std::pair { "vmalloc", 0 });

namespace {

enum class interr {
    OUT_OF_BOUND,
    DIV_BY_ZERO,
    BAD_SHIFT,
    NEG_IDX,
    VIOLATE_ANN,
};

template <interr err, typename StrRet = const char*>
constexpr StrRet mkstr()
{
    if constexpr (err == interr::OUT_OF_BOUND) {
        return "out of boundary";
    } else if (err == interr::DIV_BY_ZERO) {
        return "divide by zero";
    } else if (err == interr::BAD_SHIFT) {
        return "bad shift";
    } else if (err == interr::NEG_IDX) {
        return "negative index";
    } else if (err == interr::VIOLATE_ANN) {
        return "annotation violation";
    } else {
        static_assert(
            err == interr::OUT_OF_BOUND || err == interr::DIV_BY_ZERO || err == interr::BAD_SHIFT || err == interr::NEG_IDX || err == interr::VIOLATE_ANN,
            "unknown error type");
        return ""; // statically impossible
    }
}

template <interr err_t>
static void mark_err(Instruction& inst)
{
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, mkstr<err_t>()));
    inst.setMetadata(MKINT_IR_ERR, md);
}

static void mark_taint(Instruction& inst, std::string_view taint_name = "")
{
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, taint_name));
    inst.setMetadata(MKINT_IR_TAINT, md);
}

static void mark_sink(Instruction& inst, std::string_view sink_name = "")
{
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, sink_name));
    inst.setMetadata(MKINT_IR_SINK, md);
}

std::vector<Instruction*> mark_taint_source(Function& F)
{
    std::vector<Instruction*> ret;
    // judge if this function is the taint source.
    const auto name = F.getName();
    if (name.startswith("sys_") || name.startswith("__mkint_ann_")) {
        // mark all this function as a taint source.
        // Unfortunately arguments cannot be marked with metadata...
        // We need to rewrite the arguments -> unary callers and mark the callers.
        for (auto& arg : F.args()) {
            auto itype = dyn_cast<IntegerType>(arg.getType());
            if (nullptr == itype || arg.use_empty()) {
                continue;
            }
            auto call_name = name.str() + ".mkint.arg" + std::to_string(arg.getArgNo());
            MKINT_LOG() << "Replacing taint arg -> call inst: " << call_name;
            auto call_inst = CallInst::Create(
                F.getParent()->getOrInsertFunction(call_name, itype),
                arg.getName(),
                &*F.getEntryBlock().getFirstInsertionPt());
            mark_taint(*call_inst);
            ret.push_back(call_inst);
            arg.replaceAllUsesWith(call_inst);
        }
    }
    return ret;
}

static void taint_broadcasting(
    const std::vector<Instruction*>& taint_source)
{
    // TODO: Consider global variable;
    // TODO: Consider function arguments;
    SetVector<Instruction*> marked_taints {};
    auto taint_worklist = taint_source;
    while (!taint_worklist.empty()) {
        auto inst = taint_worklist.back();
        taint_worklist.pop_back();

        for (auto user : inst->users()) {
            if (auto user_inst = dyn_cast<Instruction>(user)) {
                if (user_inst->getMetadata(MKINT_IR_TAINT) || user_inst->getMetadata(MKINT_IR_SINK)) {
                    continue;
                }

                if (auto call_inst = dyn_cast<CallInst>(user_inst)) {
                    // call(a0, a1, ...): broadcast taints to a[?] if a[?] is tainted.
                    if (auto callf = call_inst->getCalledFunction()) {
                        SetVector<Instruction*> callf_taints {};
                        for (size_t i = 0; i < callf->arg_size(); ++i) {
                            auto operand = call_inst->getArgOperand(i);
                            if (auto call_inst_arg_inst = dyn_cast<Instruction>(operand)) {
                                if (call_inst_arg_inst->getMetadata(MKINT_IR_TAINT)) {
                                    // do broadcasting.
                                    for (auto callf_u : callf->getArg(i)->users()) {
                                        if (auto callf_u_inst = dyn_cast<Instruction>(callf_u)) {
                                            if (!callf_u_inst->getMetadata(MKINT_IR_TAINT)) {
                                                mark_taint(*callf_u_inst);
                                                callf_taints.insert(callf_u_inst);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        taint_broadcasting(callf_taints.takeVector());
                    }
                }

                mark_taint(*user_inst);
                marked_taints.insert(user_inst);
                taint_worklist.push_back(user_inst);
            }
        }
    }
}

struct MKintPass : public PassInfoMixin<MKintPass> {
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& FAM)
    {
        MKINT_LOG() << "Running MKint pass on function " << F.getName();

        auto& ctx = F.getContext();

        // MiniPass 1: Mark (source) taint/sink;
        auto taint_sources = mark_taint_source(F);
        for (auto& inst : instructions(F)) {
            if (auto* call = dyn_cast<CallInst>(&inst)) {
                // call in MKINT_SINKS
                for (const auto& [name, idx] : MKINT_SINKS) {
                    if (call->getCalledFunction()->getName().startswith(name)) {
                        if (auto inst = dyn_cast_or_null<Instruction>(call->getArgOperand(idx))) {
                            mark_sink(*inst, name);
                        }
                        break;
                    }
                }
            }
        }
        // MiniPass 2: Broadcast taint;
        taint_broadcasting(taint_sources);
        // TODO:           : Mark instructions to check and checking type;
        // TODO: MiniPass 3: Collect constraints and solve;
        // TODO:           : Remove label if violation not sat;

        // FIXME: This is some dummy code to test.
        // auto&& bb = F.getEntryBlock();
        // for (auto& inst : bb) {
        //     mark_err<interr::OUT_OF_BOUND>(inst);
        // }

        return PreservedAnalyses::all();
    }
};
} // namespace

// registering pass (new pass manager).
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo()
{
    return { LLVM_PLUGIN_API_VERSION, "MKintPass", "v0.1", [](PassBuilder& PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, FunctionPassManager& FPM,
                        ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "mkint-pass") {
                            FPM.addPass(MKintPass());
                            return true;
                        }
                        return false;
                    });
            } };
}

// the version number must match!
// get llvm ir: clang -Os -S -emit-llvm a.c
// test: opt -load-pass-plugin mkint/MiniKintPass.so -passes=mkint-pass -S a.ll