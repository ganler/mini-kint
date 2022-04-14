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

template <typename V, typename... Vs> static constexpr std::array<V, sizeof...(Vs)> mkarray(Vs&&... vs) noexcept
{
    return std::array<V, sizeof...(Vs)> { vs... };
}

constexpr auto MKINT_SINKS = mkarray<std::pair<std::string_view, size_t>>(
    std::pair { "kmalloc", 0 }, std::pair { "kzalloc", 0 }, std::pair { "vmalloc", 0 });

namespace {

enum class interr {
    OUT_OF_BOUND,
    DIV_BY_ZERO,
    BAD_SHIFT,
    NEG_IDX,
    VIOLATE_ANN,
};

template <interr err, typename StrRet = const char*> constexpr StrRet mkstr()
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
        static_assert(err == interr::OUT_OF_BOUND || err == interr::DIV_BY_ZERO || err == interr::BAD_SHIFT
                || err == interr::NEG_IDX || err == interr::VIOLATE_ANN,
            "unknown error type");
        return ""; // statically impossible
    }
}

template <interr err_t> static void mark_err(Instruction& inst)
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

static std::vector<Instruction*> get_taint_source(Function& F)
{
    std::vector<Instruction*> ret;
    // judge if this function is the taint source.
    const auto name = F.getName();
    if (name.startswith("sys_") || (name.startswith("__mkint_ann_") && !name.contains(".mkint.arg"))) {
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
            auto call_inst = CallInst::Create(F.getParent()->getOrInsertFunction(call_name, itype), arg.getName(),
                &*F.getEntryBlock().getFirstInsertionPt());
            ret.push_back(call_inst);
            arg.replaceAllUsesWith(call_inst);
        }
    }
    return ret;
}

static bool is_sink_reachable(Instruction* inst)
{
    // we want to only mark sink-reachable taints; and
    // find out if the return value is tainted.
    if (nullptr == inst) {
        return false;
    } else if (inst->getMetadata(MKINT_IR_SINK)) {
        return true;
    }

    bool you_see_sink /* ? */ = false;
    for (auto user : inst->users()) {
        if (auto user_inst = dyn_cast<Instruction>(user)) {
            you_see_sink |= is_sink_reachable(user_inst);
        }
    }

    if (you_see_sink) {
        mark_taint(*inst);
        return true;
    }

    return false;
}

static void taint_broadcasting(const std::vector<Instruction*>& taint_source)
{
    // ? Note we currently assume that sub-func-calls do not have sinks...
    // ? otherwise we need a use-def tree to do the job (but too complicated).
    // Propogation: This pass should only consider single-function-level tainting.
    //              In `out = call(..., taint, ...)`, `out` is tainted. But let's
    //              refine that in cross-function-level tainting.

    // Algo: should do depth-first search until we find a sink. If we find a sink,
    //       we backtrack and mark taints.

    for (auto ts : taint_source) {
        if (is_sink_reachable(ts)) {
            mark_taint(*ts, "source");
        }
    }
}

static void mark_func_sinks(Function& F)
{
    static auto mark_sink = [](Instruction& inst, std::string_view sink_name) {
        auto& ctx = inst.getContext();
        auto md = MDNode::get(ctx, MDString::get(ctx, sink_name));
        inst.setMetadata(MKINT_IR_SINK, md);
    };

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
}

struct MKintPass : public PassInfoMixin<MKintPass> {
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& FAM)
    {
        MKINT_LOG() << "Running MKint pass on function " << F.getName();

        auto& ctx = F.getContext();

        // MiniPass 1: Mark (source) taint/sink;
        // * Note we must do this first b.c. this is a write pass.
        // * the remaining stuff will at most add some metadata.
        auto taint_sources = get_taint_source(F);
        // for now, the taint_source are not marked as taint.
        // because we only mark taints if sinks are reachable for a certain taint candidate.
        mark_func_sinks(F);

        // MiniPass 2: Broadcast taint;
        taint_broadcasting(taint_sources);
        // TODO: MiniPass 3: Collect constraints;

        // TODO: -> Move to module pass!
        // TODO: MiniPass 4: Traverse the paths and solve constraints;
        // TODO:           : Add mkint.err label if violation detected.

        // FIXME: This is some dummy code to test.
        // auto&& bb = F.getEntryBlock();
        // for (auto& inst : bb) {
        //     mark_err<interr::OUT_OF_BOUND>(inst);
        // }

        return PreservedAnalyses::all(); // TODO: I actually cannot tell which analysis are preserved.
    }

    PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM)
    {
        MKINT_LOG() << "Running MKint pass on module " << M.getName();

        for (auto& F : M) {
            run(F, MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager());
        }

        return PreservedAnalyses::all();
    }
};
} // namespace

// registering pass (new pass manager).
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo()
{
    return { LLVM_PLUGIN_API_VERSION, "MKintPass", "v0.1", [](PassBuilder& PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager& MPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "mkint-pass") {
                            MPM.addPass(MKintPass());
                            return true;
                        }
                        return false;
                    });
            } };
}

// the version number must match!
// get llvm ir: clang -Os -S -emit-llvm a.c
// test: opt -load-pass-plugin mkint/MiniKintPass.so -passes=mkint-pass -S a.ll
