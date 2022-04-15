#include "log.hpp"
#include "smt.hpp"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/MapVector.h>
#include <llvm/ADT/SetVector.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>

#include <z3++.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
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

struct crange : public ConstantRange {
    /// https://llvm.org/doxygen/classllvm_1_1ConstantRange.html
    using ConstantRange::ConstantRange;

    crange(uint32_t bw) // by default we assume it's full set.
        : ConstantRange(bw, true)
    {
    }

    crange(const ConstantRange& cr)
        : ConstantRange(cr)
    {
    }

    crange()
        : ConstantRange(0, true)
    {
    }
};

namespace {

struct func_range_info {
    SmallVector<crange, 4> arg_ranges;
    crange ret_range;
    std::map<BasicBlock*, std::map<Instruction*, crange>> bb_ranges;

    void init(const Function& F)
    {
        for (auto& arg : F.args()) {
            arg_ranges.push_back(crange(arg.getType()->getIntegerBitWidth()));
        }
    }
};

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

crange compute_range(const BinaryOperator* op, crange lhs, crange rhs)
{
    if (lhs.getBitWidth() < rhs.getBitWidth()) {
        lhs = lhs.zextOrTrunc(lhs.getBitWidth());
    } else if (lhs.getBitWidth() > rhs.getBitWidth()) {
        rhs = rhs.zextOrTrunc(rhs.getBitWidth());
    }

    switch (op->getOpcode()) {
    case Instruction::Add:
        return lhs.add(rhs);
    case Instruction::Sub:
        return lhs.sub(rhs);
    case Instruction::Mul:
        return lhs.multiply(rhs);
    case Instruction::UDiv:
        return lhs.udiv(rhs);
    case Instruction::SDiv:
        return lhs.sdiv(rhs);
    case Instruction::Shl:
        return lhs.shl(rhs);
    case Instruction::LShr:
        return lhs.lshr(rhs);
    case Instruction::AShr:
        return lhs.ashr(rhs);
    case Instruction::And:
        return lhs.binaryAnd(rhs);
    case Instruction::Or:
        return lhs.binaryOr(rhs);
    case Instruction::Xor:
        return lhs.binaryXor(rhs);
    case Instruction::URem:
        return lhs.urem(rhs);
    case Instruction::SRem:
        return lhs.srem(rhs);
    }

    MKINT_LOG() << "Unhandled opcode: " << op->getOpcodeName();

    return rhs;
}

struct MKintPass : public PassInfoMixin<MKintPass> {
    void taint_analysis(Function& F)
    {
        MKINT_LOG() << "Taint Analysis -> " << F.getName();
        // Mark (source) taint/sink;
        // * Note we must do this first b.c. this is a write pass.
        // * the remaining stuff will at most add some metadata.
        auto taint_sources = get_taint_source(F);
        // for now, the taint_source are not marked as taint.
        // because we only mark taints if sinks are reachable for a certain taint candidate.
        mark_func_sinks(F);
        taint_broadcasting(taint_sources);

        if (!taint_sources.empty())
            m_func2tsrc[F.getName()] = std::move(taint_sources);
    }

    bool range_analysis(const Function& F)
    {
        bool changed = false;
        // TODO: consider global symbols.
        std::vector<const BasicBlock*> worklist;
        worklist.push_back(&(F.getEntryBlock()));

        std::map<const BasicBlock*, std::map<const Instruction*, crange>> bb_range;

        while (!worklist.empty()) {
            auto bb = worklist.back();
            worklist.pop_back();

            for (auto& inst : bb->getInstList()) {
                if (auto op = dyn_cast<BinaryOperator>(&inst)) {
                    auto lhs = op->getOperand(0);
                    auto rhs = op->getOperand(1);

                    crange lhs_range {}, rhs_range {};
                    if (auto lconst = dyn_cast<ConstantInt>(lhs)) {
                        lhs_range = crange(lconst->getValue());
                    } else if (auto linst = dyn_cast<Instruction>(lhs)) {
                        lhs_range = bb_range[bb][linst];
                    } else {
                        MKINT_CHECK_ABORT(false) << "Unknown operand type: " << lhs->getName();
                    }

                    if (auto rconst = dyn_cast<ConstantInt>(rhs)) {
                        rhs_range = crange(rconst->getValue());
                    } else if (auto rinst = dyn_cast<Instruction>(rhs)) {
                        rhs_range = bb_range[bb][rinst];
                    } else {
                        MKINT_CHECK_ABORT(false) << "Unknown operand type: " << lhs->getName();
                    }

                    bb_range[bb][&inst] = compute_range(op, lhs_range, rhs_range);
                }
            }
        }

        return changed;
    }

    PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM)
    {
        MKINT_LOG() << "Running MKint pass on module " << M.getName();

        for (auto& F : M) {
            taint_analysis(F);
        } // no writes anymore (except writing metadata).

        constexpr size_t max_try = 128;
        size_t try_count = 0;
        // initialize range ananlysis
        for (auto& F : M) {
            auto& rinfo = m_func2range_info[&F];
            rinfo.init(F);
        }

        while (true) { // iterative range analysis.
            bool changed = false;
            for (auto& F : M) {
                changed |= range_analysis(F);
            }
            if (!changed)
                break;
            if (++try_count > max_try) {
                MKINT_LOG() << "[Iterative Range Analysis] "
                            << "Max try " << max_try << " reached, aborting.";
                break;
            }
        }

        return PreservedAnalyses::all();
    }

private:
    MapVector<StringRef, std::vector<Instruction*>> m_func2tsrc;
    std::map<Function*, func_range_info> m_func2range_info;
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
