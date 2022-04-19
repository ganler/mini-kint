#include "log.hpp"
#include "smt.hpp"

#include <cxxabi.h>

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

static std::string demangle(const char* name)
{
    int status = -1;
    std::unique_ptr<char, void (*)(void*)> res { abi::__cxa_demangle(name, NULL, NULL, &status), std::free };
    return (status == 0) ? res.get() : std::string(name);
}

template <typename V, typename... Vs> static constexpr std::array<V, sizeof...(Vs)> mkarray(Vs&&... vs) noexcept
{
    return std::array<V, sizeof...(Vs)> { vs... };
}

constexpr auto MKINT_SINKS = mkarray<std::pair<const char*, size_t>>(
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

using bbrange_t = std::map<const BasicBlock*, std::map<const Value*, crange>>;

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
    const auto demangled_name = demangle(F.getName().str().c_str());
    const auto name = StringRef(demangled_name);
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
                const auto demangled_func_name = demangle(call->getCalledFunction()->getName().str().c_str());
                if (StringRef(demangled_func_name).startswith(name)) {
                    if (auto inst = dyn_cast_or_null<Instruction>(call->getArgOperand(idx))) {
                        mark_sink(*inst, name);
                    }
                    break;
                }
            }
        }
    }
}

std::pair<crange, crange> auto_promote(crange lhs, crange rhs) {
    if (lhs.getBitWidth() < rhs.getBitWidth()) {
        lhs = lhs.zextOrTrunc(lhs.getBitWidth());
    } else if (lhs.getBitWidth() > rhs.getBitWidth()) {
        rhs = rhs.zextOrTrunc(rhs.getBitWidth());
    }
    return std::make_pair(lhs, rhs);
}

crange compute_range(const BinaryOperator* op, crange lhs_, crange rhs_)
{

    auto [lhs, rhs] = auto_promote(std::move(lhs_), std::move(rhs_));

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

    void backedge_analysis(const Function& F)
    {
        for (const auto& bb_ref : F) {
            auto bb = &bb_ref;
            if (m_backedges.count(bb) == 0) {
                // compute backedges of bb
                m_backedges[bb] = {};
                std::vector<const BasicBlock*> remote_succs { bb };
                while (!remote_succs.empty()) {
                    auto cur_succ = remote_succs.back();
                    remote_succs.pop_back();
                    for (const auto succ : successors(cur_succ)) {
                        if (succ != bb && !m_backedges[bb].contains(succ)) {
                            m_backedges[bb].insert(succ);
                            remote_succs.push_back(succ);
                        }
                    }
                }
            }
        }
    }

    bool range_analysis(const Function& F)
    {
        MKINT_LOG() << "Range Analysis -> " << F.getName();
        bool changed = false;
        // TODO: consider global symbols.
        std::vector<const BasicBlock*> worklist;
        worklist.push_back(&(F.getEntryBlock()));

        auto& bb_range = m_func2range_info[&F];

        for (const auto& arg : F.args()) {
            if (arg.getType()->isIntegerTy() && bb_range[&(F.getEntryBlock())].count(&arg) == 0) {
                bb_range[&(F.getEntryBlock())][&arg] = crange(arg.getType()->getIntegerBitWidth());
            }
        }

        while (!worklist.empty()) {
            auto bb = worklist.back();
            worklist.pop_back();

            auto& cur_rng = bb_range[bb];

            // merge all incoming bbs
            for (const auto& pred : predecessors(bb)) {
                // avoid backedge: pred can't be a successor of bb.
                if (m_backedges[bb].contains(pred)) {
                    continue; // skip backedge
                }

                for (const auto& inst : pred->getInstList()) {
                    if (auto it = cur_rng.find(&inst); it == cur_rng.cend()) { // not found
                        cur_rng[&inst] = bb_range[pred][&inst];
                    } else { // merge
                        it->second = it->second.unionWith(bb_range[pred][&inst]);
                    }
                }
            }

            // TODO: check pred branch for conditions.

            for (auto& inst : bb->getInstList()) {
                const auto get_rng = [&bb_range, &bb, &inst](auto var) {
                    if (auto lconst = dyn_cast<ConstantInt>(var)) {
                        return crange(lconst->getValue());
                    } else {
                        if (bb_range[bb].count(var) == 0) {
                            std::string str;
                            llvm::raw_string_ostream(str) << *var << " in " << inst;
                            MKINT_CHECK_ABORT(false) << "Unknown operand type: " << str;
                        }
                        return bb_range[bb][var];
                    }
                };
                // TODO: handle void types:
                // Store / Call / Return

                // return type should be int
                if (!inst.getType()->isIntegerTy()) {
                    continue;
                }

                crange new_range;

                if (const BinaryOperator* op = dyn_cast<BinaryOperator>(&inst)) {
                    auto lhs = op->getOperand(0);
                    auto rhs = op->getOperand(1);

                    crange lhs_range = get_rng(lhs), rhs_range = get_rng(rhs);
                    new_range = compute_range(op, lhs_range, rhs_range);
                } else if (const SelectInst* op = dyn_cast<SelectInst>(&inst)) {
                    const auto tval = op->getTrueValue();
                    const auto fval = op->getFalseValue();
                    auto [lhs, rhs] = auto_promote(get_rng(tval), get_rng(fval));
                    new_range = lhs.unionWith(rhs);
                }

                bb_range[bb][&inst] = bb_range[bb][&inst].unionWith(new_range);
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

        for (auto& F : M) {
            if (!F.isDeclaration()) {
                backedge_analysis(F);
            }
        }

        while (true) { // iterative range analysis.
            bool changed = false;
            for (auto& F : M) {
                if (F.isDeclaration()) {
                    MKINT_LOG() << "Skip range analysis for declaration func: " << F.getName();
                    continue;
                }
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
    std::map<const Function*, bbrange_t> m_func2range_info;
    std::map<const BasicBlock*, SetVector<const BasicBlock*>> m_backedges;
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
