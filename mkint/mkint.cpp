#include "log.hpp"
#include "rang.hpp"
#include "smt.hpp"

#include <cxxabi.h>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/MapVector.h>
#include <llvm/ADT/SetVector.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Value.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

#include <z3++.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

using namespace llvm;

// TODO: consider constraints from annotation;

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

constexpr auto MKINT_SINKS = mkarray<std::pair<const char*, size_t>>(std::pair { "malloc", 0 },
    std::pair { "xmalloc", 0 }, std::pair { "kmalloc", 0 }, std::pair { "kzalloc", 0 }, std::pair { "vmalloc", 0 });

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

    static constexpr auto cmpRegion()
    {
        // makeAllowedICmpRegion: many false positives.
        return ConstantRange::makeAllowedICmpRegion;
        // makeSatisfyingICmpRegion: might miss some true positives.
        // return ConstantRange::makeSatisfyingICmpRegion;
    }
};

namespace {

using bbrange_t = DenseMap<const BasicBlock*, DenseMap<const Value*, crange>>;

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

static bool is_taint_src(StringRef sv)
{
    const auto demangled_name = demangle(sv.str().c_str());
    const auto name = StringRef(demangled_name);
    return name.startswith("sys_") || name.startswith("__mkint_ann_");
}

static std::vector<Instruction*> get_taint_source(Function& F)
{
    std::vector<Instruction*> ret;
    // judge if this function is the taint source.
    const auto name = F.getName();
    if (is_taint_src(name)) {
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

static bool is_taint_src_arg_call(StringRef s) { return s.contains(".mkint.arg"); }

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
                if (demangled_func_name == name) {
                    if (auto inst = dyn_cast_or_null<Instruction>(call->getArgOperand(idx))) {
                        MKINT_LOG() << "Marking sink: " << demangled_func_name;
                        mark_sink(*inst, name);
                    }
                    break;
                } else if (StringRef(demangled_func_name).startswith(name)) {
                    MKINT_WARN() << "Are you missing the sink? [demangled_func_name]: " << demangled_func_name
                                 << "; [name]: " << name;
                }
            }
        }
    }
}

std::pair<crange, crange> auto_promote(crange lhs, crange rhs)
{
    if (lhs.getBitWidth() < rhs.getBitWidth()) {
        lhs = lhs.zextOrTrunc(lhs.getBitWidth());
    } else if (lhs.getBitWidth() > rhs.getBitWidth()) {
        rhs = rhs.zextOrTrunc(rhs.getBitWidth());
    }
    return std::make_pair(lhs, rhs);
}

crange compute_binary_rng(const BinaryOperator* op, crange lhs_, crange rhs_)
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
    default:
        MKINT_LOG() << "Unhandled binary opcode: " << op->getOpcodeName();
    }

    return rhs;
}

struct MKintPass : public PassInfoMixin<MKintPass> {
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

    void range_analysis(const Function& F)
    {
        MKINT_LOG() << "Range Analysis -> " << F.getName();

        auto& bb_range = m_func2range_info[&F];

        for (const auto& bbref : F) {
            auto bb = &bbref;

            auto& cur_rng = bb_range[bb];

            const auto get_range_by_bb = [this, &bb_range](auto var, const BasicBlock* bb) -> crange {
                if (auto lconst = dyn_cast<ConstantInt>(var)) {
                    return crange(lconst->getValue());
                } else {
                    if (bb_range[bb].count(var) == 0) {
                        if (auto gv = dyn_cast<GlobalVariable>(var))
                            return m_global2range[gv];
                        MKINT_CHECK_ABORT(false) << "Unknown operand type: " << *var;
                    }
                    return bb_range[bb][var];
                }
            };

            // merge all incoming bbs
            for (const auto& pred : predecessors(bb)) {
                // avoid backedge: pred can't be a successor of bb.
                if (m_backedges[bb].contains(pred)) {
                    continue; // skip backedge
                }

                SetVector<const Value*> narrowed_insts;

                // branch or switch
                // NOTE: branch should be used to narrow the range.
                if (auto terminator = pred->getTerminator(); auto br = dyn_cast<BranchInst>(terminator)) {
                    if (br->isConditional()) {
                        if (auto cmp = dyn_cast<ICmpInst>(br->getCondition())) {
                            // br: a op b == true or false
                            // makeAllowedICmpRegion turning a op b into a range.
                            auto lhs = cmp->getOperand(0);
                            auto rhs = cmp->getOperand(1);

                            if (!lhs->getType()->isIntegerTy() || !rhs->getType()->isIntegerTy()) {
                                // This should be covered by `ICmpInst`.
                                MKINT_CHECK_ABORT(false) << "The br operands are not both integers: " << *cmp;
                                continue;
                            }

                            auto lrng = get_range_by_bb(lhs, pred), rrng = get_range_by_bb(rhs, pred);

                            if (cur_rng.count(lhs) == 0)
                                cur_rng[lhs] = crange(lhs->getType()->getIntegerBitWidth(), false);

                            if (cur_rng.count(rhs) == 0)
                                cur_rng[rhs] = crange(rhs->getType()->getIntegerBitWidth(), false);

                            if (br->getSuccessor(0) == bb) { // T branch
                                crange lprng = crange::cmpRegion()(cmp->getPredicate(), rrng);
                                crange rprng = crange::cmpRegion()(cmp->getSwappedPredicate(), lrng);

                                // Don't change constant's value.
                                cur_rng[lhs] = dyn_cast<ConstantInt>(lhs)
                                    ? lrng
                                    : lrng.intersectWith(lprng).unionWith(cur_rng[lhs]);
                                cur_rng[rhs] = dyn_cast<ConstantInt>(rhs)
                                    ? rrng
                                    : rrng.intersectWith(rprng).unionWith(cur_rng[rhs]);
                            } else { // F branch
                                crange lprng = crange::cmpRegion()(cmp->getInversePredicate(), rrng);
                                crange rprng
                                    = crange::cmpRegion()(CmpInst::getInversePredicate(cmp->getPredicate()), lrng);
                                // Don't change constant's value.
                                cur_rng[lhs] = dyn_cast<ConstantInt>(lhs)
                                    ? lrng
                                    : lrng.intersectWith(lprng).unionWith(cur_rng[lhs]);
                                cur_rng[rhs] = dyn_cast<ConstantInt>(rhs)
                                    ? rrng
                                    : rrng.intersectWith(rprng).unionWith(cur_rng[rhs]);
                            }

                            narrowed_insts.insert(lhs);
                            narrowed_insts.insert(rhs);
                        }
                    }
                } else if (auto swt = dyn_cast<SwitchInst>(terminator)) {
                    // switch
                    // ; Emulate a conditional br instruction
                    // %Val = zext i1 %value to i32
                    // switch i32 %Val, label %truedest [ i32 0, label %falsedest ]

                    // ; Emulate an unconditional br instruction
                    // switch i32 0, label %dest [ ]

                    // ; Implement a jump table:
                    // switch i32 %val, label %otherwise [ i32 0, label %onzero
                    //                                     i32 1, label %onone
                    //                                     i32 2, label %ontwo ]
                    auto cond = swt->getCondition();
                    if (!cond->getType()->isIntegerTy()) {
                        continue;
                    }

                    auto cond_rng = get_range_by_bb(cond, bb);
                    auto emp_rng = crange::getEmpty(cond->getType()->getIntegerBitWidth());

                    if (swt->getDefaultDest() == bb) { // default
                        // not (all)
                        for (auto c : swt->cases()) {
                            auto case_val = c.getCaseValue();
                            emp_rng = emp_rng.unionWith(case_val->getValue());
                        }
                        emp_rng = emp_rng.inverse();
                    } else {
                        for (auto c : swt->cases()) {
                            if (c.getCaseSuccessor() == bb) {
                                auto case_val = c.getCaseValue();
                                emp_rng = emp_rng.unionWith(case_val->getValue());
                            }
                        }
                    }

                    cur_rng[cond] = cond_rng.unionWith(emp_rng);
                    narrowed_insts.insert(cond);
                } else {
                    // try catch... (thank god, C does not have try-catch)
                    // indirectbr... ?
                    MKINT_CHECK_ABORT(false) << "Unknown terminator: " << *pred->getTerminator();
                }

                for (const auto& [inst, rng] : bb_range[pred]) {
                    // TODO: Optimization: No need to track all values.
                    if (!narrowed_insts.contains(inst)) { // for branched insts, the ranges is computed.
                        if (auto it = cur_rng.find(inst); it == cur_rng.end()) { // not found
                            cur_rng[inst] = rng;
                        } else { // merge
                            it->second = it->second.unionWith(rng);
                        }
                    }
                }
            }

            for (auto& inst : bb->getInstList()) {
                const auto get_rng = [&bb, get_range_by_bb](auto var) { return get_range_by_bb(var, bb); };
                // Store / Call / Return
                if (const auto call = dyn_cast<CallInst>(&inst)) {
                    if (const auto f = call->getCalledFunction()) {
                        for (const auto& arg : f->args()) {
                            auto& argblock = m_func2range_info[f][&(f->getEntryBlock())];
                            if (arg.getType()->isIntegerTy())
                                argblock[&arg] = get_rng(call->getArgOperand(arg.getArgNo())).unionWith(argblock[&arg]);
                        }

                        if (f->getReturnType()->isIntegerTy()) // return value is integer.
                            cur_rng[call] = m_func2ret_range[f];
                    }

                    continue;
                } else if (const auto store = dyn_cast<StoreInst>(&inst)) {
                    // is global var
                    const auto val = store->getValueOperand();
                    const auto ptr = store->getPointerOperand();

                    auto valrng = get_rng(val);
                    if (const auto gv = dyn_cast<GlobalVariable>(ptr)) {
                        // should be lazy mode. check local vars first and then check global vars.
                        m_global2range[gv] = m_global2range[gv].unionWith(valrng);
                    }
                    // is local var
                    cur_rng[ptr] = valrng; // better precision.
                    continue;
                } else if (const auto ret = dyn_cast<ReturnInst>(&inst)) {
                    // low precision: just apply!
                    if (F.getReturnType()->isIntegerTy())
                        m_func2ret_range[&F] = get_rng(ret->getReturnValue()).unionWith(m_func2ret_range[&F]);

                    continue;
                }

                // return type should be int
                if (!inst.getType()->isIntegerTy()) {
                    continue;
                }

                // empty range
                crange new_range = crange::getEmpty(inst.getType()->getIntegerBitWidth());

                if (const BinaryOperator* op = dyn_cast<BinaryOperator>(&inst)) {
                    auto lhs = op->getOperand(0);
                    auto rhs = op->getOperand(1);

                    crange lhs_range = get_rng(lhs), rhs_range = get_rng(rhs);
                    new_range = compute_binary_rng(op, lhs_range, rhs_range);
                    // NOTE: LLVM is not a fan of unary operators.
                    //       -x is represented by 0 - x...
                } else if (const SelectInst* op = dyn_cast<SelectInst>(&inst)) {
                    const auto tval = op->getTrueValue();
                    const auto fval = op->getFalseValue();
                    auto [lhs, rhs] = auto_promote(get_rng(tval), get_rng(fval));
                    new_range = lhs.unionWith(rhs);
                } else if (const CastInst* op = dyn_cast<CastInst>(&inst)) {
                    new_range = [op, &get_rng]() -> crange {
                        auto inprng = get_rng(op->getOperand(0));
                        const uint32_t bits = op->getType()->getIntegerBitWidth();
                        switch (op->getOpcode()) {
                        case CastInst::Trunc:
                            return inprng.truncate(bits);
                        case CastInst::ZExt:
                            return inprng.zeroExtend(bits);
                        case CastInst::SExt:
                            return inprng.signExtend(bits); // FIXME: Crash on M1 Mac?
                                                            // But it is not a problem on Linux.
                        default:
                            MKINT_LOG() << "Unhandled Cast Instruction " << op->getOpcodeName()
                                        << ". Using original range.";
                        }

                        return inprng;
                    }();
                } else if (const PHINode* op = dyn_cast<PHINode>(&inst)) {
                    for (size_t i = 0; i < op->getNumIncomingValues(); ++i) {
                        auto pred = op->getIncomingBlock(i);
                        if (m_backedges[bb].contains(pred)) {
                            continue; // skip backedge
                        }
                        new_range = new_range.unionWith(get_range_by_bb(op->getIncomingValue(i), pred));
                    }
                } else if (const auto op = dyn_cast<LoadInst>(&inst)) {
                    new_range = get_rng(op->getPointerOperand());
                } else if (const auto op = dyn_cast<CmpInst>(&inst)) {
                    // can be more precise by comparing the range...
                    // but nah...
                } else {
                    MKINT_CHECK_RELAX(false) << " [Range Analysis] Unhandled instruction: " << inst;
                }

                cur_rng[&inst] = new_range.unionWith(cur_rng[&inst]);
            }
        }
    }

    bool is_sink_reachable(Instruction* inst)
    {
        // we want to only mark sink-reachable taints; and
        // find out if the return value is tainted.
        if (nullptr == inst) {
            return false;
        } else if (inst->getMetadata(MKINT_IR_SINK)) {
            return true;
        }

        bool you_see_sink /* ? */ = false;

        // if store
        if (auto store = dyn_cast<StoreInst>(inst)) {
            auto ptr = store->getPointerOperand();
            if (auto gv = dyn_cast<GlobalVariable>(ptr)) {
                for (const auto& user : gv->users()) {
                    if (auto user_inst = dyn_cast<Instruction>(user)) {
                        if (user != store) // no self-loop.
                            you_see_sink |= is_sink_reachable(user_inst);
                    }
                }

                if (you_see_sink) {
                    mark_taint(*inst);
                    gv->setMetadata(MKINT_IR_TAINT, inst->getMetadata(MKINT_IR_TAINT));
                    return true;
                }
            }
        } else {
            if (auto call = dyn_cast<CallInst>(inst)) {
                if (auto f = call->getCalledFunction()) {
                    // How to do taint analysis for call func?
                    // if func's impl is unknow we simply assume it is related.
                    // if func's impl is known, we analyze which arg determines the return value.
                    // if unrelated -> cut off the connection.
                    // FIXME: But we simply assume it is related and people won't wrote stupid code that results are not
                    // related to inputs.
                    if (!f->isDeclaration() && taint_bcast_sink(f->args())) {
                        you_see_sink = true;
                        m_taint_funcs.insert(f);
                    }
                }
            }

            for (auto user : inst->users()) {
                if (auto user_inst = dyn_cast<Instruction>(user)) {
                    you_see_sink |= is_sink_reachable(user_inst);
                }
            }

            if (you_see_sink) {
                mark_taint(*inst);
                if (auto call = dyn_cast<CallInst>(inst)) {
                    if (auto f = call->getCalledFunction()) {
                        if (!f->getReturnType()->isVoidTy()) {
                            m_taint_funcs.insert(f);
                        }
                    }
                }
                return true;
            }
        }

        return false;
    }

    bool taint_bcast_sink(const std::vector<Instruction*>& taint_source)
    {
        // ? Note we currently assume that sub-func-calls do not have sinks...
        // ? otherwise we need a use-def tree to do the job (but too complicated).
        // Propogation: This pass should only consider single-function-level tainting.
        //              In `out = call(..., taint, ...)`, `out` is tainted. But let's
        //              refine that in cross-function-level tainting.

        // Algo: should do depth-first search until we find a sink. If we find a sink,
        //       we backtrack and mark taints.

        bool ret = false;

        for (auto ts : taint_source) {
            if (is_sink_reachable(ts)) {
                mark_taint(*ts, "source");
                ret = true;
            }
        }

        return ret;
    }

    template <typename Iter> bool taint_bcast_sink(Iter taint_source)
    {
        bool ret = false;

        for (auto& ts : taint_source) {
            for (auto user : ts.users()) {
                if (auto user_inst = dyn_cast<Instruction>(user)) {
                    if (is_sink_reachable(user_inst)) {
                        mark_taint(*user_inst);
                        ret = true;
                    }
                }
            }
        }

        return ret;
    }

    PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM)
    {
        MKINT_LOG() << "Running MKint pass on module " << M.getName();

        // Mark taint sources.
        for (auto& F : M) {
            auto taint_sources = get_taint_source(F);
            mark_func_sinks(F);
            if (!taint_sources.empty())
                m_func2tsrc[&F] = std::move(taint_sources);
        }

        for (auto [fp, tsrc] : m_func2tsrc) {
            if (taint_bcast_sink(tsrc)) {
                m_taint_funcs.insert(fp);
            }
        }

        size_t n_tfunc_before = 0;
        do {
            n_tfunc_before = m_taint_funcs.size();
            for (auto f : m_taint_funcs) {
                if (!is_taint_src(f->getName())) {
                    taint_bcast_sink(f->args());
                }
            }
        } while (n_tfunc_before != m_taint_funcs.size());

        constexpr size_t max_try = 128;
        size_t try_count = 0;

        for (auto& F : M) {
            if (!F.isDeclaration()) {
                backedge_analysis(F);
            }
        }

        this->init_ranges(M);
        while (true) { // iterative range analysis.
            const auto old_fn_rng = m_func2range_info;
            const auto old_glb_rng = m_global2range;
            const auto old_fn_ret_rng = m_func2ret_range;

            for (auto& F : m_range_analysis_funcs) {
                range_analysis(*F);
            }

            if (m_func2range_info == old_fn_rng && old_glb_rng == m_global2range && old_fn_ret_rng == m_func2ret_range)
                break;
            if (++try_count > max_try) {
                MKINT_LOG() << "[Iterative Range Analysis] "
                            << "Max try " << max_try << " reached, aborting.";
                break;
            }
        }
        this->pring_all_ranges();

        return PreservedAnalyses::all();
    }

    void init_ranges(Module& M)
    {
        for (auto& fp : m_taint_funcs) {
            auto& F = *fp;
            // Functions for range analysis:
            // 1. taint source -> taint sink
            if (F.isDeclaration()) {
                m_func2ret_range[&F] = crange(F.getReturnType()->getIntegerBitWidth(), true); // full.
                MKINT_LOG() << "Skip range analysis for func w/o impl: " << F.getName();
            } else {
                if (F.getReturnType()->isIntegerTy())
                    m_func2ret_range[&F] = crange(F.getReturnType()->getIntegerBitWidth(), false); // empty.

                // init the arg range
                auto& init_blk = m_func2range_info[&F][&(F.getEntryBlock())];
                for (const auto& arg : F.args()) {
                    if (arg.getType()->isIntegerTy()) {
                        // be conservative first.
                        // TODO: fine-grained arg range (some taint, some not)
                        if (is_taint_src(F.getName())) { // for taint source, we assume full set.
                            init_blk[&arg] = crange(arg.getType()->getIntegerBitWidth(), true);
                        } else {
                            init_blk[&arg] = crange(arg.getType()->getIntegerBitWidth(), false);
                        }
                    }
                }
                m_range_analysis_funcs.insert(&F);
            }
        }

        // global variables
        for (const auto& GV : M.globals()) {
            MKINT_LOG() << "Found global var " << GV.getName() << " of type " << *GV.getType();
            // TODO: handle struct (ptr); array (ptr)
            if (GV.getType()->isIntOrPtrTy()) {
                if (GV.hasInitializer()) {
                    auto init_val = dyn_cast<ConstantInt>(GV.getInitializer())->getValue();
                    MKINT_LOG() << GV.getName() << " init by " << init_val;
                    m_global2range[&GV] = crange(init_val);
                } else {
                    m_global2range[&GV] = crange(GV.getType()->getIntegerBitWidth()); // can be all range.
                }
            }
        }
    }

    void pring_all_ranges() const
    {
        MKINT_LOG() << "========== Function Return Ranges ==========";
        for (const auto& [F, rng] : m_func2ret_range) {
            MKINT_LOG() << rang::bg::black << rang::fg::green << F->getName() << rang::style::reset << " -> " << rng;
        }

        MKINT_LOG() << "========== Global Variable Ranges ==========";
        for (const auto& [GV, rng] : m_global2range) {
            MKINT_LOG() << rang::bg::black << rang::fg::blue << GV->getName() << rang::style::reset << " -> " << rng;
        }

        MKINT_LOG() << "============ Function Inst Ranges ===========";
        for (const auto& [F, blk2rng] : m_func2range_info) {
            MKINT_LOG() << " ----------- Function Name : " << rang::bg::black << rang::fg::green << F->getName()
                        << rang::style::reset;
            for (const auto& [blk, inst2rng] : blk2rng) {
                MKINT_LOG() << " ----------- Basic Block ----------- ";
                for (const auto& [val, rng] : inst2rng) {
                    if (dyn_cast<ConstantInt>(val))
                        continue; // meaningless to pring const range.

                    if (rng.isFullSet())
                        MKINT_LOG() << *val << "\t -> " << rng;
                    else
                        MKINT_LOG() << *val << "\t -> " << rang::bg::black << rang::fg::yellow << rng
                                    << rang::style::reset;
                }
            }
        }
    }

private:
    MapVector<Function*, std::vector<Instruction*>> m_func2tsrc;
    SetVector<Function*> m_taint_funcs;
    DenseMap<const BasicBlock*, SetVector<const BasicBlock*>> m_backedges;

    // for range analysis
    std::map<const Function*, bbrange_t> m_func2range_info;
    std::map<const Function*, crange> m_func2ret_range;
    SetVector<const Function*> m_range_analysis_funcs;
    std::map<const GlobalValue*, crange> m_global2range;
};
} // namespace

// registering pass (new pass manager).
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo()
{
    return { LLVM_PLUGIN_API_VERSION, "MKintPass", "v0.1", [](PassBuilder& PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef Name, ModulePassManager& MPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (Name == "mkint-pass") {
                            // do mem2reg.
                            MPM.addPass(createModuleToFunctionPassAdaptor(PromotePass()));
                            MPM.addPass(MKintPass());
                            return true;
                        }
                        return false;
                    });
            } };
}

// the version number must match!
// get llvm ir: clang -Os -S -emit-llvm a.c
// or         : clang -O0 -Xclang -disable-O0-optnone -emit-llvm -S a.cpp
// test: opt -load-pass-plugin mkint/MiniKintPass.so -passes=mkint-pass -S a.ll
