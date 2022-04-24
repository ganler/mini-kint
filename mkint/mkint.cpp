#include "log.hpp"
#include "rang.hpp"

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
#include <llvm/IR/Operator.h>
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
#include <cstddef>
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
constexpr const char* MKINT_TAINT_SRC_SUFFX = ".mkint.arg";

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
    std::pair { "__mkint_sink0", 0 }, std::pair { "__mkint_sink1", 1 }, std::pair { "xmalloc", 0 },
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

enum class interr { OVERFLOW, DIV_BY_ZERO, BAD_SHIFT, ARRAY_OOB, DEAD_TRUE_BR, DEAD_FALSE_BR };

template <interr err, typename StrRet = const char*> constexpr StrRet mkstr()
{
    if constexpr (err == interr::OVERFLOW) {
        return "integer overflow";
    } else if (err == interr::DIV_BY_ZERO) {
        return "divide by zero";
    } else if (err == interr::BAD_SHIFT) {
        return "bad shift";
    } else if (err == interr::ARRAY_OOB) {
        return "array index out of bound";
    } else if (err == interr::DEAD_TRUE_BR) {
        return "impossible true branch";
    } else if (err == interr::DEAD_FALSE_BR) {
        return "impossible false branch";
    } else {
        static_assert(err == interr::OVERFLOW || err == interr::DIV_BY_ZERO || err == interr::BAD_SHIFT
                || err == interr::ARRAY_OOB || err == interr::DEAD_TRUE_BR || err == interr::DEAD_FALSE_BR,
            "unknown error type");
        return ""; // statically impossible
    }
}

std::string_view mkstr(interr err)
{
    switch (err) {
    case interr::OVERFLOW:
        return mkstr<interr::OVERFLOW>();
    case interr::DIV_BY_ZERO:
        return mkstr<interr::DIV_BY_ZERO>();
    case interr::BAD_SHIFT:
        return mkstr<interr::BAD_SHIFT>();
    case interr::ARRAY_OOB:
        return mkstr<interr::ARRAY_OOB>();
    case interr::DEAD_TRUE_BR:
        return mkstr<interr::DEAD_TRUE_BR>();
    case interr::DEAD_FALSE_BR:
        return mkstr<interr::DEAD_FALSE_BR>();
    default:
        assert(false && "unknown error type");
        return ""; // statically impossible
    }
}

template <interr err_t, typename I> static std::enable_if_t<std::is_pointer_v<I>> mark_err(I inst)
{
    auto& ctx = inst->getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, mkstr<err_t>()));
    inst->setMetadata(MKINT_IR_ERR, md);
}

template <interr err_t, typename I> static std::enable_if_t<!std::is_pointer_v<I>> mark_err(I& inst)
{
    mark_err<err_t>(&inst);
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

static std::vector<CallInst*> get_taint_source(Function& F)
{
    std::vector<CallInst*> ret;
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
            auto call_name = name.str() + MKINT_TAINT_SRC_SUFFX + std::to_string(arg.getArgNo());
            MKINT_LOG() << "Taint Analysis -> taint src arg -> call inst: " << call_name;
            auto call_inst = CallInst::Create(F.getParent()->getOrInsertFunction(call_name, itype), arg.getName(),
                &*F.getEntryBlock().getFirstInsertionPt());
            ret.push_back(call_inst);
            arg.replaceAllUsesWith(call_inst);
        }
    }
    return ret;
}

static bool is_taint_src_arg_call(StringRef s) { return s.contains(MKINT_TAINT_SRC_SUFFX); }

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

    crange get_range_by_bb(const Value* var, const BasicBlock* bb)
    {
        auto& bb_range = m_func2range_info[bb->getParent()];
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
    }

    void range_analysis(Function& F)
    {
        MKINT_LOG() << "Range Analysis -> " << F.getName();

        auto& bb_range = m_func2range_info[&F];

        for (auto& bbref : F) {
            auto bb = &bbref;

            auto& cur_rng = bb_range[bb];
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

                            bool is_true_br = br->getSuccessor(0) == bb;
                            if (is_true_br) { // T branch
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

                            if (cur_rng[lhs].isEmptySet() || cur_rng[rhs].isEmptySet()) {
                                // TODO: higher precision.
                                m_impossible_branches[cmp] = is_true_br;
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
                const auto get_rng = [&bb, this](auto var) { return get_range_by_bb(var, bb); };
                // Store / Call / Return
                if (const auto call = dyn_cast<CallInst>(&inst)) {
                    if (const auto f = call->getCalledFunction()) {
                        if (m_callback_tsrc_fn.contains(f->getName())) {
                            const auto& argcalls = m_func2tsrc[f];

                            for (const auto& arg : f->args()) {
                                auto& argblock = m_func2range_info[f][&(f->getEntryBlock())];
                                const size_t arg_idx = arg.getArgNo();
                                if (arg.getType()->isIntegerTy()) {
                                    argblock[&arg] = get_rng(call->getArgOperand(arg_idx)).unionWith(argblock[&arg]);
                                    m_func2ret_range[argcalls[arg_idx]->getCalledFunction()] = argblock[&arg];
                                }
                            }
                        } else {
                            for (const auto& arg : f->args()) {
                                auto& argblock = m_func2range_info[f][&(f->getEntryBlock())];
                                if (arg.getType()->isIntegerTy())
                                    argblock[&arg]
                                        = get_rng(call->getArgOperand(arg.getArgNo())).unionWith(argblock[&arg]);
                            }
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
                    } else if (const auto gep = dyn_cast<GetElementPtrInst>(ptr)) {
                        auto gep_addr = gep->getPointerOperand();
                        if (auto garr = dyn_cast<GlobalVariable>(gep_addr)) {
                            if (m_garr2ranges.count(garr) && gep->getNumIndices() == 2) { // all one dim array<int>s!
                                auto idx = gep->getOperand(2);
                                const size_t arr_size = m_garr2ranges[garr].size();
                                const crange idx_rng = get_rng(idx);
                                const size_t idx_max = idx_rng.getUnsignedMax().getLimitedValue();
                                if (idx_max >= arr_size)
                                    m_gep_oob.insert(gep);

                                for (size_t i = idx_rng.getUnsignedMin().getLimitedValue();
                                     i < std::min(arr_size, idx_max); ++i) {
                                    m_garr2ranges[garr][i] = m_garr2ranges[garr][i].unionWith(valrng);
                                }
                            }
                        }
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
                } else if (auto op = dyn_cast<LoadInst>(&inst)) {
                    auto addr = op->getPointerOperand();
                    if (dyn_cast<GlobalVariable>(addr))
                        new_range = get_rng(addr);
                    else if (auto gep = dyn_cast<GetElementPtrInst>(addr)) {
                        bool succ = false;
                        // we only analyze shallow arrays. i.e., one dim.
                        auto gep_addr = gep->getPointerOperand();
                        if (auto garr = dyn_cast<GlobalVariable>(gep_addr)) {
                            if (m_garr2ranges.count(garr) && gep->getNumIndices() == 2) { // all one dim array<int>s!
                                auto idx = gep->getOperand(2);
                                const size_t arr_size = m_garr2ranges[garr].size();
                                const crange idx_rng = get_rng(idx);
                                const size_t idx_max = idx_rng.getUnsignedMax().getLimitedValue();
                                if (idx_max >= arr_size) {
                                    m_gep_oob.insert(gep);
                                }

                                for (size_t i = idx_rng.getUnsignedMin().getLimitedValue();
                                     i < std::min(arr_size, idx_max); ++i) {
                                    new_range = new_range.unionWith(m_garr2ranges[garr][i]);
                                }

                                succ = true;
                            }
                        }

                        if (!succ) {
                            MKINT_WARN() << "Unknown address to load (unknow gep src addr): " << inst;
                            new_range = crange(op->getType()->getIntegerBitWidth()); // unknown addr -> full range.
                        }
                    } else {
                        MKINT_WARN() << "Unknown address to load: " << inst;
                        new_range = crange(op->getType()->getIntegerBitWidth()); // unknown addr -> full range.
                    }
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

    static SmallVector<Function*, 2> get_sink_fns(Instruction* inst) noexcept
    {
        SmallVector<Function*, 2> ret;
        for (auto user : inst->users()) {
            if (auto call = dyn_cast<CallInst>(user)) {
                auto dname = demangle(call->getCalledFunction()->getName().data());
                if (std::find_if(
                        MKINT_SINKS.begin(), MKINT_SINKS.end(), [&dname](const auto& s) { return dname == s.first; })
                    != MKINT_SINKS.end()) {
                    ret.push_back(call->getCalledFunction());
                }
            }
        }
        return ret;
    }

    bool is_sink_reachable(Instruction* inst)
    {
        // we want to only mark sink-reachable taints; and
        // find out if the return value is tainted.
        if (nullptr == inst) {
            return false;
        } else if (inst->getMetadata(MKINT_IR_SINK)) {
            for (auto f : get_sink_fns(inst)) {
                m_taint_funcs.insert(f);
            }
            return true;
        }

        bool you_see_sink /* ? */ = false;

        // if store
        if (auto store = dyn_cast<StoreInst>(inst)) {
            auto ptr = store->getPointerOperand();
            if (auto gv = dyn_cast<GlobalVariable>(ptr)) {
                for (auto user : gv->users()) {
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

    bool taint_bcast_sink(const std::vector<CallInst*>& taint_source)
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

    void mark_func_sinks(Function& F)
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
                        if (auto arg = dyn_cast_or_null<Instruction>(call->getArgOperand(idx))) {
                            MKINT_LOG() << "Taint Analysis -> sink: argument [" << idx << "] of "
                                        << demangled_func_name;
                            mark_sink(*arg, name);
                        }
                        break;
                    } else if (StringRef(demangled_func_name).startswith(name)) {
                        MKINT_WARN() << "Are you missing the sink? [demangled_func_name]: " << demangled_func_name
                                     << "; [name]: " << name;
                    }
                }
            }
        }

        // if this function is taint source and has a return value used non-taint-source functions, we mark its return
        // statement as sink. this is because its return value can be used by, say kernel functions.
        if (is_taint_src(F.getName()) && F.getReturnType()->isIntegerTy() && !F.use_empty()) {

            // if there is any users.
            bool valid_use = false;
            for (auto user : F.users()) {
                if (auto user_inst = dyn_cast<Instruction>(user)) {
                    if (!is_taint_src(user_inst->getParent()->getParent()->getName())) {
                        valid_use = true;
                        break;
                    }
                }
            }
            if (!valid_use)
                return;

            for (auto& inst : instructions(F)) {
                if (dyn_cast<ReturnInst>(&inst)) {
                    MKINT_LOG() << "Taint Analysis -> sink: return inst of " << F.getName();
                    mark_sink(inst, "return");
                    m_callback_tsrc_fn.insert(F.getName());
                }
            }
        }
    }

    PreservedAnalyses run(Module& M, ModuleAnalysisManager& MAM)
    {
        MKINT_LOG() << "Running MKint pass on module " << M.getName();

        // Mark taint sources.
        for (auto& F : M) {
            auto taint_sources = get_taint_source(F);
            mark_func_sinks(F);
            if (is_taint_src(F.getName()))
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
            const auto old_glb_arrrng = m_garr2ranges;
            const auto old_fn_ret_rng = m_func2ret_range;

            for (auto F : m_range_analysis_funcs) {
                range_analysis(*F);
            }

            if (m_func2range_info == old_fn_rng && old_glb_rng == m_global2range && old_fn_ret_rng == m_func2ret_range
                && old_glb_arrrng == m_garr2ranges)
                break;
            if (++try_count > max_try) {
                MKINT_LOG() << "[Iterative Range Analysis] "
                            << "Max try " << max_try << " reached, aborting.";
                break;
            }
        }
        this->pring_all_ranges();

        for (auto& F : m_taint_funcs) {
            for (auto& bb : F->getBasicBlockList()) {
                for (auto& inst : bb) {
                    if (auto bop = dyn_cast<BinaryOperator>(&inst)) {
                        auto lhs = get_range_by_bb(bop->getOperand(0), &bb);
                        auto rhs = get_range_by_bb(bop->getOperand(1), &bb);
                        binary_check(bop, lhs, rhs);
                    }
                }
            }
        }

        this->mark_errors();

        return PreservedAnalyses::all();
    }

    void init_ranges(Module& M)
    {
        for (auto& F : M) {
            // Functions for range analysis:
            // 1. taint source -> taint sink.
            // 2. integer functions.
            if (F.getReturnType()->isIntegerTy() || m_taint_funcs.contains(&F)) {
                if (F.isDeclaration()) {
                    if (is_taint_src_arg_call(F.getName())
                        && m_callback_tsrc_fn.contains(
                            F.getName().substr(0, F.getName().size() - StringRef(MKINT_TAINT_SRC_SUFFX).size() - 1))) {
                        m_func2ret_range[&F] = crange(F.getReturnType()->getIntegerBitWidth(), false);
                        MKINT_LOG() << "Skip range analysis for func w/o impl [Empty Set]: " << F.getName();
                    } else {
                        m_func2ret_range[&F] = crange(F.getReturnType()->getIntegerBitWidth(), true); // full.
                        MKINT_LOG() << "Skip range analysis for func w/o impl [Full Set]: " << F.getName();
                    }
                } else {
                    if (F.getReturnType()->isIntegerTy())
                        m_func2ret_range[&F] = crange(F.getReturnType()->getIntegerBitWidth(), false); // empty.

                    // init the arg range
                    auto& init_blk = m_func2range_info[&F][&(F.getEntryBlock())];
                    for (const auto& arg : F.args()) {
                        if (arg.getType()->isIntegerTy()) {
                            // be conservative first.
                            // TODO: fine-grained arg range (some taint, some not)
                            if (is_taint_src(F.getName())
                                && !m_callback_tsrc_fn.contains(F.getName())) { // for taint source, we assume full set.
                                init_blk[&arg] = crange(arg.getType()->getIntegerBitWidth(), true);
                            } else {
                                init_blk[&arg] = crange(arg.getType()->getIntegerBitWidth(), false);
                            }
                        }
                    }
                    m_range_analysis_funcs.insert(&F);
                }
            }
        }

        // global variables
        for (const auto& GV : M.globals()) {
            MKINT_LOG() << "Found global var " << GV.getName() << " of type " << *GV.getType();
            // TODO: handle struct (ptr); array (ptr)
            if (GV.getValueType()->isIntegerTy()) {
                if (GV.hasInitializer()) {
                    auto init_val = dyn_cast<ConstantInt>(GV.getInitializer())->getValue();
                    MKINT_LOG() << GV.getName() << " init by " << init_val;
                    m_global2range[&GV] = crange(init_val);
                } else {
                    m_global2range[&GV] = crange(GV.getType()->getIntegerBitWidth()); // can be all range.
                }
            } else if (GV.getValueType()->isArrayTy()) { // int array.
                const auto garr = dyn_cast<ArrayType>(GV.getValueType());
                if (GV.hasInitializer()) {
                    if (auto darr = dyn_cast<ConstantDataArray>(GV.getInitializer())) {
                        for (size_t i = 0; i < darr->getNumElements(); i++) {
                            auto init_val = dyn_cast<ConstantInt>(darr->getElementAsConstant(i))->getValue();
                            MKINT_LOG() << GV.getName() << "[" << i << "] init by " << init_val;
                            m_garr2ranges[&GV].push_back(crange(init_val));
                        }
                    } else {
                        MKINT_CHECK_ABORT(false) << "Unsupported initializer for global array: " << GV.getName();
                    }
                } else {
                    for (size_t i = 0; i < garr->getNumElements(); i++) {
                        m_garr2ranges[&GV].push_back( // can be anything
                            crange(garr->getElementType()->getIntegerBitWidth(), true));
                    }
                }
            } else {
                MKINT_WARN() << "Unhandled global var type: " << *GV.getType() << " -> " << GV.getName();
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

        for (const auto& [GV, rng_vec] : m_garr2ranges) {
            for (size_t i = 0; i < rng_vec.size(); i++) {
                MKINT_LOG() << rang::bg::black << rang::fg::blue << GV->getName() << "[" << i << "]"
                            << rang::style::reset << " -> " << rng_vec[i];
            }
        }

        MKINT_LOG() << "============ Function Inst Ranges ============";
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

        MKINT_LOG() << "============ Impossible Branches ============";
        for (auto [cmp, is_tbr] : m_impossible_branches) {
            MKINT_WARN() << rang::bg::black << rang::fg::red << cmp->getFunction()->getName() << "::" << *cmp
                         << rang::style::reset << "'s " << rang::fg::red << rang::style::italic
                         << (is_tbr ? "true" : "false") << rang::style::reset << " branch";
        }

        MKINT_LOG() << "============ Array Index Out of Bound ============";
        for (auto gep : m_gep_oob) {
            MKINT_WARN() << rang::bg::black << rang::fg::red << gep->getFunction()->getName() << "::" << *gep
                         << rang::style::reset;
        }
    }

    // for general: check overflow;
    // for shl:     check shift amount;
    // for div:     check divisor != 0;
    void binary_check(BinaryOperator* op, const crange& lhs, const crange& rhs)
    {
        if (lhs.isEmptySet() || rhs.isEmptySet()) {
            MKINT_LOG() << "Skip due empty range in operands: " << *op;
            return;
        }

        z3::context ctx;
        z3::solver s(ctx);

        // create a int symbol
        z3::expr lhs_iv = ctx.int_const("lhs");
        z3::expr rhs_iv = ctx.int_const("rhs");

        const auto [is_nsw, is_nuw] = [op] {
            if (const auto ofop = dyn_cast<OverflowingBinaryOperator>(op)) {
                return std::make_pair(ofop->hasNoSignedWrap(), ofop->hasNoUnsignedWrap());
            }
            return std::make_pair(false, false);
        }();

        const auto add_signed_cons = [&] {
            s.add(lhs_iv <= ctx.int_val(lhs.getSignedMax().getSExtValue()), "lhs_signed_max");
            s.add(lhs_iv >= ctx.int_val(lhs.getSignedMin().getSExtValue()), "lhs_signed_min");
            s.add(rhs_iv <= ctx.int_val(rhs.getSignedMax().getSExtValue()), "rhs_signed_max");
            s.add(rhs_iv >= ctx.int_val(rhs.getSignedMin().getSExtValue()), "rhs_signed_min");
        };

        const auto add_unsigned_cons = [&] {
            s.add(lhs_iv <= ctx.int_val(lhs.getUnsignedMax().getZExtValue()), "lhs_unsigned_max");
            s.add(lhs_iv >= ctx.int_val(lhs.getUnsignedMin().getZExtValue()), "lhs_unsigned_min");
            s.add(rhs_iv <= ctx.int_val(rhs.getUnsignedMax().getZExtValue()), "rhs_unsigned_max");
            s.add(rhs_iv >= ctx.int_val(rhs.getUnsignedMin().getZExtValue()), "rhs_unsigned_min");
        };

        const auto may_signed_overflow = [&](z3::expr result, size_t nbit) {
            int64_t smin = APInt::getSignedMinValue(nbit).getSExtValue();
            int64_t smax = APInt::getSignedMaxValue(nbit).getSExtValue();
            return result < ctx.int_val(smin) || result > ctx.int_val(smax);
        };

        const auto may_unsigned_overflow = [&](z3::expr result, size_t nbit) {
            uint64_t umin = APInt::getMinValue(nbit).getZExtValue();
            uint64_t umax = APInt::getMaxValue(nbit).getZExtValue();
            return result < ctx.int_val(umin) || result > ctx.int_val(umax);
        };

        const auto check = [&](interr et) {
            if (s.check() == z3::sat) { // counter example
                z3::model m = s.get_model();
                MKINT_WARN() << mkstr(et) << " at " << *op;
                MKINT_WARN() << op->getOpcodeName() << '(' << m.eval(lhs_iv, true) << ", " << m.eval(rhs_iv, true)
                             << ')';
                switch (et) {
                case interr::OVERFLOW:
                    m_overflow_insts.insert(op);
                    break;
                case interr::BAD_SHIFT:
                    m_bad_shift_insts.insert(op);
                    break;
                case interr::DIV_BY_ZERO:
                    m_div_zero_insts.insert(op);
                    break;
                default:
                    break;
                }
            }
        };

        switch (op->getOpcode()) {
        case Instruction::Add:
            if (!is_nsw) { // unsigned
                if (!is_nsw && !is_nuw)
                    MKINT_WARN() << "Strange ... This inst is neither nsw/nuw: " << *op;
                add_unsigned_cons();
                s.add(may_unsigned_overflow(lhs_iv + rhs_iv, op->getType()->getIntegerBitWidth()));
            } else {
                add_signed_cons();
                s.add(may_signed_overflow(lhs_iv + rhs_iv, op->getType()->getIntegerBitWidth()));
            }

            check(interr::OVERFLOW);
            break;
        case Instruction::Sub:
            if (!is_nsw) {
                if (!is_nsw && !is_nuw)
                    MKINT_WARN() << "Strange ... This inst is neither nsw/nuw: " << *op;
                add_unsigned_cons();
                s.add(may_unsigned_overflow(lhs_iv - rhs_iv, op->getType()->getIntegerBitWidth()));
            } else {
                add_signed_cons();
                s.add(may_signed_overflow(lhs_iv - rhs_iv, op->getType()->getIntegerBitWidth()));
            }

            check(interr::OVERFLOW);
            break;
        case Instruction::Mul:
            if (!is_nsw) {
                if (!is_nsw && !is_nuw)
                    MKINT_WARN() << "Strange ... This inst is neither nsw/nuw: " << *op;
                add_unsigned_cons();
                s.add(may_unsigned_overflow(lhs_iv * rhs_iv, op->getType()->getIntegerBitWidth()));
            } else {
                add_signed_cons();
                s.add(may_signed_overflow(lhs_iv * rhs_iv, op->getType()->getIntegerBitWidth()));
            }

            check(interr::OVERFLOW);
            break;
        case Instruction::URem:
        case Instruction::UDiv:
            add_unsigned_cons();
            s.add(rhs_iv == 0);
            check(interr::DIV_BY_ZERO);
            break;
        case Instruction::SRem:
        case Instruction::SDiv: // can be overflow or divisor == 0
            add_signed_cons();
            s.push();
            s.add(rhs_iv == 0); // may 0?
            check(interr::DIV_BY_ZERO);
            s.pop();
            s.add(may_signed_overflow(lhs_iv / rhs_iv, op->getType()->getIntegerBitWidth()));
            check(interr::OVERFLOW);
            break;
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
            s.add(rhs_iv <= ctx.int_val(rhs.getUnsignedMax().getZExtValue()));
            s.add(rhs_iv >= ctx.int_val(rhs.getUnsignedMin().getZExtValue()));
            s.add(rhs_iv >= ctx.int_val(rhs.getBitWidth())); // sat means bug
            check(interr::BAD_SHIFT);
            break;
        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
        default:
            break;
        }
    }

    void mark_errors()
    {
        for (auto [cmp, is_tbr] : m_impossible_branches) {
            if (is_tbr)
                mark_err<interr::DEAD_TRUE_BR>(cmp);
            else
                mark_err<interr::DEAD_FALSE_BR>(cmp);
        }

        for (auto gep : m_gep_oob) {
            mark_err<interr::ARRAY_OOB>(gep);
        }

        for (auto inst : m_overflow_insts) {
            mark_err<interr::OVERFLOW>(inst);
        }

        for (auto inst : m_bad_shift_insts) {
            mark_err<interr::BAD_SHIFT>(inst);
        }

        for (auto inst : m_div_zero_insts) {
            mark_err<interr::DIV_BY_ZERO>(inst);
        }
    }

private:
    MapVector<Function*, std::vector<CallInst*>> m_func2tsrc;
    SetVector<Function*> m_taint_funcs;
    DenseMap<const BasicBlock*, SetVector<const BasicBlock*>> m_backedges;
    SetVector<StringRef> m_callback_tsrc_fn;

    // for range analysis
    std::map<const Function*, bbrange_t> m_func2range_info;
    std::map<const Function*, crange> m_func2ret_range;
    SetVector<Function*> m_range_analysis_funcs;
    std::map<const GlobalVariable*, crange> m_global2range;
    std::map<const GlobalVariable*, SmallVector<crange, 4>> m_garr2ranges;

    // for error checking
    std::map<ICmpInst*, bool> m_impossible_branches;
    std::set<GetElementPtrInst*> m_gep_oob;
    std::set<Instruction*> m_overflow_insts;
    std::set<Instruction*> m_bad_shift_insts;
    std::set<Instruction*> m_div_zero_insts;
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
