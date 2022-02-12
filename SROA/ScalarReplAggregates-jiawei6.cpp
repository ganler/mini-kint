//===- ScalarReplAggregates.cpp - Scalar Replacement of Aggregates --------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file was developed by the LLVM research group and is distributed under
// the University of Illinois Open Source License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This transformation implements the well known scalar replacement of
// aggregates transformation.  This xform breaks up alloca instructions of
// structure type into individual alloca instructions for
// each member (if possible).  Then, if possible, it transforms the individual
// alloca instructions into nice clean scalar SSA form.
//
// This combines an SRoA algorithm with Mem2Reg because they
// often interact, especially for C++ programs.  As such, this code
// iterates between SRoA and Mem2Reg until we run out of things to promote.
//
//===----------------------------------------------------------------------===//


#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Value.h"
#include <cstddef>
#define DEBUG_TYPE "scalarrepl"

#include <iostream>
#include <vector>

#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Pass.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Support/Debug.h"
#include "llvm/ADT/Statistic.h"

using namespace llvm;

STATISTIC(NumReplaced,  "Number of aggregate allocas broken up");
STATISTIC(NumPromoted,  "Number of scalar allocas promoted to register");

namespace {
  struct SROA : public FunctionPass {
    static char ID; // Pass identification
    SROA() : FunctionPass(ID) { }

    // Entry point for the overall scalar-replacement pass
    bool runOnFunction(Function &F);

    // getAnalysisUsage - List passes required by this pass.  We also know it
    // will not alter the CFG, so say so.
    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<DominatorTreeWrapperPass>();
      AU.setPreservesCFG();
    }

  private:
    // Add fields and helper functions for this pass here.
    bool isGetElementPtrSafeByUser(Function& F, const GetElementPtrInst* geptr_inst) const noexcept;
  };
}

char SROA::ID = 0;
static RegisterPass<SROA> X("scalarrepl-jiawei6",
			    "Scalar Replacement of Aggregates (by jiawei6)",
			    false /* does not modify the CFG */,
			    false /* transformation, not just analysis */);


// Public interface to create the ScalarReplAggregates pass.
// This function is provided to you.
FunctionPass *createMyScalarReplAggregatesPass() { return new SROA(); }


//===----------------------------------------------------------------------===//
//                      SKELETON FUNCTION TO BE IMPLEMENTED
//===----------------------------------------------------------------------===//

// Implementation notes:
// -> mem2reg to promote scalar allocas;
// -> sroa to replace struct allocas with scalar allocas;

// HINT: `PromoteMemToReg(AllocaVec, DominatorTree, AliasSetTracker)` ~ mem2reg
//           requires all the AllocaInst instructions in AllocaVec must be promotable (`isAllocaPromotable(c AllocaInst*)`).

namespace jiawei6 {

// TASK: Implement `isAllocaPromotable`:        
bool isAllocaPromotable(const llvm::AllocaInst* inst) {
  // R1: isFPOrFPVectorTy() || isIntOrIntVectorTy() || isPtrOrPtrVectorTy()
  if (!(inst->getAllocatedType()->isFPOrFPVectorTy() ||
        inst->getAllocatedType()->isIntOrIntVectorTy() ||
        inst->getAllocatedType()->isPtrOrPtrVectorTy()))
    return false;

  // R2: only used in a load/store instruction that !isVolatile()
  for (const auto&& user : inst->users()) {
    const auto load_inst = dyn_cast<LoadInst>(user);
    const auto store_inst = dyn_cast<StoreInst>(user);

    if ( ! ((load_inst && load_inst->isVolatile()) || (store_inst && store_inst->isVolatile())) ) {
      return false;
    }
  }

  ++NumPromoted;
  return true;
}

}

//
// Function runOnFunction:
// Entry point for the overall ScalarReplAggregates function pass.
// This function is provided to you.

// Materials referenced: https://gcc.gnu.org/wiki/summit2010?action=AttachFile&do=get&target=jambor.pdf
// Course material: https://charithm.web.illinois.edu/cs526/sp2022/cp1.pdf

// TODO(JIAWEI): 
// TASK: Implement `SROA`:
//           S1: only consider alloca instructions;
//           S2: alloca can be eliminated if:
//                   U1: `getelementptr` that "getelementpre ptr, 0, constant[, ... constant]"
//                                       that result is only used in instructions of type U1 or U2 or as the pointer argument of load/store;
bool SROA::runOnFunction(Function &F) {
  bool cfg_changed = false;

  // Step 1: promote scalar allocas to virtual registers (mem2reg)
  const auto scalar_promotion = [&F, this]{
    bool cfg_changed = false;
    auto&& bb = F.getEntryBlock();

    while (true) {
      std::vector<AllocaInst*> alloca_worklist{};
      
      for (auto&& inst : bb) {
        if (auto alloca_inst = dyn_cast<AllocaInst>(&inst)) {
          if (isAllocaPromotable(alloca_inst)) {
            alloca_worklist.push_back(alloca_inst);
          }
        }
      }

      if (alloca_worklist.empty())
        break;

      cfg_changed = true;
      NumPromoted += alloca_worklist.size();

      // allocas, dominator tree, alias set tracker
      // TODO(JIAWEI): `alias set tracker` not handled for now. But the type is "AssumptionCache"???
      PromoteMemToReg(alloca_worklist, getAnalysis<DominatorTreeWrapperPass>().getDomTree());
    }

    return cfg_changed;
  };

  // Step 2: replace aggregate allocas with scalar allocas (sroa)
  cfg_changed = scalar_promotion();

  while(true) {
    // quit until no more changes.
    if (![&F, this]{
      bool repl_changed = false;
      std::vector<AllocaInst*> alloca_worklist{};
      auto&& bb = F.getEntryBlock();

      for (auto&& inst : bb) {
        if (auto alloca_inst = dyn_cast<AllocaInst>(&inst)) {
          alloca_worklist.push_back(alloca_inst);
        }

        while (!alloca_worklist.empty()) {
          // start from the last element for best performance.
          auto&& alloca = alloca_worklist.back();
          alloca_worklist.pop_back();

          // now we have eliminated scala allocas (isAllocaPromotable).
          // but there still can be: array, struct, heap object, etc...

          // we first only consider struct
          // TODO(BONUS): handle array;
          if (auto struct_alloca = dyn_cast<AllocaInst>(alloca)) {
            if (![this, &F, struct_alloca]{

              for (auto&& user : struct_alloca->users()) {
                // U1: getelementptr;
                if (const auto geptr_inst = dyn_cast<GetElementPtrInst>(user)) {
                    if (!isGetElementPtrSafeByUser(F, geptr_inst))
                      return false;
                // U2: `eq` / `ne` against nullptr;
                } else if (const auto cmp_inst = dyn_cast<ICmpInst>(user)) {
                  if (cmp_inst->getPredicate() == ICmpInst::ICMP_EQ || cmp_inst->getPredicate() == ICmpInst::ICMP_NE) {
                    if (!dyn_cast<ConstantPointerNull>(cmp_inst->getOperand(0)) && !dyn_cast<ConstantPointerNull>(cmp_inst->getOperand(1)))
                      return false;
                  }
                }
              }

              return true;
            }()) { // * Is it safe to promote it? Skip it if unsafe.
              continue;
            }

            // struct alloca safe to be replaced now now;
            // TODO(JIAWEI): Impl alloca replacement in SROA.
            // S1: get alloca inst for sub fields;
            std::vector<AllocaInst*> sub_alloca_fields{};
            if(auto struct_alloca_types = struct_alloca->getAllocatedType()) {
              sub_alloca_fields.reserve(struct_alloca_types->getNumContainedTypes()); // optimization.
              for (size_t i = 0; i < struct_alloca_types->getNumContainedTypes(); ++i) {
                //                                 type, addr_space, name, insert_before
                auto field_alloca = new AllocaInst(
                  struct_alloca_types->getContainedType(i), 0, struct_alloca->getName() + "[" + std::to_string(i) + "]", struct_alloca);
                sub_alloca_fields.push_back(field_alloca);
              }
            }

            // S2: update the users of the struct alloca;
            for (const auto& user : struct_alloca->users()) {
              if (auto geptr = dyn_cast<GetElementPtrInst>(user)) {
                // struct alloca will be used by getelementptr;
                // e.g., struct { int a; int b; } s;
                //       s.a ~ getelementptr s, 0, 0;
                //       s.b ~ getelementptr s, 0, 1;
                // index is operand[2].
                // We don't consider array for now.
                size_t element_idx = dyn_cast<ConstantInt>(geptr->getOperand(2))->getZExtValue();
                auto target_alloca = sub_alloca_fields.at(element_idx);

                // cases like s.a or s.b is easy; we can just leave it alone;
                if (geptr->getNumOperands() <= 3) {
                  geptr->replaceAllUsesWith(target_alloca);
                } else { // more complicated form; let's expand one layer once;
                  // e.g., struct S1 {int a; int b;};  struct S2 {int x; struct S1 s1;};
                  //       s2.s1.b ~ getelementptr s2, 0, 1, 1;
                  // update -> getelementptr s2[1], 0, 1;
                  //           getelementptr ${new_alloca}, 0, {op_begin() + 3, ...}
                  std::vector<Value*> new_geptr_operands {ConstantInt::get(Type::getInt32Ty(F.getContext()), 0)};
                  new_geptr_operands.insert(new_geptr_operands.end(), geptr->op_begin() + 3, geptr->op_end());
                  // ? pointee typs is result type? (Not sure)
                  auto new_geptr = GetElementPtrInst::Create(
                    geptr->getResultElementType(), target_alloca, new_geptr_operands, geptr->getName() + "[" + std::to_string(element_idx) + "]", geptr);
                  geptr->replaceAllUsesWith(new_geptr); 
                }
                // erase itself;
                geptr->eraseFromParent();
              }
            }

            // S3: erase the struct alloca
            struct_alloca->eraseFromParent();
            ++NumReplaced;
            repl_changed = true;
          }
        }
      }

      return repl_changed;
    }())
      break;
    
    cfg_changed = true;
    
    if (!scalar_promotion()) {
      break;
    }
  }

  return cfg_changed;
}

// It is safe to replace original struct ptrs with a few scalars iff the struct ptr has not needed after replacement.
// That said, if all uses are simply 1) value read/write; and/or 2) nullptr comparison; (or even >, < but more complicated);
bool SROA::isGetElementPtrSafeByUser(Function& F, const GetElementPtrInst* geptr_inst) const noexcept {
  // U1.1: getelementptr ptr,    0, constant[, ... constant]
  //                     ptr, this, const access;
  bool is_safe_u11 = geptr_inst->getNumOperands() >= 3                                 /* >2 operands */ && \
    geptr_inst->getOperand(1) == ConstantInt::get(Type::getInt32Ty(F.getContext()), 0) /* "0"         */ && \
    [geptr_inst]{                                                                      /* "constant"  */
      for (size_t i = 2; i < geptr_inst->getNumOperands(); ++i)
        if (!isa<ConstantInt>(geptr_inst->getOperand(i)))
          return false;
      return true;
    }();
  
  if (!is_safe_u11)
    return false;

  // U1.2: result value only used by U1 or U2; 
  for (auto&& geptr_user : geptr_inst->users()) {
    // U1.2.1: argument in load/store;
    if (const auto load_inst = dyn_cast<LoadInst>(geptr_user)) {
      if (load_inst->getPointerOperand() != geptr_inst)
        return false;
    } else if (const auto store_inst = dyn_cast<StoreInst>(geptr_user)) {
      if (store_inst->getPointerOperand() != geptr_inst)
        return false;
    } else if (const auto user_geptr_inst = dyn_cast<GetElementPtrInst>(geptr_user)) {
      // U1.2.2: argument in getelementptr;
      if (!isGetElementPtrSafeByUser(F, user_geptr_inst))
        return false;
    }
  }

  return true;
}
