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

#define DEBUG_TYPE "scalarrepl"

#include <iostream>

#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Pass.h"
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
      AU.setPreservesCFG();
    }

  private:
    // Add fields and helper functions for this pass here.
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

  return true;
}

}

//
// Function runOnFunction:
// Entry point for the overall ScalarReplAggregates function pass.
// This function is provided to you.

// TODO(JIAWEI): 
// TASK: Implement `SROA`:
//           S1: only consider alloca instructions;
//           S2: alloca can be eliminated if:
//                   U1: `getelementptr` that "getelementpre ptr, 0, constant[, ... constant]"
//                                       that result is only used in instructions of type U1 or U2 or as the pointer argument of load/store;
bool SROA::runOnFunction(Function &F) {

  bool Changed = false;
  return Changed;

}

