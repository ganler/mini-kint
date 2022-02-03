#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/Casting.h>

namespace {

struct SwapAdd : llvm::PassInfoMixin<SwapAdd> {
    bool runOnBasicBlock(llvm::BasicBlock& BB) {
        bool is_changed = false;
        for (auto inst = BB.begin(); BB.end() != inst; ++inst) {
            auto binop = llvm::dyn_cast<llvm::BinaryOperator>(inst);

            if (!binop || \
                    binop->getOpcode() != llvm::Instruction::Add || \
                    !binop->getType()->isIntegerTy() || \
                    binop->getType()->getIntegerBitWidth() != 8)
                continue;

            llvm::ReplaceInstWithInst(BB.getInstList(), inst, llvm::BinaryOperator::CreateAdd(binop->getOperand(1), binop->getOperand(0)));

            LLVM_DEBUG( dbgs() << *binop << " -> " << *inst << '\n' );
            is_changed = true;
        }
        return is_changed;
    }

    llvm::PreservedAnalyses run(llvm::Function& F, llvm::FunctionAnalysisManager&) {
        llvm::errs() << "Visiting " << F.getName() << '\n';
        llvm::errs() << "\t# of arguments: " << F.arg_size() << '\n';

        for (auto&& BB : F) {
            if (this->runOnBasicBlock(BB)) // transformation pass changed the IR where prior analysis results expire;
                return llvm::PreservedAnalyses::none();
        }
        return llvm::PreservedAnalyses::all();
    }
};

}

// Registeration

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "swap-add",
        LLVM_VERSION_STRING,
        [](llvm::PassBuilder& PB) {
            PB.registerPipelineParsingCallback(
                [](llvm::StringRef Name, llvm::FunctionPassManager& FPM, llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                    if ("swap-add" == Name) {
                        FPM.addPass(SwapAdd());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}

