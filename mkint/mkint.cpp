#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>

using namespace llvm;

namespace {

struct MKintPass : public PassInfoMixin<MKintPass> {
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& FAM)
    {
        std::cout << "RUNNING: " << F.getName().str() << std::endl;
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
// test: opt -load-pass-plugin mkint/MiniKintPass.so -passes=mkint-pass -S a.ll