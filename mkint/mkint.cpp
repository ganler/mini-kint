#include "log.hpp"
#include "smt.hpp"

#include <llvm/IR/PassManager.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>
#include <type_traits>

using namespace llvm;

// TODO: consider constraints from annotation;
// TODO: consider taint annotation;
// TODO: consider sink annotation;

constexpr const char* MKINT_IR_TAINT = "mkint.taint";
constexpr const char* MKINT_IR_SINK = "mkint.sink";
constexpr const char* MKINT_IR_ERR = "mkint.err";

namespace {

enum class interr {
    OUT_OF_BOUND,
    DIV_BY_ZERO,
    BAD_SHIFT,
    NEG_IDX,
    VIOLATE_ANN,
};


template <interr err, typename StrRet = const char*>
constexpr StrRet mkstr() {
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
            err == interr::OUT_OF_BOUND ||
            err == interr::DIV_BY_ZERO ||
            err == interr::BAD_SHIFT ||
            err == interr::NEG_IDX ||
            err == interr::VIOLATE_ANN, 
            "unknown error type");
        return ""; // statically impossible
    }
}

template <interr err_t>
static void mark_err(Instruction& inst) {
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, mkstr<err_t>()));
    inst.setMetadata(MKINT_IR_ERR, md);
}

static void mark_taint(Instruction& inst, std::string_view taint_name = "") {
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, taint_name));
    inst.setMetadata(MKINT_IR_TAINT, md);
}

static void mark_sink(Instruction& inst, std::string_view sink_name = "") {
    auto& ctx = inst.getContext();
    auto md = MDNode::get(ctx, MDString::get(ctx, sink_name));
    inst.setMetadata(MKINT_IR_SINK, md);
}

struct MKintPass : public PassInfoMixin<MKintPass> {
    PreservedAnalyses run(Function& F, FunctionAnalysisManager& FAM)
    {
        MKINT_LOG() << "Running MKint pass on function " << F.getName();

        auto& ctx = F.getContext();

        // TODO: MiniPass 1: Broadcast taint/sink;
        // TODO:           : Mark instructions to check and checking type;
        // TODO: MiniPass 2: Collect constraints and solve;
        // TODO:           : Remove label if violation not sat;


        // FIXME: This is some dummy code to test.
        auto&& bb = F.getEntryBlock();
        for (auto& inst : bb) {
            mark_err<interr::OUT_OF_BOUND>(inst);
        }

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