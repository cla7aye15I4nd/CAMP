#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/Debug.h"
using namespace llvm;

#define DEBUG_TYPE ""

namespace
{
    static void addChecker(GetElementPtrInst *gep) {

    }

    static void hookGepInstruction(Function &F)
    {
        SmallVector<GetElementPtrInst *, 16> GepInsts;

        for (BasicBlock &BB : F)
            for (Instruction &I : BB)
                if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&I))
                    GepInsts.push_back(gep);

        for (auto gep : GepInsts)
            addChecker(gep);
    }

    struct ProtectionPass : public FunctionPass
    {
        static char ID;
        ProtectionPass() : FunctionPass(ID) {}

        virtual bool runOnFunction(Function &F)
        {
            LLVM_DEBUG(dbgs() << "Hooking Function " << F.getName() << "\n");
            hookGepInstruction(F);
            return false;
        }
    };
}

char ProtectionPass::ID = 0;

static void registerProtectionPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM)
{
    PM.add(new ProtectionPass());
}
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_EarlyAsPossible,
                   registerProtectionPass);