#include "llvm/ADT/ArrayRef.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace std;
using namespace llvm;

#define DEBUG_TYPE ""

/* Runttime Function List */
#define __GEP_CHECK "__gep_check" // void* __gep_check(void*, void*, int64_t)

namespace
{
    struct ProtectionPass : public ModulePass
    {
        static char ID;
        ProtectionPass() : ModulePass(ID) {}

        Module *M;

        virtual bool runOnModule(Module &M)
        {
            this->M = &M;

            bindRuntime();
            for (auto &F : M)
            {
                LLVM_DEBUG(dbgs() << "Hooking Function " << F.getName() << "\n");
                hookGepInstruction(F);
            }
            return false;
        }

        void bindRuntime()
        {
            LLVMContext &context = M->getContext();
            Type *int64Type = Type::getInt64Ty(context);
            Type *voidPointerType = Type::getInt8PtrTy(context, 0);

            M->getOrInsertFunction(
                __GEP_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType, int64Type},
                    false));
        }

        static void addChecker(GetElementPtrInst *gep)
        {
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
    };
}

char ProtectionPass::ID = 0;

static void registerProtectionPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM)
{
    static ProtectionPass *pass = nullptr;
    if (pass == nullptr)
        PM.add(pass = new ProtectionPass());
}

static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_OptimizerLast,
                    registerProtectionPass);
static RegisterStandardPasses
    RegisterMyPass1(PassManagerBuilder::EP_EnabledOnOptLevel0,
                    registerProtectionPass);