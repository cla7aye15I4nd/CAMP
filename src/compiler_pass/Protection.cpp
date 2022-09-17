#include "llvm/ADT/ArrayRef.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
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

        // Context
        Module *M;
        const DataLayout *DL;

        // Type Utils
        Type *int64Type;
        Type *voidPointerType;

        // Statistic
        int64_t gepHookCounter;

        virtual bool runOnModule(Module &M)
        {
            this->M = &M;
            this->DL = &M.getDataLayout();
            this->gepHookCounter = 0;

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

            int64Type = Type::getInt64Ty(context);
            voidPointerType = Type::getInt8PtrTy(context, 0);

            M->getOrInsertFunction(
                __GEP_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType, int64Type},
                    false));
        }

        void addGepChecker(GetElementPtrInst *gep)
        {
            /*
                Before:
                    %result = gep %base %offset

                After:
                    %result  = gep %base %offset
                    %masked = __gep_check(%base, %result, size)
                    then replace all %result with %masked
            */

            IRBuilder<> irBuilder(gep->getNextNode());

            Value *base = irBuilder.CreatePointerCast(gep->getPointerOperand(), voidPointerType);
            Value *result = irBuilder.CreatePointerCast(gep, voidPointerType);
            Value *size = irBuilder.getInt64(DL->getTypeAllocSize(gep->getResultElementType()));

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__GEP_CHECK), {base, result, size}),
                gep->getType()
            );

            gep->replaceUsesWithIf(masked, [result](Use &U)
                                      { return U.getUser() != result; });

            gepHookCounter++;
        }

        void hookGepInstruction(Function &F)
        {
            SmallVector<GetElementPtrInst *, 16> GepInsts;

            for (BasicBlock &BB : F)
                for (Instruction &I : BB)
                    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&I))
                        GepInsts.push_back(gep);

            for (auto gep : GepInsts)
                addGepChecker(gep);
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