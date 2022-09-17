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
#include <unordered_set>

using namespace std;
using namespace llvm;

#define DEBUG_TYPE ""

/* Runttime Function List */
#define __GEP_CHECK "__gep_check"         // void* __gep_check(void*, void*, int64_t)
#define __BITCAST_CHECK "__bitcast_check" // void *__bitcast_check(void *, int64_t);

namespace
{
    static bool isInternalFunction(string name)
    {
        static unordered_set<string> ifunc = {
            __GEP_CHECK,
            __BITCAST_CHECK,
        };

        return ifunc.count(name) != 0;
    }

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
        int64_t bitcastHookCounter;

        virtual bool runOnModule(Module &M)
        {
            this->M = &M;
            this->DL = &M.getDataLayout();
            this->gepHookCounter = 0;
            this->bitcastHookCounter = 0;

            bindRuntime();
            for (auto &F : M)
            {
                if (!F.isIntrinsic() &&
                    !isInternalFunction(F.getName()) &&
                    F.getInstructionCount() > 0)
                {
                    dbgs() << "Hooking Function " << F.getName() << "\n";
                    hookInstruction(F);
                }
            }

            report();

            return false;
        }

        void report()
        {
            dbgs() << "----------[ProtectionPass REPORT]----------\n";
            dbgs() << "BitCast: " << bitcastHookCounter << "\n";
            dbgs() << "GepElementPtr: " << gepHookCounter << "\n";
            dbgs() << "-------------------------------------------\n";
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

            M->getOrInsertFunction(
                __BITCAST_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, int64Type},
                    false));
        }

        void hookInstruction(Function &F)
        {
            SmallVector<GetElementPtrInst *, 16> gepInsts;
            SmallVector<BitCastInst *, 16> bcInsts;

            for (BasicBlock &BB : F)
                for (Instruction &I : BB)
                    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&I))
                    {
                        // TODO: Simply ignoring it may cause some bugs
                        if (gep->getType()->isPointerTy())
                            gepInsts.push_back(gep);
                    }
                    else if (BitCastInst *bc = dyn_cast<BitCastInst>(&I))
                    {
                        if (bc->getSrcTy()->isPointerTy() && bc->getDestTy()->isPointerTy())
                            bcInsts.push_back(bc);
                    }

            for (auto gep : gepInsts)
                addGepChecker(gep);

            for (auto bc : bcInsts)
                addBitcastChecker(bc);
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
                gep->getType());

            gep->replaceUsesWithIf(masked, [result, masked](Use &U)
                                   { return U.getUser() != result && U.getUser() != masked; });

            gepHookCounter++;
        }

        void addBitcastChecker(BitCastInst *bc)
        {
            /*
                Before:
                    %dst = bitcast %src ty1 ty2

                After:
                    %dst = bitcast %src ty1 ty2
                    %masked = __bitcast_check(%dst, size)
                    then replace all %dst with %masked
            */

            // TODO: Simply ignoring it may cause some bugs
            if (!bc->getSrcTy()->getPointerElementType()->isSized() ||
                !bc->getDestTy()->getPointerElementType()->isSized())
                return;

            unsigned int srcSize = DL->getTypeAllocSize(bc->getSrcTy()->getPointerElementType());
            unsigned int dstSize = DL->getTypeAllocSize(bc->getDestTy()->getPointerElementType());

            // Optimization 1
            if (srcSize <= dstSize)
                return;

            IRBuilder<> irBuilder(bc->getNextNode());

            Value *ptr = irBuilder.CreatePointerCast(bc, voidPointerType);
            Value *size = irBuilder.getInt64(dstSize);

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__BITCAST_CHECK), {ptr, size}),
                bc->getType());

            bc->replaceUsesWithIf(masked, [ptr, masked](Use &U)
                                  { return U.getUser() != ptr && U.getUser() != masked; });

            bitcastHookCounter++;
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