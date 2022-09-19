#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetFolder.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
using namespace llvm;

#define DEBUG_TYPE ""

/* Runttime Function List */
#define __GEP_CHECK "__violet_gep_check"         // void* __gep_check(void*, void*, int64_t)
#define __BITCAST_CHECK "__violet_bitcast_check" // void *__bitcast_check(void *, int64_t);
#define __BUILTIN_CHECK "__violet_builtin_check" // __violet_builtin_check(void *, uint8_t, int64_t, int64_t);

namespace
{
    struct VProtectionPass : public FunctionPass
    {
        static char ID;
        VProtectionPass() : FunctionPass(ID) {}

        // Basic
        Module *M;
        const DataLayout *DL;

        // Analysis
        const TargetLibraryInfo *TLI;
        ScalarEvolution *SE;
        ObjectSizeOffsetEvaluator *OSOE;

        // Type Utils
        Type *int1Type;
        Type *int64Type;
        Type *voidPointerType;

        // Statistic
        int64_t gepOptimized;
        int64_t gepRuntimeCheck;
        int64_t gepBuiltinCheck;
        int64_t bitcastOptimized;
        int64_t bitcastBuiltinCheck;
        int64_t bitcastRuntimeCheck;

        StringRef getPassName() const override
        {
            return "VProtectionPass";
        }

        bool runOnFunction(Function &F) override
        {
            if (!F.isIntrinsic() &&
                !isInternalFunction(F.getName()) &&
                F.getInstructionCount() > 0)
            {

                M = F.getParent();
                DL = &M->getDataLayout();

                gepOptimized = 0;
                gepRuntimeCheck = 0;
                gepBuiltinCheck = 0;
                bitcastOptimized = 0;
                bitcastBuiltinCheck = 0;
                bitcastRuntimeCheck = 0;

                bindRuntime();
                hookInstruction(F);

                report(F);
            }
            return false;
        }

        static bool isInternalFunction(StringRef name)
        {
            static StringSet<> ifunc = {
                __GEP_CHECK,
                __BITCAST_CHECK,
            };

            return ifunc.count(name) != 0;
        }

        void bindRuntime()
        {
            LLVMContext &context = M->getContext();
            int1Type = Type::getInt1Ty(context);
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

            M->getOrInsertFunction(
                __BUILTIN_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, int1Type, int64Type, int64Type},
                    false));
        }

        void getAnalysisUsage(AnalysisUsage &AU) const override
        {
            AU.addRequired<DominatorTreeWrapperPass>();
            AU.addRequired<TargetLibraryInfoWrapperPass>();
            AU.addRequired<PostDominatorTreeWrapperPass>();
            AU.addRequired<AAResultsWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
            AU.addRequired<ScalarEvolutionWrapperPass>();
        }

        void report(Function &F)
        {
            dbgs() << "[REPORT:" << F.getName() << "]\n";
            if (bitcastOptimized > 0 || bitcastRuntimeCheck > 0 || bitcastBuiltinCheck > 0)
            {
                dbgs() << "    [BitCast]\n";
                dbgs() << "        Optimized: " << bitcastOptimized << " \n";
                dbgs() << "        Runtime Check: " << bitcastRuntimeCheck << " \n";
                dbgs() << "        Builtin Check: " << bitcastBuiltinCheck << " \n";
            }
            if (gepOptimized > 0 || gepRuntimeCheck > 0 || gepBuiltinCheck > 0)
            {

                dbgs() << "    [GepElementPtr] \n";
                dbgs() << "        Optimized: " << gepOptimized << " \n";
                dbgs() << "        Runtime Check: " << gepRuntimeCheck << " \n";
                dbgs() << "        Builtin Check: " << gepBuiltinCheck << " \n";
            }
        }

        void hookInstruction(Function &F)
        {
            SmallVector<GetElementPtrInst *, 16> runtimeCheckGep;
            SmallVector<std::pair<GetElementPtrInst *, Value *>, 16> builtinCheckGep;
            SmallVector<BitCastInst *, 16> runtimeCheckBc;
            SmallVector<std::pair<BitCastInst *, Value *>, 16> builtinCheckBc;

            this->TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
            this->SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();

            ObjectSizeOpts EvalOpts;
            EvalOpts.RoundToAlign = true;
            this->OSOE = new ObjectSizeOffsetEvaluator(*DL, TLI, F.getContext(), EvalOpts);

            for (BasicBlock &BB : F)
                for (Instruction &I : BB)
                    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&I))
                    {
                        // TODO: Simply ignoring it may cause some bugs
                        if (gep->getType()->isPointerTy())
                        {
                            if (!allocateChecker(gep, runtimeCheckGep, builtinCheckGep))
                                gepOptimized++;
                        }
                    }
                    else if (BitCastInst *bc = dyn_cast<BitCastInst>(&I))
                    {
                        if (bc->getSrcTy()->isPointerTy() && bc->getDestTy()->isPointerTy())
                        {
                            // TODO: Simply ignoring it may cause some bugs
                            if (!bc->getSrcTy()->getPointerElementType()->isSized() ||
                                !bc->getDestTy()->getPointerElementType()->isSized())
                                continue;

                            unsigned int srcSize = DL->getTypeAllocSize(bc->getSrcTy()->getPointerElementType());
                            unsigned int dstSize = DL->getTypeAllocSize(bc->getDestTy()->getPointerElementType());

                            if (srcSize <= dstSize)
                                continue;
                            if (!allocateChecker(bc, runtimeCheckBc, builtinCheckBc))
                                bitcastOptimized++;
                        }
                    }

            for (auto &gep : runtimeCheckGep)
            {
                gepRuntimeCheck++;
                addGepRuntimeCheck(gep);
            }

            for (auto &[gep, cond] : builtinCheckGep)
            {
                gepBuiltinCheck++;
                addBuiltinCheck(gep, cond);
            }

            for (auto bc : runtimeCheckBc)
            {
                bitcastRuntimeCheck++;
                addBitcastRuntimeCheck(bc);
            }

            for (auto &[bc, cond] : builtinCheckBc)
            {
                bitcastBuiltinCheck++;
                addBuiltinCheck(bc, cond);
            }
        }

        void addBuiltinCheck(Instruction *I, Value *cond)
        {
            /*
                llvm/lib/Transforms/Instrumentation/BoundsChecking.cpp
            */

            SizeOffsetEvalType SizeOffset = OSOE->compute(I);
            IRBuilder<> irBuilder(I->getNextNode());

            Value *ptr = irBuilder.CreatePointerCast(I, voidPointerType);
            Value *size = SizeOffset.first;
            Value *offset = SizeOffset.second;

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__BUILTIN_CHECK), {ptr, cond, size, offset}),
                I->getType());

            I->replaceUsesWithIf(masked, [ptr, masked](Use &U)
                                 { return U.getUser() != ptr && U.getUser() != masked; });
        }

        void addGepRuntimeCheck(GetElementPtrInst *gep)
        {
            /*
                Before:
                    %result = gep %base %offset

                After:
                    %result  = gep %base %offset
                    %masked = __gep_check(%base, %result, size)
                    then replace all %result with %masked
            */

            uint64_t typeSize = DL->getTypeAllocSize(gep->getType()->getPointerElementType());

            IRBuilder<> irBuilder(gep->getNextNode());

            Value *base = irBuilder.CreatePointerCast(gep->getPointerOperand(), voidPointerType);
            Value *result = irBuilder.CreatePointerCast(gep, voidPointerType);
            Value *size = irBuilder.getInt64(typeSize);

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__GEP_CHECK), {base, result, size}),
                gep->getType());

            gep->replaceUsesWithIf(masked, [result, masked](Use &U)
                                   { return U.getUser() != result && U.getUser() != masked; });
        }

        void addBitcastRuntimeCheck(BitCastInst *bc)
        {
            /*
                Before:
                    %dst = bitcast %src ty1 ty2

                After:
                    %dst = bitcast %src ty1 ty2
                    %masked = __bitcast_check(%dst, size)
                    then replace all %dst with %masked
            */

            IRBuilder<> irBuilder(bc->getNextNode());

            Value *ptr = irBuilder.CreatePointerCast(bc, voidPointerType);
            Value *size = irBuilder.getInt64(DL->getTypeAllocSize(bc->getDestTy()->getPointerElementType()));

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__BITCAST_CHECK), {ptr, size}),
                bc->getType());

            bc->replaceUsesWithIf(masked, [ptr, masked](Use &U)
                                  { return U.getUser() != ptr && U.getUser() != masked; });
        }

        template <typename T, unsigned N>
        bool allocateChecker(T Ptr, SmallVector<T, N> &runtimeCheck, SmallVector<std::pair<T, Value *>, N> &builtinCheck)
        {
            Value *Or = getBoundsCheckCond(Ptr);
            if (Or == nullptr)
            {
                runtimeCheck.push_back(Ptr);
                return true;
            }

            ConstantInt *C = dyn_cast_or_null<ConstantInt>(Or);
            if (C)
            {
                if (!C->getZExtValue())
                    return false;
            }

            // FIXME: The bounds checking has some wired bugs
            // builtinCheck.push_back(std::make_pair(Ptr, Or));
            runtimeCheck.push_back(Ptr);
            return true;
        }

        Value *getBoundsCheckCond(Instruction *Ptr)
        {
            assert(Ptr->getType()->isPointerTy() && "getBoundsCheckCond(): Ptr should be pointer type");
            uint32_t NeededSize = DL->getTypeAllocSize(Ptr->getType()->getPointerElementType());
            IRBuilder<TargetFolder> IRB(Ptr->getParent(), BasicBlock::iterator(Ptr), TargetFolder(*DL));

            SizeOffsetEvalType SizeOffset = OSOE->compute(Ptr);
            if (!OSOE->bothKnown(SizeOffset))
                return nullptr;

            Value *Size = SizeOffset.first;
            Value *Offset = SizeOffset.second;
            ConstantInt *SizeCI = dyn_cast<ConstantInt>(Size);

            Type *IntTy = DL->getIntPtrType(Ptr->getType());
            Value *NeededSizeVal = ConstantInt::get(IntTy, NeededSize);

            auto SizeRange = SE->getUnsignedRange(SE->getSCEV(Size));
            auto OffsetRange = SE->getUnsignedRange(SE->getSCEV(Offset));
            auto NeededSizeRange = SE->getUnsignedRange(SE->getSCEV(NeededSizeVal));

            // three checks are required to ensure safety:
            // . Offset >= 0  (since the offset is given from the base ptr)
            // . Size >= Offset  (unsigned)
            // . Size - Offset >= NeededSize  (unsigned)
            //
            // optimization: if Size >= 0 (signed), skip 1st check
            // FIXME: add NSW/NUW here?  -- we dont care if the subtraction overflows
            Value *ObjSize = IRB.CreateSub(Size, Offset);
            Value *Cmp2 = SizeRange.getUnsignedMin().uge(OffsetRange.getUnsignedMax())
                              ? ConstantInt::getFalse(Ptr->getContext())
                              : IRB.CreateICmpULT(Size, Offset);
            Value *Cmp3 = SizeRange.sub(OffsetRange)
                                  .getUnsignedMin()
                                  .uge(NeededSizeRange.getUnsignedMax())
                              ? ConstantInt::getFalse(Ptr->getContext())
                              : IRB.CreateICmpULT(ObjSize, NeededSizeVal);
            Value *Or = IRB.CreateOr(Cmp2, Cmp3);
            if ((!SizeCI || SizeCI->getValue().slt(0)) &&
                !SizeRange.getSignedMin().isNonNegative())
            {
                Value *Cmp1 = IRB.CreateICmpSLT(Offset, ConstantInt::get(IntTy, 0));
                Or = IRB.CreateOr(Cmp1, Or);
            }

            return Or;
        }
    };
}

// char VGlobalsMetadataWrapperPass::ID = 0;
char VProtectionPass::ID = 0;

static void registerPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM)
{
    PM.add(new VProtectionPass());
}

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_OptimizerLast,
                   registerPass);
