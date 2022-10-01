#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/Pass.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
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
#define __GEP_CHECK "__gep_check_boundary"
#define __BITCAST_CHECK "__bc_check_boundary"
#define __REPORT_STATISTIC "__report_statistic"
#define __REPORT_ERROR "__report_error"
#define __GET_CHUNK_END "__get_chunk_end"

namespace
{
    struct VProtectionPass : public FunctionPass
    {
        static char ID;
        VProtectionPass() : FunctionPass(ID) {}

        // Basic
        Module *M;
        Function *F;
        const DataLayout *DL;

        // Analysis
        const TargetLibraryInfo *TLI;
        ScalarEvolution *SE;
        ObjectSizeOffsetEvaluator *OSOE;
        DominatorTree *DT;
        LoopInfo *LI;

        // Type Utils
        Type *voidType;
        Type *int32Type;
        Type *int64Type;
        Type *voidPointerType;

        // Statistic
        int64_t gepOptimized;
        int64_t gepPartialCheck;
        int64_t gepRuntimeCheck;
        int64_t gepBuiltinCheck;
        int64_t bitcastOptimized;
        int64_t bitcastPartialCheck;
        int64_t bitcastBuiltinCheck;
        int64_t bitcastRuntimeCheck;

        // Instruction
        DenseMap<Instruction *, Value *> source;
        DenseMap<Value *, SmallVector<Instruction *, 16> *> cluster;

        SmallSet<Instruction *, 16> escaped;
        SmallVector<Instruction *, 16> runtimeCheck;
        SmallVector<std::pair<Instruction *, Value *>, 16> builtinCheck;
        SmallVector<std::pair<Value *, SmallVector<Instruction *, 16> *>, 16> partialCheck;

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

                this->F = &F;

                M = F.getParent();
                DL = &M->getDataLayout();
                TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
                SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
                LI = &getAnalysis<LoopInfoWrapperPass>().getLoopInfo();

                ObjectSizeOpts EvalOpts;
                EvalOpts.RoundToAlign = true;
                OSOE = new ObjectSizeOffsetEvaluator(*DL, TLI, F.getContext(), EvalOpts);
                DT = new DominatorTree(F);

                gepOptimized = 0;
                gepRuntimeCheck = 0;
                gepPartialCheck = 0;
                gepBuiltinCheck = 0;
                bitcastOptimized = 0;
                bitcastBuiltinCheck = 0;
                bitcastPartialCheck = 0;
                bitcastRuntimeCheck = 0;

                source.clear();
                cluster.clear();
                runtimeCheck.clear();
                builtinCheck.clear();
                partialCheck.clear();

                bindRuntime();
                hookInstruction();

                if (F.getName() == "main")
                    insertReport();

                report();
                return true;
            }
            return false;
        }

        static bool isInternalFunction(StringRef name)
        {
            static StringSet<> ifunc = {
                __GEP_CHECK,
                __BITCAST_CHECK,
                __REPORT_STATISTIC,
                __REPORT_ERROR,
            };

            return ifunc.count(name) != 0;
        }

        void bindRuntime()
        {
            LLVMContext &context = M->getContext();
            voidType = Type::getVoidTy(context);
            int32Type = Type::getInt32Ty(context);
            int64Type = Type::getInt64Ty(context);
            voidPointerType = Type::getInt8PtrTy(context, 0);

            M->getOrInsertFunction(
                __GEP_CHECK,
                FunctionType::get(
                    int32Type,
                    {voidPointerType, voidPointerType, int64Type},
                    false));

            M->getOrInsertFunction(
                __BITCAST_CHECK,
                FunctionType::get(
                    int32Type,
                    {voidPointerType, int64Type},
                    false));

            M->getOrInsertFunction(
                __REPORT_STATISTIC,
                FunctionType::get(
                    voidType,
                    {},
                    false));

            M->getOrInsertFunction(
                __REPORT_ERROR,
                FunctionType::get(
                    voidType,
                    {},
                    false));

            M->getOrInsertFunction(
                __GET_CHUNK_END,
                FunctionType::get(
                    int64Type,
                    {int64Type},
                    false));
        }

        void insertReport()
        {
            SmallVector<Instruction *, 16> returns;
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                    if (ReturnInst *ret = dyn_cast<ReturnInst>(&I))
                        returns.push_back(ret);

            for (auto ret : returns)
            {
                IRBuilder<> irBuilder(ret);
                irBuilder.CreateCall(M->getFunction(__REPORT_STATISTIC));
            }
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

        void report()
        {
            dbgs() << "[REPORT:" << F->getName() << "]\n";
            if (bitcastOptimized > 0 || bitcastRuntimeCheck > 0 || bitcastPartialCheck > 0 || bitcastBuiltinCheck > 0)
            {
                dbgs() << "    [BitCast]\n";
                dbgs() << "        Optimized: " << bitcastOptimized << " \n";
                dbgs() << "        Runtime Check: " << bitcastRuntimeCheck << " \n";
                dbgs() << "        Partial Check: " << bitcastPartialCheck << " \n";
                dbgs() << "        Builtin Check: " << bitcastBuiltinCheck << " \n";
            }
            if (gepOptimized > 0 || gepRuntimeCheck > 0 || gepPartialCheck > 0 || gepBuiltinCheck > 0)
            {

                dbgs() << "    [GepElementPtr] \n";
                dbgs() << "        Optimized: " << gepOptimized << " \n";
                dbgs() << "        Runtime Check: " << gepRuntimeCheck << " \n";
                dbgs() << "        Partial Check: " << gepPartialCheck << " \n";
                dbgs() << "        Builtin Check: " << gepBuiltinCheck << " \n";
            }
        }

        void hookInstruction()
        {
            collectInformation();

            builtinOptimize();
            partialBuiltinOptimize();

            applyInstrument();
        }

        void addBuiltinCheck(Instruction *I, Value *Cond)
        {
            /*
                llvm/lib/Transforms/Instrumentation/BoundsChecking.cpp
            */

            IRBuilder<> irBuilder(SplitBlockAndInsertIfThen(Cond, I->getNextNode(), false));
            irBuilder.CreateCall(M->getFunction(__REPORT_ERROR), {});
        }

        void addPartialCheck(Value *V, SmallVector<Instruction *, 16> *S)
        {
            Instruction *InsertPoint = nullptr;

            if (isa<Instruction>(V))
                InsertPoint = dyn_cast<Instruction>(V)->getNextNode();
            else if (isa<Argument>(V))
                InsertPoint = &(F->getEntryBlock().front());
            else if (isa<GlobalVariable>(V))
                return;

            if (InsertPoint == nullptr)
                dbgs() << *V << "\n";
            assert(InsertPoint != nullptr);

            IRBuilder<> irBuilder(InsertPoint);
            auto base = irBuilder.CreatePtrToInt(V, int64Type);
            auto end = irBuilder.CreateCall(M->getFunction(__GET_CHUNK_END), {base});

            int64_t osize = DL->getTypeAllocSize(V->getType()->getPointerElementType());
            auto realEnd = irBuilder.CreateSub(end, ConstantInt::get(int64Type, osize));

            for (auto I : *S)
            {
                InsertPoint = I->getNextNode();
                irBuilder.SetInsertPoint(InsertPoint);

                auto Ptr = irBuilder.CreatePtrToInt(I, int64Type);
                auto offset = irBuilder.CreateSub(Ptr, base);

                Value *Cond = nullptr;
                int64_t nsize = DL->getTypeAllocSize(I->getType()->getPointerElementType());
                if (nsize == osize)
                {
                    Cond = irBuilder.CreateICmpSLT(realEnd, Ptr);
                }
                else
                {
                    Value *needsize = ConstantInt::get(int64Type, nsize);
                    Cond = irBuilder.CreateICmpSLT(irBuilder.CreateSub(end, needsize), Ptr);
                }

                if (SE->getSignedRangeMin(SE->getSCEV(offset)).isNegative())
                    Cond = irBuilder.CreateOr(Cond, irBuilder.CreateICmpSLT(Ptr, base));

                assert(isa<Instruction>(offset));
                dyn_cast<Instruction>(offset)->eraseFromParent();

                irBuilder.SetInsertPoint(SplitBlockAndInsertIfThen(Cond, InsertPoint, false));
                irBuilder.CreateCall(M->getFunction(__REPORT_ERROR), {});
            }
        }

        void addGepRuntimeCheck(Instruction *I)
        {
            /*
                Before:
                    %result = gep %base %offset

                After:
                    %result  = gep %base %offset
                    %masked = __gep_check(%base, %result, size)
                    then replace all %result with %masked
            */
            auto gep = dyn_cast_or_null<GetElementPtrInst>(I);
            assert(gep != nullptr && "addGepRuntimeCheck: Require GetElementPtrInst");

            uint64_t typeSize = DL->getTypeAllocSize(gep->getType()->getPointerElementType());

            IRBuilder<> irBuilder(gep->getNextNode());

            Value *base = irBuilder.CreatePointerCast(gep->getPointerOperand(), voidPointerType);
            Value *result = irBuilder.CreatePointerCast(gep, voidPointerType);
            Value *size = irBuilder.getInt64(typeSize);

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__GEP_CHECK), {base, result, size}),
                gep->getType());

            // gep->replaceUsesWithIf(masked, [result, masked](Use &U)
            //                        { return U.getUser() != result && U.getUser() != masked; });
        }

        void addBitcastRuntimeCheck(Instruction *I)
        {
            /*
                Before:
                    %dst = bitcast %src ty1 ty2

                After:
                    %dst = bitcast %src ty1 ty2
                    %masked = __bitcast_check(%dst, size)
                    then replace all %dst with %masked
            */

            auto bc = dyn_cast_or_null<BitCastInst>(I);
            assert(bc != nullptr && "addBitcastRuntimeCheck: Require BitCastInst");

            IRBuilder<> irBuilder(bc->getNextNode());

            Value *ptr = irBuilder.CreatePointerCast(bc, voidPointerType);
            Value *size = irBuilder.getInt64(DL->getTypeAllocSize(bc->getDestTy()->getPointerElementType()));

            Value *masked = irBuilder.CreatePointerCast(
                irBuilder.CreateCall(M->getFunction(__BITCAST_CHECK), {ptr, size}),
                bc->getType());

            // bc->replaceUsesWithIf(masked, [ptr, masked](Use &U)
            //                       { return U.getUser() != ptr && U.getUser() != masked; });
        }

        bool allocateChecker(Instruction *Ptr, SmallVector<Instruction *, 16> &runtimeCheck, SmallVector<std::pair<Instruction *, Value *>, 16> &builtinCheck)
        {
            assert(Ptr->getType()->isPointerTy() && "allocateChecker(): Ptr should be pointer type");

            if (escaped.count(Ptr) == 0)
                return false;

            SizeOffsetEvalType SizeOffset;
            Value *Or = getBoundsCheckCond(Ptr, SizeOffset);
            ConstantInt *C = dyn_cast_or_null<ConstantInt>(Or);

            if (C && !C->getZExtValue())
                return false;

            // TODO: Built in optimization is not always better
            if (Or != nullptr)
                // We need save the `SizeOffset` before instrument.
                // Because the analysis result will changed after instrument,
                // but our instrument will not change the semantic.
                builtinCheck.push_back(std::make_pair(Ptr, Or));
            else
                runtimeCheck.push_back(Ptr);
            return true;
        }

        Value *getBoundsCheckCond(Instruction *Ptr, SizeOffsetEvalType &SizeOffset)
        {
            assert(Ptr->getType()->isPointerTy() && "getBoundsCheckCond(): Ptr should be pointer type");

            uint32_t NeededSize = DL->getTypeAllocSize(Ptr->getType()->getPointerElementType());
            IRBuilder<TargetFolder> IRB(Ptr->getParent(), BasicBlock::iterator(Ptr), TargetFolder(*DL));

            SizeOffset = OSOE->compute(Ptr);
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

        Value *findSource(Value *V)
        {
            if (Instruction *I = dyn_cast<Instruction>(V))
            {
                if (source.count(I))
                {
                    return source[I];
                }
            }

            if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V))
            {
                return source[gep] = findSource(gep->getPointerOperand());
            }
            if (BitCastInst *bc = dyn_cast<BitCastInst>(V))
            {
                Value *S = findSource(bc->getOperand(0));
                if (CallInst *C = dyn_cast<CallInst>(S))
                    if (escaped.count(bc) == 0)
                        return bc; // It is a peephole, optimization

                return source[bc] = S;
            }

            return V;
        }

        void collectInformation()
        {
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                    if (isa<GetElementPtrInst>(I) || isa<BitCastInst>(I))
                    {
                        for (auto user : I.users())
                        {
                            if (isa<LoadInst>(user) || isa<StoreInst>(user) || isa<ReturnInst>(user))
                            {
                                escaped.insert(&I);
                                break;
                            }
                        }
                    }

            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                    findSource(&I);
        }

        void builtinOptimize()
        {
            for (BasicBlock &BB : *F)
            {
                for (Instruction &I : BB)
                {
                    if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(&I))
                    {
                        // TODO: Simply ignoring it may cause some bugs
                        if (gep->getType()->isPointerTy())
                        {
                            if (!allocateChecker(gep, runtimeCheck, builtinCheck))
                            {
                                gepOptimized++;
                            }
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

                            if (srcSize == dstSize)
                                continue;
                            if (!allocateChecker(bc, runtimeCheck, builtinCheck))
                                bitcastOptimized++;
                        }
                    }
                }
            }
        }

        void partialBuiltinOptimize()
        {
            for (auto &I : runtimeCheck)
            {
                auto src = source[I];
                if (!cluster.count(src))
                    cluster[src] = new SmallVector<Instruction *, 16>();
                cluster[src]->push_back(I);
            }

            SmallVector<Instruction *, 16> newRuntimeCheck;
            for (auto &[key, value] : cluster)
            {
                int64_t weight = 0;
                for (auto ins : *value)
                {
                    weight += 1;
                    if (Loop *Lop = LI->getLoopFor(ins->getParent()))
                        weight += 5;
                }

                if (weight > 3)
                    partialCheck.push_back(std::make_pair(key, value));
                else
                    newRuntimeCheck.append(*value);
            }

            runtimeCheck.swap(newRuntimeCheck);
        }

        void applyInstrument()
        {
            for (auto &I : runtimeCheck)
            {
                if (isa<GetElementPtrInst>(I))
                {
                    gepRuntimeCheck++;
                    addGepRuntimeCheck(I);
                }
                else
                {
                    bitcastRuntimeCheck++;
                    addBitcastRuntimeCheck(I);
                }
            }

            for (auto &[V, S] : partialCheck)
            {
                for (auto &I : *S)
                    if (isa<GetElementPtrInst>(I))
                        gepPartialCheck++;
                    else
                        bitcastPartialCheck++;

                addPartialCheck(V, S);
            }

            for (auto &[I, cond] : builtinCheck)
            {
                if (isa<GetElementPtrInst>(I))
                    gepBuiltinCheck++;
                else
                    bitcastBuiltinCheck++;

                addBuiltinCheck(I, cond);
            }
        }
    };
}

char VProtectionPass::ID = 0;

static void registerPass(const PassManagerBuilder &,
                         legacy::PassManagerBase &PM)
{
    PM.add(new VProtectionPass());
}

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_OptimizerLast,
                   registerPass);
