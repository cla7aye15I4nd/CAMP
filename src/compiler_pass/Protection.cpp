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

/* Runtime Function List */
#define __GEP_CHECK "__gep_check_boundary"
#define __BITCAST_CHECK "__bc_check_boundary"
#define __REPORT_STATISTIC "__report_statistic"
#define __REPORT_ERROR "__report_error"
#define __GET_CHUNK_END "__get_chunk_end"
#define __ESCAPE "__escape"

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
        PostDominatorTree *PDT;
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
        int64_t escapeTrace;

        // Instruction
        DenseMap<Instruction *, Value *> source;
        DenseMap<Value *, SmallVector<Instruction *, 16> *> cluster;

        SmallSet<Instruction *, 16> escaped;
        SmallVector<Instruction *, 16> runtimeCheck;
        SmallVector<std::pair<Instruction *, Value *>, 16> builtinCheck;
        SmallVector<std::pair<Value *, SmallVector<Instruction *, 16> *>, 16> partialCheck;

        SmallVector<StoreInst *, 16> storeInsts;

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
                PDT = new PostDominatorTree(F);

                gepOptimized = 0;
                gepRuntimeCheck = 0;
                gepPartialCheck = 0;
                gepBuiltinCheck = 0;
                bitcastOptimized = 0;
                bitcastBuiltinCheck = 0;
                bitcastPartialCheck = 0;
                bitcastRuntimeCheck = 0;
                escapeTrace = 0;

                source.clear();
                cluster.clear();
                runtimeCheck.clear();
                builtinCheck.clear();
                partialCheck.clear();
                storeInsts.clear();

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
                __GET_CHUNK_END,
                __ESCAPE,
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

            M->getOrInsertFunction(
                __ESCAPE,
                FunctionType::get(
                    voidType,
                    {voidPointerType, voidPointerType},
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
            if (escapeTrace > 0)
            {
                dbgs() << "    [Escape]\n";
                dbgs() << "        Escape Trace: " << escapeTrace << " \n";
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
            else if (isa<Operator>(V))
                return;

            assert(InsertPoint != nullptr);

            IRBuilder<> irBuilder(InsertPoint);
            auto base = irBuilder.CreatePtrToInt(V, int64Type);
            auto end = irBuilder.CreateCall(M->getFunction(__GET_CHUNK_END), {base});

            int64_t osize = -1;
            Value *realEnd = nullptr;

            if (V->getType()->getPointerElementType()->isSized())
            {
                osize = DL->getTypeAllocSize(V->getType()->getPointerElementType());
                realEnd = irBuilder.CreateSub(end, ConstantInt::get(int64Type, osize));
            }

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
                    __gep_check(%base, %result, size)
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
                    __bitcast_check(%dst, size)
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

        void addEscape(StoreInst *SI)
        {
            IRBuilder<> irBuilder(SI);
            irBuilder.CreateCall(M->getFunction(__ESCAPE),
                                 {irBuilder.CreatePointerCast(SI->getPointerOperand(), voidPointerType),
                                  irBuilder.CreatePointerCast(SI->getValueOperand(), voidPointerType)});
        }

        bool allocateChecker(Instruction *Ptr, SmallVector<Instruction *, 16> &runtimeCheck, SmallVector<std::pair<Instruction *, Value *>, 16> &builtinCheck)
        {
            assert(Ptr->getType()->isPointerTy() && "allocateChecker(): Ptr should be pointer type");

            if (source.count(Ptr))
            {
                if (isa<GlobalValue>(source[Ptr]))
                    return false;

                if (isa<AllocaInst>(source[Ptr]))
                    return false;
            }

            if (escaped.count(Ptr) == 0)
                return false;

            SizeOffsetEvalType SizeOffset;
            Value *Or = getBoundsCheckCond(Ptr, SizeOffset);
            ConstantInt *C = dyn_cast_or_null<ConstantInt>(Or);

            if (C && !C->getZExtValue())
                return false;

            // TODO: Built in optimization is not always better
            if (Or != nullptr)
                // We need save the `Cond` before instrument.
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
                    else if (StoreInst *SI = dyn_cast<StoreInst>(&I))
                    {
                        if (SI->getValueOperand()->getType()->isPointerTy())
                            storeInsts.push_back(SI);
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
                // FIXME: Why I need this one?
                if (isa<PHINode>(key))
                    continue;

                dependenceOptimize(key, value);
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

        void dependenceOptimize(Value *key, SmallVector<Instruction *, 16> *value)
        {
            Instruction *InsertPoint = nullptr;

            if (isa<Instruction>(key))
                InsertPoint = dyn_cast<Instruction>(key)->getNextNode();
            else if (isa<Argument>(key))
                InsertPoint = &(F->getEntryBlock().front());
            else if (isa<Operator>(key))
                return;

            IRBuilder<> irBuilder(InsertPoint);
            auto base = irBuilder.CreatePtrToInt(key, int64Type);

            SmallVector<Instruction *, 16> newvalue;
            for (size_t i = 0; i < value->size(); ++i)
            {
                bool optimized = false;
                auto I = (*value)[i];

                irBuilder.SetInsertPoint(I->getNextNode());
                auto ptr_I = irBuilder.CreatePtrToInt(I, int64Type);
                auto offset_I = irBuilder.CreateSub(ptr_I, base);
                if (!SE->getSignedRangeMin(SE->getSCEV(offset_I)).isNegative())
                {
                    for (size_t j = 0; j < value->size() && !optimized; ++j)
                    {
                        if (i != j)
                        {
                            auto J = (*value)[j];
                            if (DT->dominates(J, I) || PDT->dominates(I, J))
                            {
                                irBuilder.SetInsertPoint(J->getNextNode());
                                auto ptr_J = irBuilder.CreatePtrToInt(J, int64Type);
                                auto offset_J = irBuilder.CreateSub(ptr_J, ptr_I);
                                if (!SE->getSignedRangeMin(SE->getSCEV(offset_J)).isNegative())
                                    optimized = true;
                                dyn_cast<Instruction>(ptr_J)->eraseFromParent();
                                dyn_cast<Instruction>(offset_J)->eraseFromParent();
                            }
                        }
                    }
                }
                dyn_cast<Instruction>(ptr_I)->eraseFromParent();
                dyn_cast<Instruction>(offset_I)->eraseFromParent();
                if (optimized)
                {
                    if (isa<GetElementPtrInst>(I))
                        gepOptimized++;
                    if (isa<BitCastInst>(I))
                        bitcastOptimized++;
                }
                else
                    newvalue.push_back(I);
            }
            dyn_cast<Instruction>(base)->eraseFromParent();
            value->swap(newvalue);
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

            for (auto SI : storeInsts)
            {
                escapeTrace++;
                addEscape(SI);
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
