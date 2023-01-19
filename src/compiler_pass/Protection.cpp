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
#include "config.h"
using namespace llvm;

#define DEBUG_TYPE ""

/* Runtime Function List */
#define __GEP_CHECK "__gep_check_boundary"
#define __BITCAST_CHECK "__bc_check_boundary"
#define __REPORT_STATISTIC "__report_statistic"
#define __REPORT_ERROR "__report_error"
#define __GET_CHUNK_RANGE "__get_chunk_range"
#define __ESCAPE "__escape"
#define __STRCPY_CHECK "__strcpy_check"
#define __STRNCPY_CHECK "__strncpy_check"
#define __STRCAT_CHECK "__strcat_check"
#define __STRNCAT_CHECK "__strncat_check"

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

#if CONFIG_ENABLE_OOB_OPTIMIZATION
        // Analysis
        const TargetLibraryInfo *TLI;
        ScalarEvolution *SE;
        ObjectSizeOffsetEvaluator *OSOE;
        DominatorTree *DT;
        PostDominatorTree *PDT;
        LoopInfo *LI;
#endif
        // Type Utils
        Type *voidType;
        Type *int32Type;
        Type *int64Type;
        Type *voidPointerType;
        Type *int64PointerType;

        // Statistic
        int64_t gepIgnoreOptimized;
        int64_t gepDepOptimized;
        int64_t gepPartialCheck;
        int64_t gepRuntimeCheck;
        int64_t gepBuiltinCheck;
        int64_t bitcastIgnoreOptimized;
        int64_t bitcastDepOptimized;
        int64_t bitcastPartialCheck;
        int64_t bitcastBuiltinCheck;
        int64_t bitcastRuntimeCheck;
        int64_t escapeTrace;
        int64_t escapeOptimized;

        // Instruction
        DenseMap<Value *, Value *> source;
        DenseMap<Value *, SmallVector<Instruction *, 16> *> cluster;

        SmallSet<Instruction *, 16> escaped;
        SmallSet<Instruction *, 16> auxiliary;
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
#if CONFIG_ENABLE_OOB_OPTIMIZATION
                TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
                SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
                LI = &getAnalysis<LoopInfoWrapperPass>().getLoopInfo();

                ObjectSizeOpts EvalOpts;
                EvalOpts.RoundToAlign = true;
                OSOE = new ObjectSizeOffsetEvaluator(*DL, TLI, F.getContext(), EvalOpts);
                DT = new DominatorTree(F);
                PDT = new PostDominatorTree(F);
#endif
                gepIgnoreOptimized = 0;
                gepDepOptimized = 0;
                gepRuntimeCheck = 0;
                gepPartialCheck = 0;
                gepBuiltinCheck = 0;
                bitcastIgnoreOptimized = 0;
                bitcastDepOptimized = 0;
                bitcastBuiltinCheck = 0;
                bitcastPartialCheck = 0;
                bitcastRuntimeCheck = 0;
                escapeTrace = 0;
                escapeOptimized = 0;

                source.clear();
                cluster.clear();
                escaped.clear();
                auxiliary.clear();
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
                __GET_CHUNK_RANGE,
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
            int64PointerType = Type::getInt64PtrTy(context, 0);

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
                __GET_CHUNK_RANGE,
                FunctionType::get(
                    int64Type,
                    {int64Type, int64PointerType},
                    false));

            M->getOrInsertFunction(
                __ESCAPE,
                FunctionType::get(
                    int32Type,
                    {voidPointerType, voidPointerType},
                    false));

            M->getOrInsertFunction(
                __STRCPY_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType},
                    false));

            M->getOrInsertFunction(
                __STRNCPY_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType, int64Type},
                    false));

            M->getOrInsertFunction(
                __STRCAT_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType},
                    false));

            M->getOrInsertFunction(
                __STRNCAT_CHECK,
                FunctionType::get(
                    voidPointerType,
                    {voidPointerType, voidPointerType, int64Type},
                    false));
        }

        void insertReport()
        {
            SmallVector<Instruction *, 16> returns;
            SmallVector<Instruction *, 16> calls;
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                {
                    if (ReturnInst *ret = dyn_cast<ReturnInst>(&I))
                        returns.push_back(ret);
                    if (CallInst *call = dyn_cast<CallInst>(&I))
                        calls.push_back(call);
                }

            for (auto ret : returns)
            {
                IRBuilder<> irBuilder(ret);
                irBuilder.CreateCall(M->getFunction(__REPORT_STATISTIC));
            }

            // Avoid directly call exit(status) in main() function, instead of return, like 600.perlbench_s
            for (auto I : calls)
            {
                CallInst *call = dyn_cast<CallInst>(I);
                Function *fp = call->getCalledFunction();

                if (fp != nullptr && fp->getName() == "exit")
                {
                    IRBuilder<> irBuilder(call);
                    irBuilder.CreateCall(M->getFunction(__REPORT_STATISTIC));
                }
            }
        }
#if CONFIG_ENABLE_OOB_OPTIMIZATION
        void getAnalysisUsage(AnalysisUsage &AU) const override
        {
            AU.addRequired<DominatorTreeWrapperPass>();
            AU.addRequired<TargetLibraryInfoWrapperPass>();
            AU.addRequired<PostDominatorTreeWrapperPass>();
            AU.addRequired<AAResultsWrapperPass>();
            AU.addRequired<LoopInfoWrapperPass>();
            AU.addRequired<ScalarEvolutionWrapperPass>();
        }
#endif
        void report()
        {
            dbgs() << "[REPORT:" << F->getName() << "]\n";
            if (bitcastRuntimeCheck > 0 || bitcastPartialCheck > 0 || bitcastBuiltinCheck > 0)
            {
                dbgs() << "    [BitCast]\n";
                dbgs() << "        Ignore Optimized: " << bitcastIgnoreOptimized << " \n";
                dbgs() << "        Dep Optimized: " << bitcastDepOptimized << " \n";
                dbgs() << "        Runtime Check: " << bitcastRuntimeCheck << " \n";
                dbgs() << "        Partial Check: " << bitcastPartialCheck << " \n";
                dbgs() << "        Builtin Check: " << bitcastBuiltinCheck << " \n";
            }
            if (gepRuntimeCheck > 0 || gepPartialCheck > 0 || gepBuiltinCheck > 0)
            {

                dbgs() << "    [GepElementPtr] \n";
                dbgs() << "        Ignore Optimized: " << gepIgnoreOptimized << " \n";
                dbgs() << "        Dep Optimized: " << gepDepOptimized << " \n";
                dbgs() << "        Runtime Check: " << gepRuntimeCheck << " \n";
                dbgs() << "        Partial Check: " << gepPartialCheck << " \n";
                dbgs() << "        Builtin Check: " << gepBuiltinCheck << " \n";
            }
            if (escapeTrace > 0)
            {
                dbgs() << "    [Escape]\n";
                dbgs() << "        Escape Optimized: " << escapeOptimized << " \n";
                dbgs() << "        Escape Trace: " << escapeTrace << " \n";
            }
        }

        void hookInstruction()
        {
            collectInformation();

            builtinOptimize();
#if CONFIG_ENABLE_OOB_OPTIMIZATION
            partialBuiltinOptimize();
#endif
            escapeOptimize();
            applyInstrument();
        }

        static Instruction *getInsertionPointAfterDef(Instruction *I)
        {
            assert(!I->getType()->isVoidTy() && "Instruction must define result");

            BasicBlock *InsertBB;
            BasicBlock::iterator InsertPt;
            if (auto *PN = dyn_cast<PHINode>(I))
            {
                InsertBB = PN->getParent();
                InsertPt = InsertBB->getFirstInsertionPt();
            }
            else if (auto *II = dyn_cast<InvokeInst>(I))
            {
                InsertBB = II->getNormalDest();
                InsertPt = InsertBB->getFirstInsertionPt();
            }
            else if (auto *CB = dyn_cast<CallBrInst>(I))
            {
                InsertBB = CB->getDefaultDest();
                InsertPt = InsertBB->getFirstInsertionPt();
            }
            else
            {
                assert(!I->isTerminator() && "Only invoke/callbr terminators return value");
                InsertBB = I->getParent();
                InsertPt = std::next(I->getIterator());
            }

            // catchswitch blocks don't have any legal insertion point (because they
            // are both an exception pad and a terminator).
            if (InsertPt == InsertBB->end())
                return nullptr;
            return &*InsertPt;
        }
#if CONFIG_ENABLE_OOB_OPTIMIZATION
        void addBuiltinCheck(Instruction *I, Value *Cond)
        {
            /*
                llvm/lib/Transforms/Instrumentation/BoundsChecking.cpp
            */

            IRBuilder<> irBuilder(SplitBlockAndInsertIfThen(Cond, fetchBestInsertPoint(I), false));
            irBuilder.CreateCall(M->getFunction(__REPORT_ERROR), {});
        }

        void addPartialCheck(Value *V, SmallVector<Instruction *, 16> *S)
        {
            Instruction *InsertPoint = nullptr;

            if (isa<Instruction>(V))
                InsertPoint = getInsertionPointAfterDef(dyn_cast<Instruction>(V));
            else if (isa<Argument>(V))
                InsertPoint = &(F->getEntryBlock().front());

            assert(InsertPoint != nullptr);

            IRBuilder<> irBuilder(&F->getEntryBlock().front());
            auto base_ptr = irBuilder.CreateAlloca(int64Type);

            irBuilder.SetInsertPoint(InsertPoint);

            auto ptr = irBuilder.CreatePtrToInt(V, int64Type);

            Value *rsp = readRegister(irBuilder, "rsp");
            Value *valueNotOnStack = irBuilder.CreateICmpULT(ptr, rsp);

            irBuilder.SetInsertPoint(SplitBlockAndInsertIfThen(valueNotOnStack, InsertPoint, false));
            auto if_end = irBuilder.CreateCall(M->getFunction(__GET_CHUNK_RANGE), {ptr, base_ptr});
            auto if_base = irBuilder.CreateLoad(base_ptr);

            irBuilder.SetInsertPoint(InsertPoint);
            PHINode* base = irBuilder.CreatePHI(int64Type, 2);
            base->addIncoming(ConstantInt::get(int64Type, 0), dyn_cast<Instruction>(valueNotOnStack)->getParent());
            base->addIncoming(if_base, if_base->getParent());

            PHINode* end = irBuilder.CreatePHI(int64Type, 2);
            end->addIncoming(ConstantInt::get(int64Type, 0x1000000000000), dyn_cast<Instruction>(valueNotOnStack)->getParent());
            end->addIncoming(if_end, if_end->getParent());
            

            int64_t osize = -1;
            Value *realEnd = nullptr;

            if (V->getType()->getPointerElementType()->isSized())
            {
                osize = DL->getTypeAllocSize(V->getType()->getPointerElementType());
                realEnd = irBuilder.CreateSub(end, ConstantInt::get(int64Type, osize));
            }

            for (auto I : *S)
            {
                InsertPoint = fetchBestInsertPoint(I);
                irBuilder.SetInsertPoint(InsertPoint);

                auto Ptr = irBuilder.CreatePtrToInt(I, int64Type);
                auto offset = irBuilder.CreateSub(Ptr, base);

                Value *Cond = nullptr;
                int64_t nsize = auxiliary.count(I) ? 0 : DL->getTypeAllocSize(I->getType()->getPointerElementType());
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
#endif
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

            uint64_t typeSize = auxiliary.count(I) ? 0 : DL->getTypeAllocSize(gep->getType()->getPointerElementType());

            Instruction* InsertPoint = fetchBestInsertPoint(gep);
            IRBuilder<> irBuilder(InsertPoint);

            Value *base = irBuilder.CreatePointerCast(gep->getPointerOperand(), voidPointerType);
            Value *result = irBuilder.CreatePointerCast(gep, voidPointerType);
            Value *size = irBuilder.getInt64(typeSize);

            Value *rsp = readRegister(irBuilder, "rsp");

            Value *value = irBuilder.CreatePtrToInt(gep->getPointerOperand(), int64Type);
            Value *valueNotOnStack = irBuilder.CreateICmpULT(value, rsp);

            irBuilder.SetInsertPoint(SplitBlockAndInsertIfThen(valueNotOnStack, InsertPoint, false));
            irBuilder.CreateCall(M->getFunction(__GEP_CHECK), {base, result, size});
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

            IRBuilder<> irBuilder(fetchBestInsertPoint(bc));

            Value *ptr = irBuilder.CreatePointerCast(bc, voidPointerType);
            Value *size = irBuilder.getInt64(DL->getTypeAllocSize(bc->getDestTy()->getPointerElementType()));

            irBuilder.CreateCall(M->getFunction(__BITCAST_CHECK), {ptr, size});
        }

        Instruction *fetchBestInsertPoint(Instruction *I)
        {
            User *U = nullptr;
            for (auto user : I->users())
            {
                if (isMustEscapeInstruction(user))
                {
                    if (U != nullptr)
                        return getInsertionPointAfterDef(I);
                    U = user;
                }
            }

            Instruction *P = dyn_cast_or_null<Instruction>(U);
            return P != nullptr ? P : getInsertionPointAfterDef(I);
        }

        Value *readRegister(IRBuilder<> &IRB, StringRef Name)
        {
            Function *readReg = Intrinsic::getDeclaration(M, Intrinsic::read_register, IRB.getIntPtrTy(*DL));

            LLVMContext &context = M->getContext();
            MDNode *MD = MDNode::get(context, {MDString::get(context, Name)});
            return IRB.CreateCall(readReg, {MetadataAsValue::get(context, MD)});
        }

        void addEscape(StoreInst *SI)
        {
            IRBuilder<> IRB(SI);

            // x86-64 only
            // heap address < stack address

            Value *rsp = readRegister(IRB, "rsp");

            Value *value = IRB.CreatePtrToInt(SI->getValueOperand(), int64Type);
            Value *valueNotOnStack = IRB.CreateICmpULT(value, rsp);
            Value *valueIsNotNull = IRB.CreateICmpNE(value, Constant::getNullValue(int64Type));

            Value *cond = IRB.CreateAnd(valueNotOnStack, valueIsNotNull);
#if CONFIG_ENABLE_STACK_ESCAPE_OPTIMIZATION
            Value *locNotOnStack = IRB.CreateICmpULT(IRB.CreatePtrToInt(SI->getPointerOperand(), int64Type), rsp);
            cond = IRB.CreateAnd(cond, locNotOnStack);
#endif
            IRB.SetInsertPoint(SplitBlockAndInsertIfThen(cond, SI, false));
            IRB.CreateCall(M->getFunction(__ESCAPE),
                           {IRB.CreatePointerCast(SI->getPointerOperand(), voidPointerType),
                            IRB.CreatePointerCast(SI->getValueOperand(), voidPointerType)});
        }

        bool allocateChecker(Instruction *Ptr, SmallVector<Instruction *, 16> &runtimeCheck, SmallVector<std::pair<Instruction *, Value *>, 16> &builtinCheck)
        {
            assert(Ptr->getType()->isPointerTy() && "allocateChecker(): Ptr should be pointer type");
#if CONFIG_ENABLE_OOB_OPTIMIZATION
#if CONFIG_ENABLE_TYPE_BASE_OPTIMIZATION
            if (GetElementPtrInst *Gep = dyn_cast<GetElementPtrInst>(Ptr))
            {
                if (isExtractMember(Gep))
                    return false;
                if (isZeroIndex(Gep))
                    return false;
                if (isVirtualTable(Gep))
                    return false;
            }
#endif  // CONFIG_ENABLE_TYPE_BASE_OPTIMIZATION
            if (escaped.count(Ptr) == 0)
                return false;

            SizeOffsetEvalType SizeOffset;
            Value *Or = getBoundsCheckCond(Ptr, SizeOffset);
            ConstantInt *C = dyn_cast_or_null<ConstantInt>(Or);

            if (C && !C->getZExtValue())
                return false;

            SmallSet<Value *, 16> Visit;
            if (!isHeapAddress(Ptr, Visit))
                return false;

#if CONFIG_ENABLE_BUILTIN_OPTIMIZATION
            // TODO: Built in optimization is not always better
            if (Or != nullptr)
                // We need save the `Cond` before instrument.
                // Because the analysis result will changed after instrument,
                // but our instrument will not change the semantic.
                builtinCheck.push_back(std::make_pair(Ptr, Or));
            else
                runtimeCheck.push_back(Ptr);
#else   // CONFIG_ENABLE_BUILTIN_OPTIMIZATION
            runtimeCheck.push_back(Ptr);
#endif  // CONFIG_ENABLE_BUILTIN_OPTIMIZATION

#else   // CONFIG_ENABLE_OOB_OPTIMIZATION
            runtimeCheck.push_back(Ptr);
#endif  // CONFIG_ENABLE_OOB_OPTIMIZATION
            return true;
        }

        bool isHeapAddress(Value *Ptr, SmallSet<Value *, 16> &Visit)
        {
            Value *S = findSource(Ptr);
            if (isa<GlobalValue>(S) ||
                isa<AllocaInst>(S))
                return false;

            if (Visit.count(S))
                return false;

            Visit.insert(S);

            if (auto PN = dyn_cast<PHINode>(S))
            {
                for (int i = 0; i < PN->getNumIncomingValues(); ++i)
                {
                    Value *V = PN->getIncomingValue(i);
                    if (isHeapAddress(V, Visit))
                        return true;
                }
                return false;
            }
            return true;
        }

        bool isZeroIndex(GetElementPtrInst* Gep) {
            for (auto &index : Gep->indices())
            {
                if (auto c = dyn_cast<ConstantInt>(index)) 
                {
                    if (c->getSExtValue() != 0) 
                        return false;
                } 
                else
                    return false;
            }
            return true;
        }

        bool isSizedStruct(Type *ty)
        {
            if (isUnionTy(ty))
                return false;

            if (StructType *sty = dyn_cast<StructType>(ty))
            {
                assert(!sty->isOpaque());
                if (!sty->isSized())
                    return false;
                if (ArrayType *aty = dyn_cast<ArrayType>(sty->elements().back()))
                    return aty->getNumElements() != 0;
                return true;
            }

            return false;
        }

        bool isExtractMember(GetElementPtrInst *Gep) 
        {
            Type *ty = Gep->getPointerOperand()->getType()->getPointerElementType();
            if (!isSizedStruct(ty))
                return false;

            for (auto &index : Gep->indices())
            {
                if (auto c = dyn_cast<ConstantInt>(index)) 
                {
                    if (c->getSExtValue() != 0)
                    {
                        return false;
                    }
                } 
                else 
                {
                    return false;
                }
                break;
            }
            return true;
        }

        bool isVirtualTable(GetElementPtrInst *Gep) 
        {
            if (auto pty = dyn_cast<PointerType>(Gep->getPointerOperand()->getType()->getPointerElementType())) {
                if (auto fty = dyn_cast<FunctionType>(pty->getPointerElementType())) {
                    if (fty->getNumParams() >= 1) {
                        if (auto fpty = dyn_cast<PointerType>(fty->getParamType(0))) {
                            if (fpty->getPointerElementType()->isStructTy()) {
                                dbgs() << "isVirtualTable: " << *Gep << "\n";
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

#if CONFIG_ENABLE_OOB_OPTIMIZATION
        Value *getBoundsCheckCond(Instruction *Ptr, SizeOffsetEvalType &SizeOffset)
        {
            assert(Ptr->getType()->isPointerTy() && "getBoundsCheckCond(): Ptr should be pointer type");

            uint32_t NeededSize = auxiliary.count(Ptr) ? 0 : DL->getTypeAllocSize(Ptr->getType()->getPointerElementType());
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
#endif

        bool searchPhi(Value *V, Value* &src, SmallSet<Value*, 16>& Visit) {
            if (Visit.count(V))
                return true;
            Visit.insert(V);
            if (PHINode *phi = dyn_cast<PHINode>(V)) {
                for (int i = 0; i < phi->getNumIncomingValues(); ++i) 
                {
                    if (!searchPhi(phi->getIncomingValue(i), src, Visit))
                        return false;
                }
                return true;
            }
            if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V))
            {
                return searchPhi(gep->getPointerOperand(), src, Visit);
            }
            if (BitCastInst *bc = dyn_cast<BitCastInst>(V))
            {
                return searchPhi(bc->getOperand(0), src, Visit);
            }
            if (GEPOperator *gepo = dyn_cast<GEPOperator>(V))
            {
                return searchPhi(gepo->getPointerOperand(), src, Visit);
            }
            if (src == nullptr) {
                src = V;
                return true;
            }
            return src == V;
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
            if (PHINode *phi = dyn_cast<PHINode>(V))
            {   
                Value *src = nullptr;
                SmallSet<Value*, 16> Visit;
                if (searchPhi(phi, src, Visit))
                    return source[phi] = src;
                else
                    return source[phi] = phi;
            }
            if (GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(V))
            {
                return source[gep] = findSource(gep->getPointerOperand());
            }
            if (BitCastInst *bc = dyn_cast<BitCastInst>(V))
            {
                return source[bc] = findSource(bc->getOperand(0));
            }
            if (GEPOperator *gepo = dyn_cast<GEPOperator>(V))
            {
                return findSource(gepo->getPointerOperand());
            }

            return V;
        }

        void collectInformation()
        {
#if CONFIG_ENABLE_OOB_CHECK
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                    if (CallInst *CI = dyn_cast<CallInst>(&I))
                    {
                        Function *fp = CI->getCalledFunction();
                        if (fp != nullptr)
                        {
                            StringRef name = fp->getName();
                            if (name.startswith("llvm.memcpy") ||
                                name.startswith("llvm.memmove"))
                            {

                                addAuxInstruction(CI, CI->getArgOperand(0), CI->getArgOperand(2));
                                addAuxInstruction(CI, CI->getArgOperand(1), CI->getArgOperand(2));
                            }
                            else if (name.startswith("llvm.memset"))
                            {
                                addAuxInstruction(CI, CI->getArgOperand(0), CI->getArgOperand(2));
                            }
                            else if (name == "snprintf")
                            {
                                addAuxInstruction(CI, CI->getArgOperand(0), CI->getArgOperand(1));
                            }
                            else if (name == "strncpy")
                            {
                                CI->setCalledFunction(M->getFunction(__STRNCPY_CHECK));
                            }
                            else if (name == "strcpy")
                            {
                                CI->setCalledFunction(M->getFunction(__STRCPY_CHECK));
                            }
                            else if (name == "strncat")
                            {
                                CI->setCalledFunction(M->getFunction(__STRNCAT_CHECK));
                            }
                            else if (name == "strcat")
                            {
                                CI->setCalledFunction(M->getFunction(__STRCAT_CHECK));
                            }
                        }
                    }
#endif
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                {
                    if (isa<GetElementPtrInst>(I) || isa<BitCastInst>(I))
                    {
                        if (auxiliary.count(&I))
                            escaped.insert(&I);
                        else
                        {
                            SmallSet<Instruction *, 16> Visit;
                            if (isEscaped(&I, Visit))
                            {
                                escaped.insert(&I);
                            }
                        }
                    }
                    else if (StoreInst *SI = dyn_cast<StoreInst>(&I))
                    {
                        if (SI->getValueOperand()->getType()->isPointerTy())
                        {
#if CONFIG_ENABLE_ESCAPE_TYPE_ONLY
                            if (!cast<PointerType>(SI->getValueOperand()->getType())->getElementType()->isStructTy())
                            {
                                escapeOptimized++;
                                continue;
                            }
#endif
                            if (isa<AllocaInst>(SI->getValueOperand()) || isa<ConstantPointerNull>(SI->getValueOperand()))
                            {
                                escapeOptimized++;
                                continue;
                            }

                            Instruction *ptr = dyn_cast_or_null<Instruction>(SI->getValueOperand());
                            if (ptr && source.count(ptr) && isa<AllocaInst>(source[ptr]))
                            {
                                escapeOptimized++;
                                continue;
                            }
#if CONFIG_ENABLE_STACK_ESCAPE_OPTIMIZATION

                            Instruction *loc = dyn_cast_or_null<Instruction>(SI->getPointerOperand());
                            if (loc && source.count(loc) &&
                                (isa<AllocaInst>(source[loc]) || isa<AllocaInst>(SI->getPointerOperand())))
                            {
                                escapeOptimized++;
                                continue;
                            }
#endif
                            storeInsts.push_back(SI);
                        }
                    }
                }
            for (BasicBlock &BB : *F)
                for (Instruction &I : BB)
                    findSource(&I);
        }

        void addAuxInstruction(CallInst *CI, Value *Ptr, Value *Len)
        {
            IRBuilder<> irBuilder(CI);
            auto BC = irBuilder.CreatePointerCast(Ptr, voidPointerType);
            auto GEP = irBuilder.CreateGEP(BC, irBuilder.CreatePointerCast(Len, int64Type));

            if (auto I = dyn_cast<Instruction>(BC))
                auxiliary.insert(I);
            if (auto I = dyn_cast<Instruction>(GEP))
                auxiliary.insert(I);
        }

        bool isMustEscapeInstruction(User *I)
        {
#if CONFIG_ENABLE_READ_CHECK
            if (isa<LoadInst>(I))
                return true;
#endif
            if (isa<StoreInst>(I) || isa<ReturnInst>(I))
                return true;

            if (auto CB = dyn_cast<CallBase>(I))
            {
                Function *F = CB->getCalledFunction();
                if (F != nullptr) {
                    static SmallVector<StringRef, 16> whitelist = {
                        "llvm.prefetch.",
                        "llvm.lifetime.start",
                        "llvm.lifetime.end",
                    };

                    for (auto name : whitelist) {
                        if (F->getName().startswith(name))
                            return false;
                    }
                }
                return true;
            }

            return false;
        }

        bool isEscaped(Instruction *I, SmallSet<Instruction *, 16> &Visit)
        {
            if (Visit.count(I))
                return false;

            Visit.insert(I);
            for (auto user : I->users())
                if (isMustEscapeInstruction(user))
                    return true;
            for (auto user : I->users())
                if (auto PN = dyn_cast<PHINode>(user))
                    if (isEscaped(PN, Visit))
                        return true;
            return false;
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
                                gepIgnoreOptimized++;
                            }
                        }
                    }
                    else if (BitCastInst *bc = dyn_cast<BitCastInst>(&I))
                    {
                        if (bc->getSrcTy()->isPointerTy() && bc->getDestTy()->isPointerTy())
                        {
                            Type *srcTy = bc->getSrcTy()->getPointerElementType();
                            Type *dstTy = bc->getDestTy()->getPointerElementType();

                            if (!srcTy->isSized() ||
                                !dstTy->isSized())
                                continue;

                            if (isUnionTy(dstTy))
                                continue;

                            if (!isUnionTy(srcTy))
                            {
                                unsigned int srcSize = DL->getTypeAllocSize(srcTy);
                                unsigned int dstSize = DL->getTypeAllocSize(dstTy);

                                if (srcSize >= dstSize)
                                    continue;
                            }

                            if (!allocateChecker(bc, runtimeCheck, builtinCheck))
                                bitcastIgnoreOptimized++;
                        }
                    }
                }
            }
        }

        bool isUnionTy(Type *ty)
        {
            if (auto sty = dyn_cast<StructType>(ty))
                return sty->hasName() && sty->getName().startswith("union.");
            return false;
        }
#if CONFIG_ENABLE_OOB_OPTIMIZATION
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
                if (isa<BitCastOperator>(key))
                {
                    dbgs() << "[WARNING] Unhandled Value: " << *key << "\n";
                    continue;
                }

                Instruction *InsertPoint = dependenceOptimize(key, value);
                int64_t weight = 0, dom = 0;
                for (auto ins : *value)
                {
                    if (ins->getParent() == InsertPoint->getParent())
                    {
                        dom += 1;
                    }
                    else
                    {
                        weight += 1;
                        if (Loop *Lop = LI->getLoopFor(ins->getParent()))
                            weight += 5;
                    }
                }
#if CONFIG_ENABLE_MERGE_OPTIMIZATION
                if (dom > 1 || weight > 4)
                    partialCheck.push_back(std::make_pair(key, value));
                else
                    newRuntimeCheck.append(*value);
#else
                newRuntimeCheck.append(*value);
#endif
            }

            runtimeCheck.swap(newRuntimeCheck);
        }

        Instruction *dependenceOptimize(Value *key, SmallVector<Instruction *, 16> *value)
        {
            Instruction *InsertPoint = nullptr;

            if (isa<Instruction>(key))
                InsertPoint = getInsertionPointAfterDef(dyn_cast<Instruction>(key));
            else if (isa<Argument>(key))
                InsertPoint = &(F->getEntryBlock().front());

#if CONFIG_ENABLE_REMOVE_REDUNDANT_OPTIMIZATION
            IRBuilder<TargetFolder> irBuilder(InsertPoint->getParent(), BasicBlock::iterator(InsertPoint->getIterator()), TargetFolder(*DL));

            SmallVector<Instruction *, 16> newvalue;
            for (size_t i = 0; i < value->size(); ++i)
            {
                bool optimized = false;
                if (auto I = dyn_cast<GetElementPtrInst>((*value)[i])) {
                    for (size_t j = 0; j < value->size(); ++j)
                    {
                        if (i != j)
                        {
                            if (auto J = dyn_cast<GetElementPtrInst>((*value)[j])) {
                                if (DT->dominates(J, I) || PDT->dominates(I, J))
                                {
                                    if (I->getPointerOperand() == J->getPointerOperand()) 
                                    {
                                        if (isSizedStruct(I->getType()->getPointerElementType())) {
                                            Value *Iindex = GetSingleIndex(I);
                                            Value *Jindex = GetSingleIndex(J);
                                            irBuilder.SetInsertPoint(J);
                                            auto Offset = irBuilder.CreateSub(Jindex, Iindex);
                                            auto OffsetRange = SE->getSignedRange(SE->getSCEV(Offset));
                                            if (!OffsetRange.getSignedMin().isNegative())
                                            {
                                                optimized = true;
                                                break;
                                            }
                                        }
                                        if (I->getNumIndices() == 1 && J->getNumIndices() == 1)
                                        {
                                            Value *Iindex = GetSingleIndex(I);
                                            Value *Jindex = GetSingleIndex(J);
                                            irBuilder.SetInsertPoint(J);
                                            auto Offset = irBuilder.CreateSub(Jindex, Iindex);
                                            auto OffsetRange = SE->getSignedRange(SE->getSCEV(Offset));
                                            if (!OffsetRange.getSignedMin().isNegative())
                                            {
                                                optimized = true;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (optimized)
                        gepDepOptimized++;
                    else {
                        newvalue.push_back(I);
                    }
                }
            }
            value->swap(newvalue);
#endif
            return InsertPoint;
        }

        Value* GetSingleIndex(GetElementPtrInst *gep)
        {
            for (auto &Ind : gep->indices()) {
                auto V = Ind.get();
                while (true) {
                    if (auto I = dyn_cast<Instruction>(V)) {
                        if (I->getNumOperands() == 1)
                            V = I->getOperand(0);
                        else break;
                    } else break;
                }
                return V;
            }
            return nullptr;
        }
#endif
        void escapeOptimize()
        {
            SmallVector<StoreInst *, 16> newStoreInsts;

            for (auto *SI : storeInsts)
            {
                bool flag = false;
                if (auto I = dyn_cast<Instruction>(SI->getValueOperand()))
                    if (source.count(I))
                        if (LoadInst *LI = dyn_cast<LoadInst>(source[I]))
                            if (LI->getPointerOperand() == SI->getPointerOperand())
                                flag = true;
                if (flag)
                    escapeOptimized++;
                else
                    newStoreInsts.push_back(SI);
            }
            storeInsts.swap(newStoreInsts);
        }

        void applyInstrument()
        {
#if CONFIG_ENABLE_OOB_CHECK
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
#if CONFIG_ENABLE_OOB_OPTIMIZATION
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
#endif
#endif
#if CONFIG_ENABLE_UAF_CHECK
            for (auto SI : storeInsts)
            {
                escapeTrace++;
                addEscape(SI);
            }
#endif
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

#if CONFIG_ENABLE_OOB_OPTIMIZATION == 0
static RegisterStandardPasses
    RegisterNoOptPass(PassManagerBuilder::EP_EnabledOnOptLevel0,
                   registerPass);
#endif