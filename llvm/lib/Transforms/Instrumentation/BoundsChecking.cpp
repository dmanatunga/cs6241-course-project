//===- BoundsChecking.cpp - Instrumentation for run-time bounds checking --===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements a pass that instruments the code to perform run-time
// bounds checking on loads, stores, and other memory intrinsics.
//
//===----------------------------------------------------------------------===//

#define DEBUG_TYPE "bounds-checking"
#include "llvm/IRBuilder.h"
#include "llvm/Intrinsics.h"
#include "llvm/Pass.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/TargetFolder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/DataLayout.h"
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/Transforms/Instrumentation.h"
using namespace llvm;

static cl::opt<bool> SingleTrapBB("bounds-checking-single-trap",
                                  cl::desc("Use one trap block per function"));

STATISTIC(ChecksAdded, "Bounds checks added");
STATISTIC(ChecksSkipped, "Bounds checks skipped");
STATISTIC(ChecksUnable, "Bounds checks unable to add");

typedef IRBuilder<true, TargetFolder> BuilderTy;

namespace {
  struct BoundsChecking : public FunctionPass {
    static char ID;

    BoundsChecking(unsigned _Penalty = 5) : FunctionPass(ID), Penalty(_Penalty){
      initializeBoundsCheckingPass(*PassRegistry::getPassRegistry());
    }

    virtual bool runOnFunction(Function &F);

    virtual void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<DataLayout>();
      AU.addRequired<TargetLibraryInfo>();
    }

  private:
    const DataLayout *TD;
    const TargetLibraryInfo *TLI;
    ObjectSizeOffsetEvaluator *ObjSizeEval;
    BuilderTy *Builder;
    Instruction *Inst;
    BasicBlock *TrapBB;
    unsigned Penalty;

    BasicBlock *getTrapBB();
    void emitBranchToTrap(Value *Cmp = 0);
    bool computeAllocSize(Value *Ptr, APInt &Offset, Value* &OffsetValue,
                          APInt &Size, Value* &SizeValue);
    bool instrument(Value *Ptr, Value *Val);
    bool LocalAnalysis(BasicBlock *blk);
 };
}

char BoundsChecking::ID = 0;
INITIALIZE_PASS(BoundsChecking, "bounds-checking", "Run-time bounds checking",
                false, false)


/// getTrapBB - create a basic block that traps. All overflowing conditions
/// branch to this block. There's only one trap block per function.
BasicBlock *BoundsChecking::getTrapBB() {
  if (TrapBB)
    return TrapBB;

  Function *Fn = Inst->getParent()->getParent();
  BasicBlock::iterator PrevInsertPoint = Builder->GetInsertPoint();
  TrapBB = BasicBlock::Create(Fn->getContext(), "trap", Fn);
  Builder->SetInsertPoint(TrapBB);

  llvm::Value *F = Intrinsic::getDeclaration(Fn->getParent(), Intrinsic::trap);
  CallInst *TrapCall = Builder->CreateCall(F);
  TrapCall->setDoesNotReturn();
  TrapCall->setDoesNotThrow();
  TrapCall->setDebugLoc(Inst->getDebugLoc());
  Builder->CreateUnreachable();

  Builder->SetInsertPoint(PrevInsertPoint);
  return TrapBB;
}


/// emitBranchToTrap - emit a branch instruction to a trap block.
/// If Cmp is non-null, perform a jump only if its value evaluates to true.
void BoundsChecking::emitBranchToTrap(Value *Cmp) {
  // check if the comparison is always false
  ConstantInt *C = dyn_cast_or_null<ConstantInt>(Cmp);
  if (C) {
    ++ChecksSkipped;
    if (!C->getZExtValue())
      return;
    else
      Cmp = 0; // unconditional branch
  }

  Instruction *Inst = Builder->GetInsertPoint();
  BasicBlock *OldBB = Inst->getParent();
  BasicBlock *Cont = OldBB->splitBasicBlock(Inst);
  OldBB->getTerminator()->eraseFromParent();

  if (Cmp)
    BranchInst::Create(getTrapBB(), Cont, Cmp, OldBB);
  else
    BranchInst::Create(getTrapBB(), OldBB);
}


/// instrument - adds run-time bounds checks to memory accessing instructions.
/// Ptr is the pointer that will be read/written, and InstVal is either the
/// result from the load or the value being stored. It is used to determine the
/// size of memory block that is touched.
/// Returns true if any change was made to the IR, false otherwise.
bool BoundsChecking::instrument(Value *Ptr, Value *InstVal) {
  uint64_t NeededSize = TD->getTypeStoreSize(InstVal->getType());
  DEBUG(dbgs() << "Instrument " << *Ptr << " for " << Twine(NeededSize)
              << " bytes\n");

  SizeOffsetEvalType SizeOffset = ObjSizeEval->compute(Ptr);

  if (!ObjSizeEval->bothKnown(SizeOffset)) {
    ++ChecksUnable;
    return false;
  }

  Value *Size   = SizeOffset.first;
  Value *Offset = SizeOffset.second;
  ConstantInt *SizeCI = dyn_cast<ConstantInt>(Size);
  
  Type *IntTy = TD->getIntPtrType(Ptr->getType());
  Value *NeededSizeVal = ConstantInt::get(IntTy, NeededSize);

  /**
  errs() << "===========================\n";
  errs() << "Array: " << Ptr->getName() << "\n";
  errs() << "Index: " << *Offset <<  "\n";
  errs() << " Size : " << *Size << "\n";
  */
  // three checks are required to ensure safety:
  // . Offset >= 0  (since the offset is given from the base ptr)
  // . Size >= Offset  (unsigned)
  // . Size - Offset >= NeededSize  (unsigned)
  //
  // optimization: if Size >= 0 (signed), skip 1st check
  // FIXME: add NSW/NUW here?  -- we dont care if the subtraction overflows
  Value *ObjSize = Builder->CreateSub(Size, Offset);
  Value *Cmp2 = Builder->CreateICmpULT(Size, Offset);
  Value *Cmp3 = Builder->CreateICmpULT(ObjSize, NeededSizeVal);
  Value *Or = Builder->CreateOr(Cmp2, Cmp3);
  if (!SizeCI || SizeCI->getValue().slt(0)) {
    Value *Cmp1 = Builder->CreateICmpSLT(Offset, ConstantInt::get(IntTy, 0));
    Or = Builder->CreateOr(Cmp1, Or);
  }
  emitBranchToTrap(Or);

  ++ChecksAdded;
  return true;
}


bool BoundsChecking::LocalAnalysis(BasicBlock *blk) {
  // check HANDLE_MEMORY_INST in include/llvm/Instruction.def for memory
  // touching instructions
  std::vector<Instruction*> WorkList;
  // Iterate over instructions in the basic block and build the constraint graph
  for (BasicBlock::iterator i = blk->begin(), e = blk->end(); i != e; ++i) {
    Instruction *I = &*i;
    errs() << "===========================================\n"; 
    if (isa<CallInst>(I)) {
      // Function call instruction, we must kill all variables
      errs() << "Function Call: " << *I << "\n"; 
    } else if (I->isCast()) {
      // If cast, basically set output equal to input
      errs() << "Cast Operator: " << *I << "\n";
      Value *op1 = I->getOperand(0);
      errs() << "Casting: " << *op1 << "\n";
    } else if (isa<LoadInst>(I)) {
      // If a load, associate register with memory identifier
      errs() << "Load Operator: " << *I << "\n";
      Value *op1 = I->getOperand(0);
      errs() << "Loading From: " << *op1 << "\n";
      errs() << "Loading To: " << *I << "\n";
    } else if (isa<StoreInst>(I)) {
      // If a store instruction, we need to set that memory location to value in graph
      errs() << "Store Operator: " << *I << "\n";
      Value *op1 = I->getOperand(0);
      Value *op2 = I->getOperand(1);

      ConstantInt *ConstVal = dyn_cast<ConstantInt>(op1);
      if (ConstVal != NULL) {
        errs() << "Storing Value: " << ConstVal->getSExtValue() << "\n";
      } else {
        errs() << "Storing From: " << *op1 << "\n";
      }
     
      AllocaInst *allocInst = dyn_cast<AllocaInst>(op2);
      GlobalValue *global = dyn_cast<GlobalValue>(op2);
      if (allocInst != NULL || global != NULL) {
        errs() << "Storing To: " << *op2 << "\n";
      } else {
        errs() << "Storing To Pointer Location: " << *op2 << "\n";
      }
    } else if (I->isBinaryOp()) {
      unsigned opcode = I->getOpcode();
      if (opcode == Instruction::Add) {
          int64_t val = 0;
          Value *var = NULL;
          errs() << "Add Operator: " << *I << "\n";
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() + ConstVal2->getSExtValue();
          } else if (ConstVal1 != NULL) {
            val = ConstVal1->getSExtValue();
            var = op2;
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
          }
      } else if (opcode == Instruction::Sub) {
          int64_t val = 0;
          Value *var = NULL;
          errs() << "Subtraction Operator: " << *I << "\n";
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() - ConstVal2->getSExtValue();
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = -ConstVal2->getSExtValue();
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
          }
      } else if (opcode == Instruction::Mul) {
          int64_t val = 0;
          Value *var = NULL;
          errs() << "Multiply Operator: " << *I << "\n";
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue()*ConstVal2->getSExtValue();
          } else if (ConstVal1 != NULL) {
            val = ConstVal1->getSExtValue();
            var = op2;
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
          }
      } else if (opcode == Instruction::UDiv) {
          int64_t val = 0;
          Value *var = NULL;
          errs() << "Unsigned Division Operator: " << *I << "\n";
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = (int64_t)(ConstVal1->getZExtValue()/ConstVal2->getZExtValue());
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = (int64_t)ConstVal2->getZExtValue();
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
          }
      } else if (opcode == Instruction::SDiv) {
          int64_t val = 0;
          Value *var = NULL;
          errs() << "Signed Division Operator: " << *I << "\n";
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() + ConstVal2->getSExtValue();
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            
          } else {
            // Both operands are variables, so we must just create blank node
          }
          errs() << *var << "\n";
          errs() << "Constant: " << val << "\n";
      } else {
        errs() << "Handle opcode: " << I->getOpcodeName() << "?\n";
      }
    } else {
      errs() << "Handle opcode: " << I->getOpcodeName() << "?\n";
    }



    if (I->mayWriteToMemory()) {
      // Instruction writes to memory, so kill other definitions
    }

    // Add to bounds checking creator list    
    if (isa<LoadInst>(I) || isa<StoreInst>(I) || isa<AtomicCmpXchgInst>(I) ||
        isa<AtomicRMWInst>(I)) {
      //  errs() << *i << "\n";
        WorkList.push_back(I);
    }
  }
  
  // Iterate over instructions in the basic block and build the constraint graph
  for (BasicBlock::iterator i = blk->begin(), e = blk->end(); i != e; ++i) {
    Instruction *I = &*i;
    if (isa<LoadInst>(I) || isa<StoreInst>(I) || isa<AtomicCmpXchgInst>(I) ||
        isa<AtomicRMWInst>(I)) {
      //  errs() << *i << "\n";
        WorkList.push_back(I);
    }
  }
  bool MadeChange = false;
  for (std::vector<Instruction*>::iterator i = WorkList.begin(),
       e = WorkList.end(); i != e; ++i) {
    Inst = *i;

    Builder->SetInsertPoint(Inst);
    if (LoadInst *LI = dyn_cast<LoadInst>(Inst)) {
      MadeChange |= instrument(LI->getPointerOperand(), LI);
    } else if (StoreInst *SI = dyn_cast<StoreInst>(Inst)) {
      MadeChange |= instrument(SI->getPointerOperand(), SI->getValueOperand());
    } else if (AtomicCmpXchgInst *AI = dyn_cast<AtomicCmpXchgInst>(Inst)) {
      MadeChange |= instrument(AI->getPointerOperand(),AI->getCompareOperand());
    } else if (AtomicRMWInst *AI = dyn_cast<AtomicRMWInst>(Inst)) {
      MadeChange |= instrument(AI->getPointerOperand(), AI->getValOperand());
    } else {
      llvm_unreachable("unknown Instruction type");
    }
  }
  return MadeChange;
}


bool BoundsChecking::runOnFunction(Function &F) {
  TD = &getAnalysis<DataLayout>();
  TLI = &getAnalysis<TargetLibraryInfo>();

  TrapBB = 0;
  BuilderTy TheBuilder(F.getContext(), TargetFolder(TD));
  Builder = &TheBuilder;
  ObjectSizeOffsetEvaluator TheObjSizeEval(TD, TLI, F.getContext());
  ObjSizeEval = &TheObjSizeEval;

  std::vector<BasicBlock*> BBWorkList;
  // Iterate over the Basic Blocks and perform local analysis
  for (Function::iterator i = F.begin(), e = F.end(); i != e; ++i) {
    errs() << "Basic block (name=" << i->getName() << ") has " << i->size() << "instructions.\n";
    BasicBlock *blk = &*i;
    BBWorkList.push_back(blk);
  }

  bool MadeChange = false;
  for (std::vector<BasicBlock*>::iterator i = BBWorkList.begin(),
       e = BBWorkList.end(); i != e; ++i) {
    MadeChange |= LocalAnalysis(*i);
  }
  return MadeChange;
}

FunctionPass *llvm::createBoundsCheckingPass(unsigned Penalty) {
  return new BoundsChecking(Penalty);
}
