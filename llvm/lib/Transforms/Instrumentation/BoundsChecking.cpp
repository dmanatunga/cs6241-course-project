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
#include "BoundsCheck.hpp"
#include "ConstraintGraph.hpp"

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

    // Local Analysis Functions
    bool LocalAnalysis(BasicBlock *blk);
    void IdentifyBoundsChecks(BasicBlock *blk, std::vector<BoundsCheck*> *boundsChecks);
    void EliminateBoundsChecks(std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph *cg);
    void eliminateForwards(BoundsCheck* check1, BoundsCheck* check2, ConstraintGraph *cg);
    void eliminateBackwards(BoundsCheck* check1, BoundsCheck* check2, ConstraintGraph *cg);
    bool InsertChecks(std::vector<BoundsCheck*> *boundsCheck);
    BoundsCheck* createBoundsCheck(Instruction *Inst, Value *Ptr, Value *Val);
    void buildConstraintGraph(BasicBlock *blk, ConstraintGraph *cg);
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



void BoundsChecking::buildConstraintGraph(BasicBlock *blk, ConstraintGraph *cg) {

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
    } else if (isa<GetElementPtrInst>(I)) {
      errs() << "Get Element Pointer: " << *I << "\n";
      Value *index = I->getOperand(I->getNumOperands()-1);
      errs() << "Index: " << *index << "\n";
    } else if (isa<LoadInst>(I)) {
      // If a load, associate register with memory identifier
      errs() << "Load Operator: " << *I << "\n";
      LoadInst *LI = dyn_cast<LoadInst>(I);
      Value *op1 = LI->getPointerOperand();
      errs() << "Loading From: " << *op1 << "\n";
      errs() << "Loading To: " << *I << "\n";
    } else if (isa<StoreInst>(I)) {
      // If a store instruction, we need to set that memory location to value in graph
      errs() << "Store Operator: " << *I << "\n";
      StoreInst *SI = dyn_cast<StoreInst>(I);
      Value *to = SI->getPointerOperand();
      Value *from = SI->getValueOperand();
      ConstantInt *ConstVal = dyn_cast<ConstantInt>(from);
      if (ConstVal != NULL) {
        errs() << "Storing Value: " << ConstVal->getSExtValue() << "\n";
      } else {
        errs() << "Storing From: " << *from << "\n";
      }
    
       
      //AllocaInst *allocInst = dyn_cast<AllocaInst>(to);
      //GlobalValue *global = dyn_cast<GlobalValue>(to);
      //bool isPointer = (allocInst == NULL && global == NULL);
      
      Type* T = to->getType();
      bool isPointer = T->isPointerTy() && T->getContainedType(0)->isPointerTy();
      if (isPointer) {
        errs() << "Storing To Pointer Location: " << *to << "\n";
      } else {
        errs() << "Storing To: " << *to << "\n";
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
      errs() << *I << "\n";
    }
  }
}

void BoundsChecking::IdentifyBoundsChecks(BasicBlock *blk, std::vector<BoundsCheck*> *boundsChecks) {
  for (BasicBlock::iterator i = blk->begin(), e = blk->end(); i != e; ++i) {
    Instruction *Inst = &*i;
    BoundsCheck *check = NULL;
    if (LoadInst *LI = dyn_cast<LoadInst>(Inst)) {
      check = createBoundsCheck(Inst, LI->getPointerOperand(), LI);
    } else if (StoreInst *SI = dyn_cast<StoreInst>(Inst)) {
      check = createBoundsCheck(Inst, SI->getPointerOperand(), SI->getValueOperand());
    } else if (AtomicCmpXchgInst *AI = dyn_cast<AtomicCmpXchgInst>(Inst)) {
      check = createBoundsCheck(Inst, AI->getPointerOperand(),AI->getCompareOperand());
    } else if (AtomicRMWInst *AI = dyn_cast<AtomicRMWInst>(Inst)) {
      check = createBoundsCheck(Inst, AI->getPointerOperand(), AI->getValOperand());
    } 

    if (check != NULL) {
      boundsChecks->push_back(check);
    }
  }
}


/// Ptr is the pointer that will be read/written, and InstVal is either the
/// result from the load or the value being stored. It is used to determine the
/// size of memory block that is touched.
/// Returns true if any change was made to the IR, false otherwise.
BoundsCheck* BoundsChecking::createBoundsCheck(Instruction *Inst, Value *Ptr, Value *InstVal) {
  uint64_t NeededSize = TD->getTypeStoreSize(InstVal->getType());
  SizeOffsetEvalType SizeOffset = ObjSizeEval->compute(Ptr);
  
  BoundsCheck *check = NULL;
  if (!ObjSizeEval->bothKnown(SizeOffset)) {
    return check;
  }

  Value *Size   = SizeOffset.first;
  Value *Offset = SizeOffset.second;
  ConstantInt *SizeCI = dyn_cast<ConstantInt>(Size);
  ConstantInt *OffsetCI = dyn_cast<ConstantInt>(Offset);  

  // three checks are required to ensure safety:
  // . Offset >= 0  (since the offset is given from the base ptr)
  // . Size >= Offset  (unsigned)
  // . Size - Offset >= NeededSize  (unsigned)
  //
  // optimization: if Size >= 0 (signed), skip 1st check
  // FIXME: add NSW/NUW here?  -- we dont care if the subtraction overflows
  
      //errs() << "Instruction: " << *Inst << "\n";
      //errs() << "Offset: " << *Offset << "\n";
      //errs() << "Size: " << *Size << "\n";
      //errs() << "Needed Size: " << NeededSize << "\n";
  if (SizeCI && !SizeCI->getValue().slt(0)) {
    if (OffsetCI != NULL) {
      uint64_t size = SizeCI->getZExtValue();
      uint64_t offset = OffsetCI->getZExtValue();
      
      //errs() << "Constant Size: " << size << "\n";
      //errs() << "Constant Offset: " << offset << "\n";

      if ((size >= offset) && ((size - offset) >= NeededSize)) {
        return check;
      }
    }
  }
  // Add check to work list
  check = new BoundsCheck(Inst, Ptr, Offset, Size);   
  return check;
}


void BoundsChecking::eliminateForwards(BoundsCheck* check1, BoundsCheck* check2,
                                       ConstraintGraph *cg) { 
  Value *ub1 = check1->getUpperBound();
  Value *ub2 = check2->getUpperBound();
  Value *index1 = check2->getIndex();
  Value *index2 = check2->getIndex();

  ConstraintGraph::CompareEnum cmp1 = cg->compare(index1, index2);
  if (check1->hasLowerBoundsCheck()) {
    // If check1 lower bounds check is valid
    switch (cmp1) {
      case ConstraintGraph::LESS_THAN:
      case ConstraintGraph::EQUALS:
        // If index1 < index2, don't need 0 <= index2
        check2->deleteLowerBoundsCheck();
        break;
      default:
        // Unknown value for indiciesi
        break;
    }
  }

  if (check1->hasUpperBoundsCheck()) {
    // If check 1 is upper bounds check valid
    ConstraintGraph::CompareEnum cmp2 = cg->compare(ub1, ub2);
    switch (cmp1) {
      case ConstraintGraph::GREATER_THAN:
      case ConstraintGraph::EQUALS:
        if (cmp2 == ConstraintGraph::LESS_THAN || cmp2 == ConstraintGraph::EQUALS) {
          // If index1 >= index2, and ub1 <= ub2, don't need index2 <= ub2
          check2->deleteUpperBoundsCheck();
        }
        break;
      default:
        // Unknown indicies, or unknown sizes
        break;
    }
  }
}

void BoundsChecking::eliminateBackwards(BoundsCheck* check1, BoundsCheck* check2,
                                        ConstraintGraph *cg) { 
  Value *ub1 = check1->getUpperBound();
  Value *ub2 = check2->getUpperBound();
  Value *index1 = check2->getIndex();
  Value *index2 = check2->getIndex();
  
  ConstraintGraph::CompareEnum cmp1 = cg->compare(index2, index1);
  if (check2->hasLowerBoundsCheck()) {
    // If check2 lower bounds check is valid
    switch (cmp1) {
      case ConstraintGraph::LESS_THAN:
      case ConstraintGraph::EQUALS:
        // If index2 < index1, don't need 0 <= index1
        check1->deleteLowerBoundsCheck();
        check2->insertBefore(check1->getInsertPoint());
        break;
      default:
        // Unknown value for indicies
        break;
    }
  }

  if (check2->hasUpperBoundsCheck()) {
    // If check 2 is upper bounds check valid
    ConstraintGraph::CompareEnum cmp2 = cg->compare(ub2, ub1);
    switch (cmp1) {
      case ConstraintGraph::EQUALS:
      case ConstraintGraph::GREATER_THAN:
        if (cmp2 == ConstraintGraph::LESS_THAN || cmp2 == ConstraintGraph::EQUALS) {
          // If index2 >= index1, and ub2 <= ub1, don't need index1 <= ub2
          check1->deleteUpperBoundsCheck();
          check2->insertBefore(check1->getInsertPoint());
        }
        break;
      default:
        // Unknown indicies, or unknown sizes
        break;
    }
  }
}

void BoundsChecking::EliminateBoundsChecks(std::vector<BoundsCheck*> *boundsChecks, 
                                           ConstraintGraph *cg) {
  // Forward analysis to identify if higher occuring bounds check
  // is stricter than lower occuring bounds check
  for (unsigned int i = 0; i < boundsChecks->size(); i++) {
    BoundsCheck *check = boundsChecks->at(i);

    if (check->stillExists()) {
      for (unsigned int j = i + 1; i < boundsChecks->size(); j++) {
        BoundsCheck* tmp = boundsChecks->at(j);
        if (tmp->stillExists()) {
          eliminateForwards(check, tmp, cg);
        }
      }
    }
  }

  // Backwards analysis to identify if lower occuring bounds check
  // is stricter than higher occuring bounds check
  for (int i = boundsChecks->size()-1; i >= 0; i--) {
    BoundsCheck *check = boundsChecks->at(i);

    if (check->stillExists()) {
      for (int j = i - 1; j >= 0;  j--) {
        BoundsCheck* tmp = boundsChecks->at(j);
        if (tmp->stillExists()) {
          eliminateBackwards(check, tmp, cg);
        }
      }
    }
  }
}

bool BoundsChecking::InsertChecks(std::vector<BoundsCheck*> *boundsChecks) {
  bool MadeChange = false;
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(),
            e = boundsChecks->end(); i != e; i++) {
    
    
  }  
  return MadeChange;
}

bool BoundsChecking::LocalAnalysis(BasicBlock *blk) {
  std::vector<BoundsCheck*> boundsChecks;
  bool MadeChange = false;
  IdentifyBoundsChecks(blk, &boundsChecks);

  errs() << "===================================\n";
  errs() << "Identified Bounds Checks\n";
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks.begin(),
        e = boundsChecks.end(); i != e; i++) {
    BoundsCheck* check = *i;
    check->print();
  }
  errs() << "===================================\n";

  errs() << "===================================\n";
  errs() << "Building Constraints Graph\n";
  ConstraintGraph cg;
  buildConstraintGraph(blk, &cg);
  errs() << "===================================\n";
  
  //EliminateBoundsChecks(&boundsChecks, &cg);
  MadeChange = InsertChecks(&boundsChecks);
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

  bool MadeChange = true;
  // Iterate over the Basic Blocks and perform local analysis
  for (Function::iterator i = F.begin(), e = F.end(); i != e; ++i) {
    errs() << "Basic block (name=" << i->getName() << ") has " << i->size() << "instructions.\n";
    BasicBlock *blk = &*i;
    MadeChange |= LocalAnalysis(blk);
  }

  return MadeChange;
}

FunctionPass *llvm::createBoundsCheckingPass(unsigned Penalty) {
  return new BoundsChecking(Penalty);
}

