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
#include "llvm/Support/CFG.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/TargetFolder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/DataLayout.h"
#include "llvm/Target/TargetLibraryInfo.h"
#include "llvm/Transforms/Instrumentation.h"
#include <queue>
#include <set>
using namespace llvm;
#define DEBUG_LOCAL 0
#define DEBUG_GLOBAL 1
#define DEBUG_INSERT 1
#include "BoundsCheck.hpp"
#include "ConstraintGraph.hpp"
#include "GlobalAnalysis.hpp"

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
    int numChecksAdded;
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

    // Bounds Checks identifying Functions
    void IdentifyBoundsChecks(BasicBlock *blk, std::vector<BoundsCheck*> *boundsChecks);
    BoundsCheck* createBoundsCheck(Instruction *Inst, Value *Ptr, Value *Val);
    // Local Analysis Functions
    void LocalAnalysis(BasicBlock *blk, std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph *cg);
    void getCheckVariables(std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph *cg);
    void promoteCheck(BoundsCheck* check);
    void promoteLocalChecks(std::vector<BoundsCheck*> *boundsChecks);
    void EliminateBoundsChecks(std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph *cg);
    void eliminateForwards(BoundsCheck* check1, BoundsCheck* check2, ConstraintGraph *cg);
    void eliminateBackwards(BoundsCheck* check1, BoundsCheck* check2, ConstraintGraph *cg);
    void buildConstraintGraph(BasicBlock *blk, ConstraintGraph *cg);
    // Global Analysis Functions
    void GlobalAnalysis(std::vector<BasicBlock*> *worklist, std::map<BasicBlock*,std::vector<BoundsCheck*>*> *blkChecks, std::map<BasicBlock*,ConstraintGraph*> *blkCG);

    // Loop Analysis Functions

    // Bounds Checks Insertion Functions
    bool InsertCheck(BoundsCheck* check);
    bool InsertChecks(std::vector<BoundsCheck*> *boundsCheck);
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
#if DEBUG_LOCAL
  errs() << "Emitting Branch Instruction\n";
#endif
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
  #if DEBUG_LOCAL
    errs() << "===========================================\n";
    if (I->hasName()) {
      errs() << "Instruction Name: " << I->getName() << "\n";
    } else {
      errs() << "Instruction Name: No Name\n";
    }
  #endif
    if (isa<AllocaInst>(I)) {      
    #if DEBUG_LOCAL
      errs() << "Allocate Instruction: " << *I << "\n";
    #endif
      cg->addMemoryNode(I);
    } else if (isa<CallInst>(I)) {
    #if DEBUG_LOCAL
      errs() << "Function Call: " << *I << "\n";
    #endif
      // Function call instruction, we must kill all variables
      cg->killMemoryLocations();
      //errs() << "Function Call: " << *I << "\n"; 
    } else if (I->isCast()) {
    #if DEBUG_LOCAL
      errs() << "Cast Operator: " << *I << "\n";
    #endif
      // If cast, basically set output equal to input
      Value *op2 = I->getOperand(0);
      cg->addCastEdge(op2, I);
      //errs() << "Cast Operator: " << *I << "\n";
      //errs() << "Casting: " << *op1 << "\n";
    } else if (isa<GetElementPtrInst>(I)) {
    #if DEBUG_LOCAL
      errs() << "GEP: " << *I << "\n";
    #endif
      Value *index = I->getOperand(I->getNumOperands()-1);
      cg->addGEPEdge(index, I);
      //errs() << "Get Element Pointer: " << *I << "\n";
      //errs() << "Index: " << *index << "\n";
    } else if (isa<LoadInst>(I)) {
    #if DEBUG_LOCAL
      errs() << "Load Operator: " << *I << "\n";
    #endif
      // If a load, associate register with memory identifier
      LoadInst *LI = dyn_cast<LoadInst>(I);
      Value *op1 = LI->getPointerOperand();
      cg->addLoadEdge(op1, I);
      //errs() << "Loading From: " << *op1 << "\n";
      //errs() << "Loading To: " << *I << "\n";
    } else if (isa<StoreInst>(I)) {
    #if DEBUG_LOCAL
      errs() << "Store Operator: " << *I << "\n";
    #endif
      // If a store instruction, we need to set that memory location to value in graph
      StoreInst *SI = dyn_cast<StoreInst>(I);
      Value *to = SI->getPointerOperand();
      Value *from = SI->getValueOperand();
      Type* T = to->getType();
      bool isPointer = T->isPointerTy() && T->getContainedType(0)->isPointerTy();
      cg->addStoreEdge(from, to, I);
      if (isPointer) {
      #if DEBUG_LOCAL
        errs() << "Storing From Pointer\n";
      #endif
        // If store to location was a pointer, then we must kill all memory locations
        cg->killMemoryLocations();
      } 
      /**
      ConstantInt *ConstVal = dyn_cast<ConstantInt>(from);
      if (ConstVal != NULL) {
        errs() << "Storing Value: " << ConstVal->getSExtValue() << "\n";
      } else {
        errs() << "Storing From: " << *from << "\n";
      }
      
      if (isPointer) {
        errs() << "Storing To Pointer Location: " << *to << "\n";
      } else {
        errs() << "Storing To: " << *to << "\n";
      }
      */
    } else if (I->isBinaryOp()) {
      unsigned opcode = I->getOpcode();
      if (opcode == Instruction::Add) {
          int64_t val = 0;
          Value *var = NULL;
        #if DEBUG_LOCAL
          errs() << "Add Operator: " << *I << "\n";
        #endif  
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() + ConstVal2->getSExtValue();
            cg->addConstantNode(I, val);
          } else if (ConstVal1 != NULL) {
            val = ConstVal1->getSExtValue();
            var = op2;
            cg->addAddEdge(var, I, val);
            //errs() << *var << "\n";
            //errs() << "Constant: " << val << "\n";
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            cg->addAddEdge(var, I, val);
            //errs() << *var << "\n";
            //errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
            cg->addNode(I);
          }
      } else if (opcode == Instruction::Sub) {
          int64_t val = 0;
          Value *var = NULL;
        #if DEBUG_LOCAL
          errs() << "Subtraction Operator: " << *I << "\n";
        #endif
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() - ConstVal2->getSExtValue();
            cg->addConstantNode(I, val);
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
            cg->addNode(I);
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            cg->addSubEdge(var, I, val);
            //errs() << *var << "\n";
            //errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
            cg->addNode(I);
          }
      } else if (opcode == Instruction::Mul) {
          int64_t val = 0;
          Value *var = NULL;
        #if DEBUG_LOCAL
          errs() << "Multiply Operator: " << *I << "\n";
        #endif
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue()*ConstVal2->getSExtValue();
            cg->addConstantNode(I, val);
          } else if (ConstVal1 != NULL) {
            val = ConstVal1->getSExtValue();
            var = op2;
            cg->addMulEdge(var, I, val);
            //errs() << *var << "\n";
            //errs() << "Constant: " << val << "\n";
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            cg->addMulEdge(var, I, val);
            //errs() << *var << "\n";
            //errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
            cg->addNode(I);
          }
      } else if (opcode == Instruction::UDiv) {
          int64_t val = 0;
          Value *var = NULL;
        #if DEBUG_LOCAL 
          errs() << "Unsigned Division Operator: " << *I << "\n";
        #endif
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = (int64_t)(ConstVal1->getZExtValue()/ConstVal2->getZExtValue());
            cg->addConstantNode(I, val);
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
            cg->addNode(I);
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = (int64_t)ConstVal2->getZExtValue();
            cg->addDivEdge(var, I, val);
            errs() << *var << "\n";
            errs() << "Constant: " << val << "\n";
          } else {
            // Both operands are variables, so we must just create blank node
            cg->addNode(I);
          }
      } else if (opcode == Instruction::SDiv) {
          int64_t val = 0;
          Value *var = NULL;
        #if DEBUG_LOCAL  
          errs() << "Signed Division Operator: " << *I << "\n";
        #endif
          Value *op1 = I->getOperand(0);
          Value *op2 = I->getOperand(1);

          ConstantInt *ConstVal1 = dyn_cast<ConstantInt>(op1);
          ConstantInt *ConstVal2 = dyn_cast<ConstantInt>(op2);

          if ((ConstVal1 != NULL) && (ConstVal2 !=NULL)) {
            // We know both operands so can just create blank node with value
            val = ConstVal1->getSExtValue() + ConstVal2->getSExtValue();
            cg->addConstantNode(I, val);
          } else if (ConstVal1 != NULL) {
            // Second operand is variable so we can't determine much about operation
            cg->addNode(I);
          } else if (ConstVal2 != NULL) {
            var = op1;
            val = ConstVal2->getSExtValue();
            if (val > 0) { 
              cg->addDivEdge(var, I, val);
              //errs() << *var << "\n";
              //errs() << "Constant: " << val << "\n";
            } else {
              cg->addNode(I);
            }
          } else {
            // Both operands are variables, so we must just create blank node
            cg->addNode(I);
          }
      } else {
        errs() << "Handle opcode: " << I->getOpcodeName() << "?: " << *I << "\n";
      }
    } else {
      cg->addNode(I);
      errs() << "Handle opcode: " << I->getOpcodeName() << "?: " << *I << "\n";
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
  if (SizeCI) {
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

  Value* Index = Ptr;
  GetElementPtrInst* gep = dyn_cast<GetElementPtrInst>(Ptr);
  if (gep != NULL) {
      Index = gep->getOperand(gep->getNumOperands()-1);
  }

  // Add check to work list
  check = new BoundsCheck(Inst, Ptr, Index, Offset, Size);   
  return check;
}


void BoundsChecking::eliminateForwards(BoundsCheck* check1, BoundsCheck* check2,
                                       ConstraintGraph *cg) { 
  Value *ub1 = check1->getUpperBound();
  Value *ub2 = check2->getUpperBound();
  Value *index1 = check1->getIndex();
  Value *index2 = check2->getIndex();

  ConstraintGraph::CompareEnum cmp1 = cg->compare(index1, index2);
  if (check1->hasLowerBoundsCheck() && check2->hasUpperBoundsCheck()) {
    // If check1 lower bounds check is valid
    switch (cmp1) {
      case ConstraintGraph::LESS_THAN:
      case ConstraintGraph::EQUALS:
      #if DEBUG_LOCAL
        errs() << "Has Lower Bound Subsuming...\n";
        errs() << "Deleting Lower Bounds Check for " << *index2 << "\n";
      #endif
        // If index1 <= index2, don't need 0 <= index2
        check2->deleteLowerBoundsCheck();
        break;
      #if DEBUG_LOCAL
      case ConstraintGraph::GREATER_THAN:
        break;
      #endif
      default:
      #if DEBUG_LOCAL
        errs() << "Unknown comparison between " << *index1 << " and " << *index2 <<"\n";
      #endif
        // Unknown value for indiciesi
        break;
    }
  }

  if (check1->hasUpperBoundsCheck() && check2->hasUpperBoundsCheck()) {
    ConstraintGraph::CompareEnum cmp2 = ConstraintGraph::UNKNOWN;
    switch (cmp1) {
      #if DEBUG_LOCAL
      case ConstraintGraph::LESS_THAN:
        break;
      #endif
      case ConstraintGraph::EQUALS:
      case ConstraintGraph::GREATER_THAN:
      #if DEBUG_LOCAL
        errs() << "Has Upper Bound Subsuming...\n";
      #endif
        // If check 1 is upper bounds check valid
        cmp2 = cg->compare(ub1, ub2);
        if (cmp2 == ConstraintGraph::LESS_THAN || cmp2 == ConstraintGraph::EQUALS) {
        #if DEBUG_LOCAL
          errs() << "Deleting Upper Bounds Check for " << *index2 << "\n";
        #endif
          // If index1 >= index2, and ub1 <= ub2, don't need index2 <= ub2
          check2->deleteUpperBoundsCheck();
        }
        #if DEBUG_LOCAL
         else if (cmp2 == ConstraintGraph::UNKNOWN) {
          errs() << "Unknown comparison between " << *ub1 << " and " << *ub2 <<"\n";
         }
        #endif
        break;
      default:
      #if DEBUG_LOCAL
        errs() << "Unknown comparison between " << *index1 << " and " << *index2 <<"\n";
      #endif
        // Unknown indicies, or unknown sizes
        break;
    }
  }
}

void BoundsChecking::eliminateBackwards(BoundsCheck* check1, BoundsCheck* check2,
                                        ConstraintGraph *cg) { 
  Value *ub1 = check1->getUpperBound();
  Value *ub2 = check2->getUpperBound();
  Value *index1 = check1->getIndex();
  Value *index2 = check2->getIndex();
  
  // Compare index 1 to index 2
  ConstraintGraph::CompareEnum cmp1 = cg->compare(index1, index2);
  if (check2->hasLowerBoundsCheck() && check1->hasLowerBoundsCheck()) {
    // If check2 lower bounds check is valid
    switch (cmp1) {
      #if DEBUG_LOCAL
      case ConstraintGraph::LESS_THAN:
        break;
      #endif
      case ConstraintGraph::EQUALS:
      case ConstraintGraph::GREATER_THAN:
      #if DEBUG_LOCAL
        errs() << "Checking Lower Bound Subsuming...\n";
      #endif
      #if DEBUG_LOCAL
        errs() << "Deleting Lower Bounds Check for " << *index1 << "\n";
      #endif
        // If index1 >= index2, don't need 0 <= index1
        if (cg->findDependencyPath(index1, check2->getIndex(), &(check2->dependentInsts))) {
          check1->deleteLowerBoundsCheck();
          check2->insertBefore(dyn_cast<Instruction>(check1->getIndex()), false);
        }
      #if DEBUG_LOCAL
        else {
          errs() << "Could not move " << *index2 << " to " << *index1 << "\n";
        }
      #endif
        break;
      default:
      #if DEBUG_LOCAL
        errs() << "Unknown comparison between " << *index1 << " and " << *index2 <<"\n";
      #endif
        // Unknown value for indicies
        break;
    }
  }

  if (check2->hasUpperBoundsCheck() && check1->hasUpperBoundsCheck()) {
    // If check 2 is upper bounds check valid
    ConstraintGraph::CompareEnum cmp2 = cg->compare(ub1, ub2);
    switch (cmp1) {
      case ConstraintGraph::LESS_THAN:
      case ConstraintGraph::EQUALS:
      #if DEBUG_LOCAL
        errs() << "Checking Upper Bound Subsuming...\n";
      #endif
        if (cmp2 == ConstraintGraph::GREATER_THAN || cmp2 == ConstraintGraph::EQUALS) {
        #if DEBUG_LOCAL
          errs() << "Deleting Upper Bounds Check for " << *index1 << "\n";
        #endif
          // If index1 <= index2, and ub2 <= ub1, don't need index1 <= ub1
          if (cg->findDependencyPath(index1, check2->getOffset(), &(check2->dependentInsts))) {
            check1->deleteUpperBoundsCheck();
            check2->insertBefore(dyn_cast<Instruction>(check1->getIndex()), true);
          }
        #if DEBUG_LOCAL
          else {
            errs() << "Could not move " << *index2 << " to " << *index1 << "\n";
          }
        #endif
        } 
      #if DEBUG_LOCAL
        else if (cmp2 == ConstraintGraph::UNKNOWN) {
          errs() << "Unknown comparison between " << *ub1 << " and " << *ub2 <<"\n";
        }
      #endif
        break;
      #if DEBUG_LOCAL
      case ConstraintGraph::GREATER_THAN:
      #endif
      default:
      #if DEBUG_LOCAL
        errs() << "Unknown comparison between " << *index1 << " and " << *index2 <<"\n";
      #endif
        // Unknown indicies, or unknown sizes
        break;
    }
  }
}

void BoundsChecking::getCheckVariables(std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph *cg) {
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(), e = boundsChecks->end();
          i != e; i++ ) {
    BoundsCheck *check = *i;
    
    bool known;
    int64_t weight;
    Value *val = cg->findFirstLoad(check->getIndex(), &weight, &known);
    check->setVariable(val, weight, known);
  }
}

void BoundsChecking::EliminateBoundsChecks(std::vector<BoundsCheck*> *boundsChecks, 
                                           ConstraintGraph *cg) {
#if DEBUG_LOCAL
  errs() << "Forward Elimination...\n";
#endif
  // Forward analysis to identify if higher occuring bounds check
  // is stricter than lower occuring bounds check
  for (int i = 0; i < ((int)boundsChecks->size())-1; i++) {
    BoundsCheck *check = boundsChecks->at(i);

    if (check->stillExists()) {
      for (unsigned int j = i + 1; j < boundsChecks->size(); j++) {
        BoundsCheck* tmp = boundsChecks->at(j);
        if (tmp->stillExists()) {
          eliminateForwards(check, tmp, cg);
        }
      }
    }
  }


#if DEBUG_LOCAL
  errs() << "Backwards Elimination...\n";
#endif
  // Backwards analysis to identify if lower occuring bounds check
  // is stricter than higher occuring bounds check
  for (int i = boundsChecks->size()-1; i >= 1; i--) {
    BoundsCheck *check = boundsChecks->at(i);

    if (check->stillExists()) {
      for (int j = i - 1; j >= 0;  j--) {
        BoundsCheck* tmp = boundsChecks->at(j);
        if (tmp->stillExists()) {
          eliminateBackwards(tmp, check, cg);
        }
      }
    }
  }
}

void BoundsChecking::promoteCheck(BoundsCheck* check) {
  if (check->moveCheck()) {
    // Propogate the instructions to their new location
    Instruction *insertPoint = check->getInsertPoint();
    #if DEBUG_LOCAL
      errs() << "Inserting Instructions at: " <<  *insertPoint << "\n";
    #endif
    for (std::vector<Instruction*>::iterator i = check->dependentInsts.begin(),
             e = check->dependentInsts.end(); i != e; i++) {
      Instruction *inst = *i;
    #if DEBUG_LOCAL
      errs() << "Moving instruction: " << *inst << " before " << *insertPoint << "\n";
    #endif
      inst->moveBefore(insertPoint);
      insertPoint = inst;
    }
  }
}

void BoundsChecking::promoteLocalChecks(std::vector<BoundsCheck*> *boundsChecks) 
{
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(),
            e = boundsChecks->end(); i != e; i++) {
    promoteCheck(*i);
  }  
}

void BoundsChecking::LocalAnalysis(BasicBlock *blk, std::vector<BoundsCheck*> *boundsChecks, ConstraintGraph* cg) 
{ 
  // Identify bounds checks in block
  IdentifyBoundsChecks(blk, boundsChecks);
#if DEBUG_LOCAL  
  errs() << "===================================\n";
  errs() << "Identified Bounds Checks\n";
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(),
        e = boundsChecks->end(); i != e; i++) {
    BoundsCheck* check = *i;
    check->print();
  }
#endif

#if DEBUG_LOCAL  
  errs() << "===================================\n";
#endif

#if DEBUG_LOCAL  
  errs() << "===================================\n";
  errs() << "Building Constraints Graph\n";
#endif
  // Build the Constraits Graph for blk
  buildConstraintGraph(blk, cg);
#if DEBUG_LOCAL  
  cg->print();
  errs() << "===================================\n";
#endif

#if DEBUG_LOCAL  
  errs() << "===================================\n";
  errs() << "Eliminating Bounds Checks\n";
#endif
  // Eliminate bounds checks from block
  getCheckVariables(boundsChecks, cg);
  EliminateBoundsChecks(boundsChecks, cg);
#if DEBUG_LOCAL  
  errs() << "===================================\n";
#endif
  
#if DEBUG_LOCAL  
  errs() << "Promoting Checks\n";
#endif
  promoteLocalChecks(boundsChecks);
#if DEBUG_LOCAL  
  errs() << "===================================\n";
#endif
#if DEBUG_LOCAL  
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(),
        e = boundsChecks->end(); i != e; i++) {
    BoundsCheck* check = *i;
    check->print();
  }
  errs() << "===================================\n";
#endif
}


void BoundsChecking::GlobalAnalysis(std::vector<BasicBlock*> *worklist, std::map<BasicBlock*,std::vector<BoundsCheck*>*> *blkChecks, std::map<BasicBlock*,ConstraintGraph*> *blkCG) 
{
  std::vector<GlobalCheck*> allChecks;
  std::map<BasicBlock*,BlockFlow*> flows;

  // Create a block flow object for each valid block
  for (std::vector<BasicBlock*>::iterator i = worklist->begin(), e = worklist->end(); 
              i != e; i++) {
    BasicBlock *blk = *i;
    BlockFlow *blk_flow = new BlockFlow(blk, (*blkChecks)[blk], (*blkCG)[blk], &flows);
    flows[blk] = blk_flow;
#if DEBUG_GLOBAL
    errs() << "Created Flow Block for Block: " << blk->getName() << "\n";
#endif
  }

  BasicBlock *entry = &(worklist->at(0)->getParent()->getEntryBlock());
  flows[entry]->isEntry = true;
  flows[entry]->identifyOutSet();

#if DEBUG_GLOBAL
  errs() << "Performing Available Check Analysis:\n";
  int iteration = 0;
#endif
  // Perform the available expression analysis
  bool change;
  do {
  #if DEBUG_GLOBAL
    errs() << "Running iteration: " << iteration << "\n";
    iteration++;
  #endif
    change = false;
    for (std::vector<BasicBlock*>::iterator i = worklist->begin(), e = worklist->end(); i != e; i++) {
      BasicBlock *blk = *i;
      if (blk != entry) {
        change |= flows[blk]->identifyOutSet();
      }
    }
  } while (change);
#if DEBUG_GLOBAL
  for (std::vector<BasicBlock*>::iterator i = worklist->begin(), e = worklist->end(); 
              i != e; i++) {
    BasicBlock *blk = *i;
    BlockFlow *blk_flow = flows[blk];
    blk_flow->print();
  }
  errs() << "==============================\n";
#endif
#if DEBUG_GLOBAL
  errs() << "Eliminating Redundant Checks\n";
#endif
  // Eliminate checks based on in set values
  for (std::vector<BasicBlock*>::iterator i = worklist->begin(), e = worklist->end(); i != e; i++) {
    BasicBlock *blk = *i;
    BlockFlow *blk_flow = flows[blk];
  #if DEBUG_GLOBAL
    errs() << "Eliminating Checks for Block:" << blk->getName() << "\n";
  #endif
    blk_flow->eliminateRedundantChecks();
  }
#if DEBUG_GLOBAL
  errs() << "==============================\n";
#endif
}

bool BoundsChecking::runOnFunction(Function &F) {
  TD = &getAnalysis<DataLayout>();
  TLI = &getAnalysis<TargetLibraryInfo>();

  TrapBB = 0;
  BuilderTy TheBuilder(F.getContext(), TargetFolder(TD));
  Builder = &TheBuilder;
  ObjectSizeOffsetEvaluator TheObjSizeEval(TD, TLI, F.getContext());
  ObjSizeEval = &TheObjSizeEval;
  
  std::vector<BasicBlock*> worklist;
  std::map<BasicBlock*, std::vector<BoundsCheck*>*> blkChecks;
  std::map<BasicBlock*, ConstraintGraph*> blkCG;
 
  // Identify basic blocks in function
  for (Function::iterator i = F.begin(), e = F.end(); i != e; ++i) {
    BasicBlock* blk =  &*i;
    worklist.push_back(blk);
    blkCG[blk] = new ConstraintGraph();
    blkChecks[blk] = new std::vector<BoundsCheck*>();
  }

  // Iterate over the Basic Blocks and perform local analysis
  for (std::vector<BasicBlock*>::iterator i = worklist.begin(), e = worklist.end(); 
              i != e; i++) {
    BasicBlock *blk = *i;
    LocalAnalysis(blk, blkChecks[blk], blkCG[blk]);
  }
 
  // Perform Global Analysis
  errs() << "Global Analysis\n";
  GlobalAnalysis(&worklist, &blkChecks, &blkCG);
  // Perform Loop Analysis
    
  // Insert identified checks
  errs() << "Inserting Bounds Checks\n";
  bool MadeChange = true;
  int prevNumberChecks = numChecksAdded;
  for (std::vector<BasicBlock*>::iterator i = worklist.begin(), e = worklist.end(); 
              i != e; i++) {
    // Inserting Checks for given basic block
    BasicBlock* blk =  *i;
    MadeChange |= InsertChecks(blkChecks[blk]);
    errs() << "Basic Block (name=" << blk->getName() << "):";
    errs() << (numChecksAdded - prevNumberChecks)  << " Checks Added\n";
    prevNumberChecks = numChecksAdded;
  }
  errs() << "===================================\n";
  errs() << "Total Number of Checks Addded: " << numChecksAdded << "\n";

#if DEBUG_LOCAL
  for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) {
    Instruction *I = &*i;
    errs() << *I << "\n";
  }
#endif
  return MadeChange;
}

FunctionPass *llvm::createBoundsCheckingPass(unsigned Penalty) {
  return new BoundsChecking(Penalty);
}

bool BoundsChecking::InsertCheck(BoundsCheck* check) {
  if (!check->stillExists())
    return false;
 
#if DEBUG_INSERT
  check->print();
#endif
  Inst = check->getInstruction(); 
  Value *Size = check->getUpperBound();
  Value *Index = check->getIndex();
  Value *Offset = check->getOffset();

  
  Builder->SetInsertPoint(check->getInsertPoint());
  Value *llvmCheck = NULL;
  if (check->hasUpperBoundsCheck()) {
    llvmCheck = Builder->CreateICmpULT(Size, Offset);
    numChecksAdded++;
  } 

  if (check->hasLowerBoundsCheck()) {
    Type *T = Index->getType();
    numChecksAdded++;
    bool isPointer = T->isPointerTy();
    if (!isPointer) {
      Value *lowerCheck = Builder->CreateICmpSLT(Index, ConstantInt::get(T, 0));
      if (llvmCheck != NULL) {
        llvmCheck = Builder->CreateOr(lowerCheck, llvmCheck);
      } else {
        llvmCheck = lowerCheck;
      }
    }
  }

  if (llvmCheck != NULL) {
    emitBranchToTrap(llvmCheck);
    return true;
  }
  return false;
}

bool BoundsChecking::InsertChecks(std::vector<BoundsCheck*> *boundsChecks) {
  bool MadeChange = false;
  for (std::vector<BoundsCheck*>::iterator i = boundsChecks->begin(),
            e = boundsChecks->end(); i != e; i++) {
    MadeChange |= InsertCheck(*i);
  }  
  return MadeChange;
}
