
// BoundsCheck Class
class BoundsCheck
{
  public:
    BoundsCheck(Instruction *inst, Value *ptr, Value *ind, Value* off, Value *ub_val);
    ~BoundsCheck();
    

    Value*  getPointer();
    Value*  getUpperBound();
    Value*  getIndex();
    Value*  getOffset();
   

    bool hasLowerBoundsCheck();
    bool hasUpperBoundsCheck();
    void deleteLowerBoundsCheck();
    void deleteUpperBoundsCheck();
    
    Instruction* getInsertPoint();
    void insertBefore(Instruction* I);

    bool stillExists();
    bool moveCheck();
    void print();
    
    void addLowerBoundsCheck();
    void addUpperBoundsCheck();
    Instruction* getInstruction();

    uint64_t lowerBoundValue();
    uint64_t upperBoundValue();
    
    std::vector<Instruction*> dependentInsts;
  private:
    // Value associated with the check
    Value *pointer;
    Instruction *inst;
    Instruction *insertLoc;
    bool move_check;
    Value *index;
    Value *offset;

    uint64_t lower_bound;
    bool lower_bound_static;
    uint64_t upper_bound;
    bool upper_bound_static;
    Value *upper_bound_value;
    bool insert_lower_bound;
    bool insert_upper_bound;
};


BoundsCheck::BoundsCheck(Instruction *I, Value *ptr, Value *ind, Value* off, Value *ub_val) 
{
  pointer = ptr;
  inst = I;
  index = ind;
  upper_bound_value = ub_val;
  offset = off;
  insertLoc = I;
  move_check = false;
  lower_bound = 0;
  lower_bound_static = true;

  ConstantInt *ub_const = dyn_cast<ConstantInt>(ub_val);
  if (ub_const != NULL) {
    upper_bound = ub_const->getZExtValue();
    upper_bound_static = true;
  } else {
    upper_bound_static = false;
  }
  
  
  insert_lower_bound = true;
  insert_upper_bound = true;
}

BoundsCheck::~BoundsCheck() 
{
}

Instruction* BoundsCheck::getInstruction() {
  return inst;
}
Value* BoundsCheck::getUpperBound() {
  return upper_bound_value;
}


Value* BoundsCheck::getIndex() {
  return index;
}

Value* BoundsCheck::getOffset() {
  return offset;
}

Value* BoundsCheck::getPointer() {
  return pointer;
}

Instruction* BoundsCheck::getInsertPoint() {
  return insertLoc;
}


void BoundsCheck::insertBefore(Instruction *inst) {
  move_check = insertLoc != inst;
  insertLoc = inst;
}

bool BoundsCheck::moveCheck() {
  return move_check;
}

bool BoundsCheck::stillExists() {
  return insert_lower_bound || insert_upper_bound;
}

void BoundsCheck::print()
{
  errs() << "===========================\n";
  errs() << "Instruction: " << *inst << "\n";
  if (insert_lower_bound) {
    errs() << "Lower Bound Check: " << lower_bound << "\n";
  } else {
    errs() << "Lower Bound Check (DELETED): " << lower_bound << "\n";
  }

  if (insert_upper_bound) {
    errs() << "Upper Bound Check: " << *upper_bound_value << "\n";
  } else {
    errs() << "Upper Bound Check (DELETED): " << *upper_bound_value << "\n";
  }
  errs() << "Index: " << *index << "\n";
  errs() << "Moving Check :" << (move_check ? "Yes": "No") << "\n";
  errs() << "Insert Point: " << *insertLoc << "\n";
}

uint64_t BoundsCheck::lowerBoundValue() 
{
  return lower_bound;
}

uint64_t BoundsCheck::upperBoundValue() 
{
  return upper_bound;
}

bool BoundsCheck::hasLowerBoundsCheck() 
{
  return insert_lower_bound;
}

void BoundsCheck::addLowerBoundsCheck() {
  insert_lower_bound = true;
}

void BoundsCheck::deleteLowerBoundsCheck() {
  insert_lower_bound = false;
}


bool BoundsCheck::hasUpperBoundsCheck() 
{
  return insert_upper_bound;
}

void BoundsCheck::addUpperBoundsCheck() {
  insert_upper_bound = true;
}

void BoundsCheck::deleteUpperBoundsCheck() {
  insert_upper_bound = false;
}
