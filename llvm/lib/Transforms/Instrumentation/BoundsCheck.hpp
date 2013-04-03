


class BoundsCheck
{
  public:
    BoundsCheck(Instruction *inst, Value *ind, Value *ub_val);
    ~BoundsCheck();
    
    uint64_t lowerBoundValue();
    uint64_t upperBoundValue();

    bool insertLowerBoundsCheck();
    void addLowerBoundsCheck();
    void deleteLowerBoundsCheck();
    bool insertUpperBoundsCheck();
    void addUpperBoundsCheck();
    void deleteUpperBoundsCheck();
    void print();
  private:
    // Value associated with the check
    Instruction *inst;
    Value *index;
    uint64_t lower_bound;
    bool lower_bound_static;
    uint64_t upper_bound;
    bool upper_bound_static;
    Value *upper_bound_value;
    bool insert_lower_bound;
    bool insert_upper_bound;
};


BoundsCheck::BoundsCheck(Instruction *I, Value *ind, Value *ub_val) 
{
  inst = I;
  index = ind;
  upper_bound_value = ub_val;

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
  insert_upper_bound = false;
}

BoundsCheck::~BoundsCheck() 
{
  
}

void BoundsCheck::print()
{
  errs() << "===========================\n";
  errs() << "Instruction: " << *inst << "\n";
  errs() << "Lower Bound: " << lower_bound << "\n";
  errs() << "Upper Bound: " << *upper_bound_value << "\n";
  errs() << "Index: " << *index << "\n";
}
uint64_t BoundsCheck::lowerBoundValue() 
{
  return lower_bound;
}

uint64_t BoundsCheck::upperBoundValue() 
{
  return upper_bound;
}

bool BoundsCheck::insertLowerBoundsCheck() 
{
  return insert_lower_bound;
}

void BoundsCheck::addLowerBoundsCheck() {
  insert_lower_bound = true;
}

void BoundsCheck::deleteLowerBoundsCheck() {
  insert_lower_bound = false;
}


bool BoundsCheck::insertUpperBoundsCheck() 
{
  return insert_upper_bound;
}

void BoundsCheck::addUpperBoundsCheck() {
  insert_upper_bound = true;
}

void BoundsCheck::deleteUpperBoundsCheck() {
  insert_upper_bound = false;
}
