// Constraint Node
class ConstraintNode {
  public:
    enum EdgeType
    {
      UNKNOWN,
      LOAD,
      STORE,
      ADD,
      SUB,
      MULT,
      DIV,
      EQUALS
    };
    ConstraintNode(Value *val, int id_num);
    ~ConstraintNode();

    void setPredecessor(ConstraintNode* node, int64_t weight, EdgeType type)
    void addEdgeTo(ConstraintNode* node, int64_t weight, EdgeType type);
    void setConstantValue(int64_t val);
    int64_t getConstantValue();
    bool hasConstantValue();
  private:
    Value *llvmVal;
    int id;
    int64_t const_val;
    bool has_const_val;
    ConstraintNode* pred;
    int64_t pred_weight;
    EdgeType pred_edge_type;
    std::vector<ConstraintNode> successors;
    std::vector<int64_t> weights;
    std::vector<EdgeType> types;
}

ConstraintNode::ConstraintNode(Value *val, int id_num) 
{
  llvmVal = val;
  id = id_num;
  pred = NULL;
  pred_edge_type = ConstraintNode::UNKNOWN;
  has_const_val = false;
}

ConstraintNode::~ConstraintNode() 
{
}

bool hasConstantValue() {
  return has_const_val;
}

int64_t getConstantValue() {
  return const_val;
}

void ConstraintNode::setPredecessor(ConstraintNode* node, int64_t weight, EdgeType type) 
{
  pred = node;
  pred_weight = weight;
  pred_edge_type = type;

}

void ConstraintNode::addEdgeTo(ConstraintNode* node, int64_t value, EdgeType type) 
{
  successors.push_back(node);
  weights.push_back(weight);
  types.push_back(type);
}

void ConstraintNode::setConstantValue(int64_t val) 
{
  has_const_val = true;
  const_val = val;
}

// Constraint Graph
class ConstraintGraph {
  public:
    enum CompareEnum
    {
      UNKNOWN = 0,
      LESS_THAN = 1,
      EQUALS = 2,
      GREATER_THAN = 3
    };
    ConstraintGraph();
    ~ConstraintGraph();

    CompareEnum compare(Value *val1, Value *val2);
  private:
    std::vector<ConstraintNode*> nodes;
    std::map<Value, int> memoryNodes;
};

ConstraintGraph::ConstraintGraph() {

}

ConstraintGraph::~ConstraintGraph() 
{
  // Iterate and delete create constraint nodes
  for (std::vector<ConstraintNode*>::iterator i = nodes->begin(), 
        std::vector<ConstraintNode*>::iterator e = nodes->end; i != e; i++) {
    delete *i;  
  }
  nodes.clear();
  memoryNodes.clear();
}


ConstraintGraph::CompareEnum ConstraintGraph::compare(Value *val1, Value *val2) 
{
  return ConstraintGraph::UNKNOWN;
}

ConstraintNode* ConstraintGraph::getNode(Value *val, int id) 
{
  for (std::vector<ConstraintNode*>::iterator i = nodes->begin(), 
        std::vector<ConstraintNode*>::iterator e = nodes->end; i != e; i++) {
    ConstraintNode *node = *i;
    if (node->equals(Value *val, id)) {
      return node;
    }
  }
  return NULL;
}

ConstraintGraph::addStoreEdge(Value *from, Value *to) 
{
  std::map<Value,int>::iterator it = memoryNodes.find(to);
  int id = 0;
  if (it == std::map<Value,int>::end) {
    memoryNodes[to] = 0;
  } else {
    id = memoryNodes[to];
    memoryNodes[to] = id + 1;
  }
  ConstantInt *ConstVal = dyn_cast<ConstantInt>(from);
  ConstraintNode* toNode = new ConstraintNode(to, id);
  if (ConstVal != NULL) {
    toNode->setConstantValue(ConstVal->getSExtValue());
    nodes.push_back(toNode);
  } else {
    ConstraintNode* fromNode = getNode(from, 0);
    if (fromNode == NULL) {
      fromNode = new ConstraintNode(from, 0);
      nodes.push_back(fromNode);
    } else {
      toNode->setPredecessor(fromNode, 0, ConstraintNode::STORE);
      fromNode->addEdgeTo(toNode, ConstraintNode::STORE);
    }
  }
}

ConstraintGraph::addLoadEdge(Value *from, Value *to) 
{
  ConstraintNode* fromNode; = getNode(from, 0);
  std::map<Value,int>::iterator it = memoryNodes.find(from);
  if (it == std::map<Value,int>::end) {
    memoryNodes[from] = 0;
    fromNode = new ConstraintNode(from, 0);
    nodes.push_back(from_node);
  } else {
    fromNode = getNode(from, memoryNodes[to]);
  }

  
  ConstraintNode* toNode = new ConstraintNode(to, 0);
  toNode->setPredecessor(fromNode, 0, ConstraintNode::LOAD);
  if (fromNode->hasConstantValue()) {
    toNode->setConstantValue(fromNode->getConstantValue());
  }
  fromNode->addEdgeTo(toNode, 0, ConstraintNode::LOAD);
}

