package graph

// MemoryNavigator is an in-memory representation of a GraphNavigator, as a map[string]Node
type MemoryNavigator map[string]Node

func NewMemoryNavigator() *MemoryNavigator {
	return &MemoryNavigator{}
}

func (n *MemoryNavigator) Set(node Node) error {
	(*n)[node.Name()] = node
	return nil
}

func (n *MemoryNavigator) Get(id string) (Node, error) {
	return (*n)[id], nil
}

func (n *MemoryNavigator) Delete(id string) error {
	delete(*n, id)

	return nil
}

func (n *MemoryNavigator) NewNode(id string) Node {
	mn := &MemoryNode{
		id:       id,
		grants:   []Grant{},
		children: []Node{},
		parent:   nil,
	}

	n.Set(mn)

	return mn
}
