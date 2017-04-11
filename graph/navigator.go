package graph

/*
GraphNavigator is an interface to CRUD operations for a table of nodes. See
MemoryNavigator for a type that implements this interface.
*/
type GraphNavigator interface {
	/*
	   Add a node to the graph.
	*/
	Set(node Node) error
	/*
	   Get a node from the graph. Takes a string which is the Name() identifier.
	*/
	Get(id string) (Node, error)
	/*
	  Delete a node. Takes a string which is the Name() identifier.
	*/
	Delete(id string) error

	/*
	   Create a new node. Will add to the Navigator registry. Returns nil on
	   error.
	*/
	NewNode(id string) Node
}
