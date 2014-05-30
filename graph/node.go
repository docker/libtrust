package graph

/*
Node is an interface to graph nodes. See Graph for an example type which
implements this interface.
*/
type Node interface {
	/*
	   The identifier, or name, as a string.
	*/
	Name() string

	/*
	   Add a child to the node. Duplicate operations will only yield one copy.
	*/
	AddChild(Node) error

	/*
	   Remove a child from the node.
	*/
	RemoveChild(Node) error

	/*
	  Return all children for the node.
	*/
	Children() []Node

	/*
	   Add a grant to the node. Please see Grant.
	*/
	AddGrant(Grant) error

	/*
	   Remove a grant from the node. Please see Grant.
	*/
	RemoveGrant(Grant) error

	/*
	  Yield all grants for the node.
	*/
	Grants() []Grant

	/*
	   Sets the parent of this node. Should also ensure that a child exists in any
	   children tracking solution.
	*/
	SetParent(Node) error

	/* Retrieve the parent of this node. */
	Parent() Node

	/*
	   Is the user capable of `Action`?
	*/
	IsCapable(act Action) bool

	/*
	   Can the user delegate `Action`?
	*/
	IsDelegated(act Action) bool

	/*
	  Is this node equal to the passed node?
	*/
	Equals(Node) bool

	NewGrant(Category, Action, Node) (Grant, error)
}
