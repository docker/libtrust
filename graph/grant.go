package graph

/*
   GrantInterface encapsulates the full data required to grant a Category of
   grant for a specific Action to a specific node, which is treated as an
   identity for the purposes of this discussion.
*/
type Grant interface {
	/*
	   Does this grant equal this other grant?
	*/
	Equals(Grant) bool

	/*
	   Set the kind of category associated with this grant.
	*/
	SetCategory(Category) error
	/*
	   Get the kind of category associated with this grant.
	*/
	Category() Category
	/*
	   Set the kind of action associated with this grant.
	*/
	SetAction(Action) error
	/*
	   Get the kind of action associated with this grant.
	*/
	Action() Action
	/*
	   Set the node associated with this grant.
	*/
	SetNode(Node) error
	/*
	   Get the node associated with this grant.
	*/
	Node() Node
}

// Categories are types of grants.
type Category int

const (
	// Authorize the user to execute X
	Authorize Category = iota

	// Authorize a user to authorize others to execute X on behalf of the parent.
	Delegate
)

// Actions are types of actions that can be granted.
type Action int

// Actions map to Beam commands.
// FIXME: move this to Beam and import it from there.
const (
	LS Action = iota
	CD
	CONNECT
	SET
	GET
	LOG
	STOP
	START
	RM
	REGISTER
	AUTHORIZE
	DELEGATE
	PULL
	PUSH
)
