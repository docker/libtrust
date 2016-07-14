package trustgraph

import "github.com/docker/libtrust"

// TrustGraph represents a graph of authorization mapping
// public keys to nodes and grants between nodes.
type TrustGraph interface {
	// Verifies that the given public key is allowed to perform
	// the given action on the given node according to the trust
	// graph.
	Verify(libtrust.PublicKey, string, string) (bool, error)

	// GetGrants returns an array of all grant chains which are used to
	// allow the requested scope.
	GetGrants(libtrust.PublicKey, string, string) ([][]*Grant, error)
}

// Grant represents a transfer of permission from one part of the
// trust graph to another. This is the only way to delegate
// permission between two different sub trees in the graph.
type Grant struct {
	// Subject is the namespace being granted
	Subject string

	// Scopes is an array of allowed actions.
	Scopes []string

	// Grantee represents the node being granted
	// a permission scope.  The grantee can be
	// either a namespace item or a key id where namespace
	// items will always start with a '/'.
	Grantee string

	// statement represents the statement used to create
	// this object.
	statement *Statement
}
