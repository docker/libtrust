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
