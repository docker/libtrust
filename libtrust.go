package libtrust

import (
	"io"
)

// ID represents an keypair identity.  Fellow trust agents and servers
// will delegate responsibilities to a single ID.
type ID interface {
	// String returns a unique representation of the id
	String() string

	// Signs signs the content using the id.  If this id has
	// no private key specified, this will return an
	// error.
	Sign(io.Reader) ([]byte, error)

	// CanSign returns whether an ID object is capable of generating
	// signatures, verifying signature is always possible.
	CanSign() bool

	// Verify verifies content using the id.
	Verify(io.Reader, []byte) error

	// Returns the public part of the ID as a JSON Web Key.
	JSONWebKey() map[string]interface{}
}
