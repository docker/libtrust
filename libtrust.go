package libtrust

import (
	"errors"
	"io"
)

type SignatureAlgorithm int

const (
	RSA256 = iota
	RSA384
	RSA512
	EC256
	EC384
	EC512
)

var (
	ErrUnsupportedAlgorithm = errors.New("Unsupported algorithm")
)

// Fingerprint is a secure fingerprint of a public key
type Fingerprint [32]byte

// Verifier represents a type capable of verifying content.
type Verifier interface {
	// SupportedAlgorithms returns a list of algorithms supported
	// by the key.
	SupportedAlgorithms() []SignatureAlgorithm

	// Verify verifies content using the id.
	Verify(io.Reader, []byte, SignatureAlgorithm) error
}

// Signer represents a type capable of signing and verifying content.
type Signer interface {
	Verifier

	// Sign signs the content using the key.
	Sign(io.Reader, SignatureAlgorithm) ([]byte, error)
}

// FingerPrinter represents a type capable of returning a
// secure fingerprint and unique string
type FingerPrinter interface {
	// String returns a unique string representation of the key.
	String() string

	// Fingerprint returns a secure fingerprint for the key.
	Fingerprint() Fingerprint
}

// PublicKey represents the public part of a key pair.
type PublicKey interface {
	Verifier

	FingerPrinter
}

// Key represents a keypair identity.  Fellow trust agents and servers
// will delegate responsibilities to a single Key.
type Key interface {
	Signer

	FingerPrinter

	// PublicKey returns the corresponding public part of this key.
	PublicKey() PublicKey
}
