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

// PublicKey represents the public part of a key pair.
type PublicKey interface {
	// String returns a unique string representation of the key.
	String() string

	// Fingerprint returns a secure fingerprint for the key.
	Fingerprint() Fingerprint

	// SupportedAlgorithms returns a list of algorithms supported
	// by the key.
	SupportedAlgorithms() []SignatureAlgorithm

	// Verify verifies content using the id.
	Verify(io.Reader, []byte, SignatureAlgorithm) error
}

// Key represents a keypair identity.  Fellow trust agents and servers
// will delegate responsibilities to a single Key.
type Key interface {
	PublicKey

	// Sign signs the content using the key.
	Sign(io.Reader, SignatureAlgorithm) ([]byte, error)

	// GenerateX509KeyPair generates a new self-signed X509 certificate
	// and private key using this KeyPair.
	GenerateX509KeyPair() ([]byte, []byte, error)
}
