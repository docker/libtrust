package trustchain

import (
	"bytes"
	"errors"
	"strings"
	"time"
)

var (
	// ErrInvalidChain used when at least one link of a chain is invalid.
	ErrInvalidChain = errors.New("invalid chain")

	// ErrLinkRevocation used when at least one link of a chain
	// contains a revoked key.
	ErrLinkRevocation = errors.New("chain link revoked")

	// ErrRootUnverified used when the last grantee in a chain is
	// not a verified authority.
	ErrRootUnverified = errors.New("root unverified")
)

// KeyID used to represent the secure fingerprint of a key
type KeyID [32]byte

// ShortKeyID used to represent an identifiable fingerprint of a key
type ShortKeyID [20]byte

// Link represents a single segment of an authentication chain
type Link struct {
	// Key which was granted access
	Grantee KeyID
	// Key whose authority was used to grant access
	Granter KeyID
	// Namespace which was granted access to
	Namespace string
	// When the granted access is no longer valid
	Expiration time.Time
}

// Chain represents an order list of links, the end of which
// being the root authority.  A valid chain most be ordered such
// that the next item grantee in the link is the granter of
// the current item.  The final granter is considered the root key.
type Chain []*Link

// ChainVerifier represents an object which can verify a chain
type ChainVerifier interface {
	// VerifyChain checks to ensure the chain has root authority
	// and no links have been revoked
	VerifyChain(Chain) error
}

// KeyAuthority represents a set of authorities and revocations
// which can be used to verify a chain of trust.
type KeyAuthority struct {
	// Authorities map key IDs to namespaces
	Authorities map[string]string

	// Ordered revocation list
	RevocationList []ShortKeyID
}

func newKeyAuthority() *KeyAuthority {
	return &KeyAuthority{
		Authorities:    make(map[string]string),
		RevocationList: make([]ShortKeyID, 0),
	}
}

// LoadKeyAuthorityFile loads a KeyAuthority from a
// key authority file.
func LoadKeyAuthorityFile(name string) (*KeyAuthority, error) {
	// TODO Load file
	return nil, nil
}

func (a *KeyAuthority) checkRevocationList(k KeyID) bool {
	// Shorten key to 20 bytes
	// TODO Binary search
	return false
}

// VerifyChain verifies the the chain of trust using the
// KeyAuthority's set of authorities and revocations.
func (a *KeyAuthority) VerifyChain(c Chain) error {
	if len(c) == 0 {
		return ErrInvalidChain
	}

	for i := range c {
		if i+1 < len(c) {
			if bytes.Compare(c[i].Grantee[:], c[i+1].Granter[:]) != 0 {
				return ErrInvalidChain
			}
			if !strings.HasPrefix(c[i].Namespace, c[i+1].Namespace) {
				return ErrInvalidChain
			}
		}
		if time.Now().After(c[i].Expiration.Add(time.Minute)) {
			return ErrInvalidChain
		}

		if a.checkRevocationList(c[i].Grantee) {
			return ErrLinkRevocation
		}
	}

	rootLink := c[len(c)-1]
	root := string(rootLink.Grantee[:])
	rootNS, rootOk := a.Authorities[root]
	if !rootOk {
		return ErrRootUnverified
	}
	if !strings.HasPrefix(rootLink.Namespace, rootNS) {
		return ErrRootUnverified
	}

	return nil
}
