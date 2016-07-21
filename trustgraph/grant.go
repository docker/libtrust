package trustgraph

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/docker/libtrust"
)

// Grant represents a transfer of permission from one part of the
// trust graph to another. This is the only way to delegate
// permission between two different sub trees in the graph.
type Grant struct {
	// Subject is the namespace being granted
	Subject string

	// Verbs is an array of allowed actions.
	Scopes []string

	// Delegated is a flag to determine whether the scopes
	// may be further granted by grantee to the subject.
	Delegated bool

	// Revoked is a flag to determine whether the scopes
	// and delegation is revoked, taking precedence over
	// previously generated grants.
	Revoked bool

	// Grantee represents the node being granted
	// a permission scope.  The grantee can be
	// either a namespace item or a key id where namespace
	// items will always start with a '/'.
	Grantee string

	// Expiration represents the latest time in which a grant
	// may be considered valid. The grant may be used after
	// this date but a warning should be issued since a
	// revocation which negated may have been cleaned up
	// since.
	Expiration time.Time

	// IssuedAt is the time at which the grant was issued.
	// This date should be used to resolve conflicts between
	// grants.
	IssuedAt time.Time

	// statement represents the statement used to create
	// this object.
	statement *Statement

	// Signature
	signature *libtrust.JSONSignature `json:"-"`
}

func LoadGrant(b []byte) (*Grant, error) {
	sig, err := libtrust.ParseJWS(b)
	if err != nil {
		return nil, err
	}
	g := new(Grant)
	if payload, err := sig.Payload(); err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(payload, g); err != nil {
			return nil, err
		}
	}
	g.signature = sig
	return g, nil
}

func NewGrant(subject, grantee string, verbs []string) (*Grant, error) {
	issuedAt := time.Now().UTC()
	return &Grant{
		Subject:    subject,
		Grantee:    grantee,
		Scopes:     verbs,
		IssuedAt:   issuedAt,
		Expiration: issuedAt.Add(time.Hour * 24 * 365),
	}, nil
}

func (g *Grant) getSignature() (*libtrust.JSONSignature, error) {
	// Adds signature
	b, err := json.MarshalIndent(g, "", "   ")
	if err != nil {
		return nil, err
	}

	return libtrust.NewJSONSignature(b)
}

func (g *Grant) Sign(key libtrust.PrivateKey) error {
	sig, err := g.getSignature()
	if err != nil {
		return err
	}

	if err := sig.Sign(key); err != nil {
		return err
	}

	g.signature = sig

	return nil
}

func (g *Grant) SignWithChain(key libtrust.PrivateKey, chain []*x509.Certificate) error {
	sig, err := g.getSignature()
	if err != nil {
		return err
	}

	if err := sig.SignWithChain(key, chain); err != nil {
		return err
	}

	g.signature = sig

	return nil

}

func (g *Grant) Verify() ([]libtrust.PublicKey, error) {
	if g.signature == nil {
		return nil, errors.New("missing signature")
	}
	return g.signature.Verify()
}

func (g *Grant) JWS() ([]byte, error) {
	if g.signature == nil {
		return nil, errors.New("missing signature")
	}

	return g.signature.JWS()
}
