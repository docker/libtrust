package libtrust

import (
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha512"
	"io"
)

type Id interface {
	String() string
	Sign(io.Reader) ([]byte, error)
}

func NewId() (Id, error) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return &RsaId{k}, nil
}

type RsaId struct {
	k	*rsa.PrivateKey
}

func (id *RsaId) String() string {
	// FIXME
	return "public key as a string"
}

func (id *RsaId) Sign(src io.Reader) ([]byte, error) {
	h := sha512.New()
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, id.k, crypto.SHA512, h.Sum(nil))
}

