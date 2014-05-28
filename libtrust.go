package libtrust

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"io"
)

type Id interface {
	String() string
	Sign(io.Reader) ([]byte, error)
}

func NewId() (*RsaId, error) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return &RsaId{k}, nil
}

type RsaId struct {
	k *rsa.PrivateKey
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

func (id *RsaId) Export() string {
	bin := x509.MarshalPKCS1PrivateKey(id.k)
	return base64.StdEncoding.EncodeToString(bin)
}

func ImportId(b64 string) (*RsaId, error) {

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &RsaId{k}, nil
}
