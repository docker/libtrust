package libtrust

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math/big"
)

func NewRsaID() (*RsaID, error) {
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return &RsaID{k, &k.PublicKey}, nil
}

type RsaID struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

func (id *RsaID) String() string {
	return id.public.N.String()
}

func (id *RsaID) Sign(src io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, id.private, crypto.SHA256, h.Sum(nil))
}

func (id *RsaID) CanSign() bool {
	return id.private != nil
}

func (id *RsaID) Verify(src io.Reader, signature []byte) error {
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(id.public, crypto.SHA256, h.Sum(nil), signature)
}

func (id *RsaID) JSONWebKey() map[string]interface{} {
	e := make([]byte, 8)
	n := binary.PutUvarint(e, uint64(id.public.E))
	e = e[:n]

	return map[string]interface{}{
		"kty": "RSA",
		"n":   Base64UrlEncode(id.public.N.Bytes()),
		"e":   Base64UrlEncode(e),
	}
}

func (id *RsaID) Export() string {
	bin := x509.MarshalPKCS1PrivateKey(id.private)
	return base64.StdEncoding.EncodeToString(bin)
}

func ImportRsaID(b64 string) (*RsaID, error) {

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS1PrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &RsaID{k, &k.PublicKey}, nil
}

func parseRSAJWK(jwk map[string]interface{}) (*RsaID, error) {
	pk := new(rsa.PublicKey)

	if e, ok := jwk["e"]; ok {
		eString, ok := e.(string)
		if !ok {
			return nil, ErrIllegalJWKFormat
		}
		eBytes, err := Base64UrlDecode(eString)
		if err != nil {
			return nil, err
		}
		e64, n := binary.Uvarint(eBytes)
		if n > 4 {
			return nil, ErrIllegalJWKFormat
		}
		pk.E = int(e64)
	} else {
		return nil, ErrIllegalJWKFormat
	}

	if n, ok := jwk["n"]; ok {
		nString, ok := n.(string)
		if !ok {
			return nil, ErrIllegalJWKFormat
		}
		nBytes, err := Base64UrlDecode(nString)
		if err != nil {
			return nil, err
		}

		pk.N = new(big.Int)
		pk.N.SetBytes(nBytes)
	}

	return &RsaID{public: pk}, nil
}
