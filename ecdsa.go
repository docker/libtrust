package libtrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
)

func NewEcdsaID() (*EcdsaID, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EcdsaID{k, &k.PublicKey}, nil
}

type EcdsaID struct {
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func (id *EcdsaID) String() string {
	return id.public.X.String()
}

func (id *EcdsaID) Sign(src io.Reader) ([]byte, error) {
	h := sha256.New() // TODO If not P256 use sha512
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, id.private, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	byteLen := (id.public.Curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 2*byteLen)
	rBytes := r.Bytes()
	copy(ret[byteLen-len(rBytes):], rBytes)
	sBytes := s.Bytes()
	copy(ret[2*byteLen-len(sBytes):], sBytes)
	return ret, nil
}

func (id *EcdsaID) CanSign() bool {
	return id.private != nil
}

func (id *EcdsaID) Verify(src io.Reader, signature []byte) error {
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		return err
	}

	byteLen := (id.public.Curve.Params().BitSize + 7) >> 3
	if len(signature) != 2*byteLen {
		return ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(signature[:byteLen])
	s := new(big.Int).SetBytes(signature[byteLen:])

	if !ecdsa.Verify(id.public, h.Sum(nil), r, s) {
		return ErrInvalidSignature
	}

	return nil
}

func (id *EcdsaID) JSONWebKey() map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   Base64UrlEncode(id.public.X.Bytes()),
		"y":   Base64UrlEncode(id.public.Y.Bytes()),
	}
}

func (id *EcdsaID) Export() string {
	bin, err := x509.MarshalECPrivateKey(id.private)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(bin)
}

func ImportEcdsaID(b64 string) (*EcdsaID, error) {

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return &EcdsaID{k, &k.PublicKey}, nil
}

func parseECJWK(jwk map[string]interface{}) (*EcdsaID, error) {
	pk := new(ecdsa.PublicKey)
	if crv, ok := jwk["crv"]; ok {
		switch crv {
		case "P-256":
			pk.Curve = elliptic.P256()
		default:
			return nil, ErrUnsupportedAlgorithm
		}
	} else {
		return nil, ErrIllegalJWKFormat
	}

	if x, ok := jwk["x"]; ok {
		xString, ok := x.(string)
		if !ok {
			return nil, ErrIllegalJWKFormat
		}
		xBytes, err := Base64UrlDecode(xString)
		if err != nil {
			return nil, err
		}

		pk.X = new(big.Int)
		pk.X.SetBytes(xBytes)
	} else {
		return nil, ErrIllegalJWKFormat
	}

	if y, ok := jwk["y"]; ok {
		yString, ok := y.(string)
		if !ok {
			return nil, ErrIllegalJWKFormat
		}
		yBytes, err := Base64UrlDecode(yString)
		if err != nil {
			return nil, err
		}

		pk.Y = new(big.Int)
		pk.Y.SetBytes(yBytes)
	} else {
		return nil, ErrIllegalJWKFormat
	}

	return &EcdsaID{public: pk}, nil
}
