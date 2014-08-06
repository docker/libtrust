package libtrust

import (
	"errors"
	"io"

	"github.com/docker/libtrust/jwa"
)

var (
	jwaAlgorithms = map[SignatureAlgorithm]string{
		RSA256: "RS256",
		RSA384: "RS384",
		RSA512: "RS512",
		EC256:  "ES256",
		EC384:  "ES384",
		EC512:  "ES512",
	}

	libtrustAlgorithms = map[string]SignatureAlgorithm{
		"RS256": RSA256,
		"RS384": RSA384,
		"RS512": RSA512,
		"ES256": EC256,
		"ES384": EC384,
		"ES512": EC512,
	}
)

type jwaPublicKey struct {
	key jwa.PublicKey
}

type jwaKey struct {
	key jwa.PrivateKey
}

func (k *jwaPublicKey) String() string {
	return k.key.KeyID()
}

func (k *jwaPublicKey) Fingerprint() Fingerprint {
	var fingerprint Fingerprint
	return fingerprint
}

func (k *jwaPublicKey) SupportedAlgorithms() []SignatureAlgorithm {
	// Get list of supported keys

	return []SignatureAlgorithm{}
}

func (k *jwaPublicKey) Verify(io.Reader, []byte, SignatureAlgorithm) error {
	return errors.New("not implemented")
}

func (k *jwaKey) String() string {
	return k.key.KeyID()
}

func (k *jwaKey) Fingerprint() Fingerprint {
	var fingerprint Fingerprint
	return fingerprint
}

func (k *jwaKey) SupportedAlgorithms() []SignatureAlgorithm {
	// Get list of supported keys

	return []SignatureAlgorithm{}
}

func (k *jwaKey) Verify(io.Reader, []byte, SignatureAlgorithm) error {
	//k.key.Verify(data io.Reader, alg string, signature []byte) error
	return errors.New("not implemented")
}

func (k *jwaKey) Sign(io.Reader, SignatureAlgorithm) ([]byte, error) {
	//k.key.Sign(data io.Reader, hashID crypto.Hash) (signature []byte, alg string, err error)
	return nil, errors.New("not implemented")
}

func (k *jwaKey) GenerateX509KeyPair() ([]byte, []byte, error) {
	cert, err := k.key.GeneratePEMCert(k.key.PublicKey(), []string{"localhost"}, nil)
	if err != nil {
		return nil, nil, err
	}
	key, err := k.key.GeneratePEMKey()
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func GenerateJWAKey(alg SignatureAlgorithm) (Key, error) {
	var pk jwa.PrivateKey
	var err error
	switch alg {
	case RSA256:
		pk, err = jwa.GenerateRSA2048PrivateKey()
	case RSA384:
		pk, err = jwa.GenerateRSA3072PrivateKey()
	case RSA512:
		pk, err = jwa.GenerateRSA4096PrivateKey()
	case EC256:
		pk, err = jwa.GenerateECP256PrivateKey()
	case EC384:
		pk, err = jwa.GenerateECP384PrivateKey()
	case EC512:
		pk, err = jwa.GenerateECP521PrivateKey()
	default:
		return nil, ErrUnsupportedAlgorithm
	}
	if err != nil {
		return nil, err
	}

	return &jwaKey{key: pk}, nil
}
