package jwa

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
)

// PublicKey is a generic interface for a JWK Public Key.
type PublicKey interface {
	Kty() string
	Kid() string
	Verify(data io.Reader, alg, sigBase64Url string) error
	json.Marshaler
}

// PrivateKey is a generic interface for a JWK Private Key.
type PrivateKey interface {
	PublicKey
	PublicKey() PublicKey
	Sign(data io.Reader, hashID crypto.Hash) (sigBase64Url, alg string, err error)
}

// UnmarshalPublicKeyJSON unmarshals the given JSON into a generic JWK Public Key
func UnmarshalPublicKeyJSON(data []byte) (PublicKey, error) {
	jwk := make(map[string]interface{})

	err := json.Unmarshal(data, &jwk)
	if err != nil {
		return nil, fmt.Errorf(
			"decoding JWK Public Key JSON data: %s\n", err,
		)
	}

	// Get the Key Type value.
	kty, err := stringFromMap(jwk, "kty")
	if err != nil {
		return nil, fmt.Errorf("JWK Public Key type: %s", err)
	}

	switch {
	case kty == "EC":
		// Call out to unmarshal EC public key.
		return ecPublicKeyFromMap(jwk)
	case kty == "RSA":
		// Call out to unmarshal RSA public key.
		return rsaPublicKeyFromMap(jwk)
	default:
		return nil, fmt.Errorf(
			"JWK Public Key type not supported: %q\n", kty,
		)
	}
}

// UnmarshalPrivateKeyJSON unmarshals the given JSON into a generic JWK Private Key
func UnmarshalPrivateKeyJSON(data []byte) (PrivateKey, error) {
	jwk := make(map[string]interface{})

	err := json.Unmarshal(data, &jwk)
	if err != nil {
		return nil, fmt.Errorf(
			"decoding JWK Private Key JSON data: %s\n", err,
		)
	}

	// Get the Key Type value.
	kty, err := stringFromMap(jwk, "kty")
	if err != nil {
		return nil, fmt.Errorf("JWK Private Key type: %s", err)
	}

	switch {
	case kty == "EC":
		// Call out to unmarshal EC private key.
		return ecPrivateKeyFromMap(jwk)
	case kty == "RSA":
		// Call out to unmarshal RSA private key.
		return rsaPrivateKeyFromMap(jwk)
	default:
		return nil, fmt.Errorf(
			"JWK Private Key type not supported: %q\n", kty,
		)
	}
}
