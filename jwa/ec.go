package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

/*
 * EC DSA PUBLIC KEY
 */

// ecPublicKey implements a JWK Public Key using elliptic curve digital signature
// algorithms.
type ecPublicKey struct {
	*ecdsa.PublicKey
	curveName          string
	signatureAlgorithm *signatureAlgorithm
}

// KeyType returns the JWK key type for elliptic curve keys, i.e., "EC".
func (k *ecPublicKey) KeyType() string {
	return "EC"
}

// Crv returns the JWK elliptic curve identifier.
// Possible values are "P-256", "P-384", and "P-521".
func (k *ecPublicKey) CurveName() string {
	return k.curveName
}

// KeyID returns a distinct identifier which is unique to this Public Key.
func (k *ecPublicKey) KeyID() string {
	// Generate and return a 'libtrust' fingerprint of the EC public key.
	// For an EC key this should be:
	//   SHA256("EC"+curveName+bytes(X)+bytes(Y))
	// Then truncated to 240 bits and encoded into 12 base32 groups like so:
	//   ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(k.KeyType() + k.CurveName()))
	hasher.Write(k.X.Bytes())
	hasher.Write(k.Y.Bytes())
	return keyIDEncode(hasher.Sum(nil)[:30])
}

// Verify verifyies the signature of the data in the io.Reader using this Public Key.
// The alg parameter should be the name of the JWA digital signature algorithm
// which was used to produce the signature and should be supported by this
// public key. Returns a nil error if the signature is valid.
func (k *ecPublicKey) Verify(data io.Reader, alg string, signature []byte) error {
	// For EC keys there is only one supported signature algorithm depending
	// on the curve parameters.
	if k.signatureAlgorithm.HeaderParam() != alg {
		return fmt.Errorf("unable to verify signature: JWK EC Public Key with curve %q does not support signature algorithm %q", k.curveName, alg)
	}

	// signature is the concatenation of (r, s), base64Url encoded.
	sigLength := len(signature)
	expectedOctetLength := 2 * ((k.Params().BitSize + 7) >> 3)
	if sigLength != expectedOctetLength {
		return fmt.Errorf("signature length is %d octets long, should be %d", sigLength, expectedOctetLength)
	}

	rBytes, sBytes := signature[:sigLength/2], signature[sigLength/2:]
	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)

	hasher := k.signatureAlgorithm.HashID().New()
	_, err := io.Copy(hasher, data)
	if err != nil {
		return fmt.Errorf("error reading data to sign: %s", err)
	}
	hash := hasher.Sum(nil)

	if !ecdsa.Verify(k.PublicKey, hash, r, s) {
		return errors.New("invalid signature")
	}

	return nil
}

// CryptoPublicKey returns the internal object which can be used as a
// crypto.PublicKey for use with other standard library operations. The type
// is either *rsa.PublicKey or *ecdsa.PublicKey
func (k *ecPublicKey) CryptoPublicKey() crypto.PublicKey {
	return k.PublicKey
}

func (k *ecPublicKey) toMap() map[string]interface{} {
	jwk := make(map[string]interface{})
	jwk["kty"] = k.KeyType()
	jwk["kid"] = k.KeyID()
	jwk["crv"] = k.CurveName()

	xBytes := k.X.Bytes()
	yBytes := k.Y.Bytes()
	octetLength := (k.Params().BitSize + 7) >> 3
	// MUST include leading zeros in the output so that x, y are each
	// *octetLength* bytes long.
	xBuf := make([]byte, octetLength-len(xBytes), octetLength)
	yBuf := make([]byte, octetLength-len(yBytes), octetLength)
	xBuf = append(xBuf, xBytes...)
	yBuf = append(yBuf, yBytes...)

	jwk["x"] = JOSEBase64UrlEncode(xBuf)
	jwk["y"] = JOSEBase64UrlEncode(yBuf)

	return jwk
}

// MarshalJSON serializes this Public Key using the JWK JSON serialization format for
// elliptic curve keys.
func (k *ecPublicKey) MarshalJSON() (data []byte, err error) {
	return json.Marshal(k.toMap())
}

func ecPublicKeyFromMap(jwk map[string]interface{}) (*ecPublicKey, error) {
	// JWK key type (kty) has already been determined to be "EC".
	// Need to extract 'crv', 'x', 'y', and 'kid' and check for
	// consistency.

	// Get the curve identifier value.
	crv, err := stringFromMap(jwk, "crv")
	if err != nil {
		return nil, fmt.Errorf("JWK EC Public Key curve identifier: %s", err)
	}

	var (
		curve  elliptic.Curve
		sigAlg *signatureAlgorithm
	)

	switch {
	case crv == "P-256":
		curve = elliptic.P256()
		sigAlg = es256
	case crv == "P-384":
		curve = elliptic.P384()
		sigAlg = es384
	case crv == "P-521":
		curve = elliptic.P521()
		sigAlg = es512
	default:
		return nil, fmt.Errorf("JWK EC Public Key curve identifier not supported: %q\n", crv)
	}

	// Get the X and Y coordinates for the public key point.
	xB64Url, err := stringFromMap(jwk, "x")
	if err != nil {
		return nil, fmt.Errorf("JWK EC Public Key x-coordinate: %s", err)
	}
	x, err := parseECCoordinate(xB64Url, curve)
	if err != nil {
		return nil, fmt.Errorf("JWK EC Public Key x-coordinate: %s", err)
	}

	yB64Url, err := stringFromMap(jwk, "y")
	if err != nil {
		return nil, fmt.Errorf("JWK EC Public Key y-coordinate: %s", err)
	}
	y, err := parseECCoordinate(yB64Url, curve)
	if err != nil {
		return nil, fmt.Errorf("JWK EC Public Key y-coordinate: %s", err)
	}

	key := &ecPublicKey{
		PublicKey: &ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		curveName: crv, signatureAlgorithm: sigAlg,
	}

	// Key ID is optional too, but if it exists, it should match the key.
	_, ok := jwk["kid"]
	if ok {
		kid, err := stringFromMap(jwk, "kid")
		if err != nil {
			return nil, fmt.Errorf("JWK EC Public Key ID: %s", err)
		}
		if kid != key.KeyID() {
			return nil, fmt.Errorf("JWK EC Public Key ID does not match: %s", kid)
		}
	}

	return key, nil
}

/*
 * EC DSA PRIVATE KEY
 */

// ecPrivateKey implements a JWK Private Key using elliptic curve digital signature
// algorithms.
type ecPrivateKey struct {
	ecPublicKey
	*ecdsa.PrivateKey
}

// PublicKey returns the Public Key data associated with this Private Key.
func (k *ecPrivateKey) PublicKey() PublicKey {
	return &k.ecPublicKey
}

// Sign signs the data read from the io.Reader using a signature algorithm supported
// by the elliptic curve private key. If the specified hashing algorithm is
// supported by this key, that hash function is used to generate the signature
// otherwise the the default hashing algorithm for this key is used. Returns
// the signature and the name of the JWK signature algorithm used, e.g.,
// "ES256", "ES384", "ES512".
func (k *ecPrivateKey) Sign(data io.Reader, hashID crypto.Hash) (signature []byte, alg string, err error) {
	// Generate a signature of the data using the internal alg.
	// The given hashId is only a suggestion, and since EC keys only support
	// on signature/hash algorithm given the curve name, we disregard it for
	// the elliptic curve JWK signature implementation.
	hasher := k.signatureAlgorithm.HashID().New()
	_, err = io.Copy(hasher, data)
	if err != nil {
		return nil, "", fmt.Errorf("error reading data to sign: %s", err)
	}
	hash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, hash)
	if err != nil {
		return nil, "", fmt.Errorf("error producing signature: %s", err)
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	octetLength := (k.ecPublicKey.Params().BitSize + 7) >> 3
	// MUST include leading zeros in the output
	rBuf := make([]byte, octetLength-len(rBytes), octetLength)
	sBuf := make([]byte, octetLength-len(sBytes), octetLength)

	rBuf = append(rBuf, rBytes...)
	sBuf = append(sBuf, sBytes...)

	signature = append(rBuf, sBuf...)
	alg = k.signatureAlgorithm.HeaderParam()

	return
}

// CryptoPrivateKey returns the internal object which can be used as a
// crypto.PublicKey for use with other standard library operations. The type
// is either *rsa.PublicKey or *ecdsa.PublicKey
func (k *ecPrivateKey) CryptoPrivateKey() crypto.PrivateKey {
	return k.PrivateKey
}

// GeneratePEMKey generates a PEM encoded block of a the internal private key
// for use as an X509 key pair suitable for TLS and other functions.
func (k *ecPrivateKey) GeneratePEMKey() (key []byte, err error) {
	return generatePEMPrivateKey(k)
}

// GeneratePEMCert generates a PEM encoded block of a certificate with
// this key as the issuer and the given public key as the subject. Using this
// key as the argument generates a self-signed certificate.
func (k *ecPrivateKey) GeneratePEMCert(pub PublicKey) (cert []byte, err error) {
	return generateKeyIDPEMCert(pub, k)
}

func (k *ecPrivateKey) toMap() map[string]interface{} {
	jwk := k.ecPublicKey.toMap()

	dBytes := k.D.Bytes()
	// The length of this octet string MUST be ceiling(log-base-2(n)/8)
	// octets (where n is the order of the curve). This is because the private
	// key d must be in the interval [1, n-1] so the bitlength of d should be
	// no larger than the bitlength of n-1. The easiest way to find the octet
	// length is to take bitlength(n-1), add 7 to force a carry, and shift this
	// bit sequence right by 3, which is essentially dividing by 8 and adding
	// 1 if there is any remainder. Thus, the private key value d should be
	// output to (bitlength(n-1)+7)>>3 octets.
	n := k.ecPublicKey.Params().N
	octetLength := (new(big.Int).Sub(n, big.NewInt(1)).BitLen() + 7) >> 3
	// Create a buffer with the necessary zero-padding.
	dBuf := make([]byte, octetLength-len(dBytes), octetLength)
	dBuf = append(dBuf, dBytes...)

	jwk["d"] = JOSEBase64UrlEncode(dBuf)

	return jwk
}

// MarshalJSON serializes this Private Key using the JWK JSON serialization format for
// elliptic curve keys.
func (k *ecPrivateKey) MarshalJSON() (data []byte, err error) {
	return json.Marshal(k.toMap())
}

func ecPrivateKeyFromMap(jwk map[string]interface{}) (*ecPrivateKey, error) {
	// JWK key type (kty) has already been determined to be "EC".
	// Need to extract the public key information, then extract the private
	// key value 'd'.
	publicKey, err := ecPublicKeyFromMap(jwk)
	if err != nil {
		return nil, err
	}

	dB64Url, err := stringFromMap(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("JWK EC Private Key: %s", err)
	}

	d, err := parseECPrivateParam(dB64Url, publicKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("JWK EC Private Key d-param: %s", err)
	}

	key := &ecPrivateKey{
		ecPublicKey: *publicKey,
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: *publicKey.PublicKey,
			D:         d,
		},
	}

	return key, nil
}

/*
 *	Key Generation Functions.
 */

func generateECPrivateKey(curve elliptic.Curve) (k *ecPrivateKey, err error) {
	k = new(ecPrivateKey)
	k.PrivateKey, err = ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}

	k.ecPublicKey.PublicKey = &k.PrivateKey.PublicKey

	return
}

// GenerateECP256PrivateKey generates a JWK key pair using elliptic curve P-256. It is configured to
// generate signatures using the JWA "ES256" digital signature algorithm.
func GenerateECP256PrivateKey() (PrivateKey, error) {
	k, err := generateECPrivateKey(elliptic.P256())
	if err != nil {
		return nil, fmt.Errorf("error generating EC P-256 key: %s", err)
	}

	k.curveName = "P-256"
	k.signatureAlgorithm = es256

	return k, nil
}

// GenerateECP384PrivateKey generates a JWK key pair using elliptic curve P-384. It is configured to
// generate signatures using the JWA "ES384" digital signature algorithm.
func GenerateECP384PrivateKey() (PrivateKey, error) {
	k, err := generateECPrivateKey(elliptic.P384())
	if err != nil {
		return nil, fmt.Errorf("error generating EC P-384 key: %s", err)
	}

	k.curveName = "P-384"
	k.signatureAlgorithm = es384

	return k, nil
}

// GenerateECP521PrivateKey generates a JWK key pair using elliptic curve P-521. It is configured to
// generate signatures using the JWA "ES512" digital signature algorithm.
func GenerateECP521PrivateKey() (PrivateKey, error) {
	k, err := generateECPrivateKey(elliptic.P521())
	if err != nil {
		return nil, fmt.Errorf("error generating EC P-521 key: %s", err)
	}

	k.curveName = "P-521"
	k.signatureAlgorithm = es512

	return k, nil
}
