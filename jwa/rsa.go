package jwa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

/*
 * RSA DSA PUBLIC KEY
 */

// rsaPublicKey implements a JWK Public Key using RSA digital signature algorithms.
type rsaPublicKey struct {
	*rsa.PublicKey
}

// Kty returns the JWK key type for RSA keys, i.e., "RSA".
func (k *rsaPublicKey) Kty() string {
	return "RSA"
}

// Kid returns a distinct identifier which is unique to this Public Key.
func (k *rsaPublicKey) Kid() string {
	// Generate and return a 'libtrust' fingerprint of the RSA public key.
	// For an RSA key this should be:
	//   SHA256("RSA"+bytes(N)+bytes(E))
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(k.Kty()))
	hasher.Write(k.N.Bytes())
	hasher.Write(serializeRSAPublicExponentParam(k.E))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

// Verify verifyies the signature of the data in the io.Reader using this Public Key.
// The alg parameter should be the name of the JWA digital signature algorithm
// which was used to produce the signature and should be supported by this
// public key. Returns a nil error if the signature is valid.
func (k *rsaPublicKey) Verify(data io.Reader, alg, sigBase64Url string) error {
	// Verify the signature of the given date, return non-nil error if valid.
	sigAlg, err := rsaSignatureAlgorithmByName(alg)
	if err != nil {
		return fmt.Errorf("unable to verify Signature: %s", err)
	}

	signature, err := base64.URLEncoding.DecodeString(sigBase64Url)
	if err != nil {
		return fmt.Errorf("invalid base64 URL encoded signature: %s", err)
	}

	hasher := sigAlg.HashID().New()
	_, err = io.Copy(hasher, data)
	if err != nil {
		return fmt.Errorf("error reading data to sign: %s", err)
	}
	hash := hasher.Sum(nil)

	err = rsa.VerifyPKCS1v15(k.PublicKey, sigAlg.HashID(), hash, signature)
	if err != nil {
		return fmt.Errorf("invalid %s signature: %s", sigAlg.HeaderParam(), err)
	}

	return nil
}

func (k *rsaPublicKey) toMap() map[string]interface{} {
	jwk := make(map[string]interface{})
	jwk["kty"] = k.Kty()
	jwk["kid"] = k.Kid()
	jwk["n"] = base64.URLEncoding.EncodeToString(k.N.Bytes())
	jwk["e"] = base64.URLEncoding.EncodeToString(serializeRSAPublicExponentParam(k.E))

	return jwk
}

// MarshalJSON serializes this Public Key using the JWK JSON serialization format for
// RSA keys.
func (k *rsaPublicKey) MarshalJSON() (data []byte, err error) {
	return json.Marshal(k.toMap())
}

func rsaPublicKeyFromMap(jwk map[string]interface{}) (*rsaPublicKey, error) {
	// JWK key type (kty) has already been determined to be "RSA".
	// Need to extract 'n', 'e', and 'kid' and check for
	// consistency.

	// Get the modulus parameter N.
	nB64Url, err := stringFromMap(jwk, "n")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	n, err := parseRSAModulusParam(nB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key modulus: %s", err)
	}

	// Get the public exponent E.
	eB64Url, err := stringFromMap(jwk, "e")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	e, err := parseRSAPublicExponentParam(eB64Url)
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Public Key exponent: %s", err)
	}

	key := &rsaPublicKey{
		PublicKey: &rsa.PublicKey{N: n, E: e},
	}

	// Key ID is optional, but if it exists, it should match the key.
	_, ok := jwk["kid"]
	if ok {
		kid, err := stringFromMap(jwk, "kid")
		if err != nil {
			return nil, fmt.Errorf("JWK RSA Public Key ID: %s", err)
		}
		if kid != key.Kid() {
			return nil, fmt.Errorf("JWK RSA Public Key ID does not match: %s", kid)
		}
	}

	return key, nil
}

/*
 * RSA DSA PRIVATE KEY
 */

// rsaPrivateKey implements a JWK Private Key using RSA digital signature algorithms.
type rsaPrivateKey struct {
	rsaPublicKey
	*rsa.PrivateKey
}

// PublicKey returns the Public Key data associated with this Private Key.
func (k *rsaPrivateKey) PublicKey() PublicKey {
	return &k.rsaPublicKey
}

// Sign signs the data read from the io.Reader using a signature algorithm supported
// by the RSA private key. If the specified hashing algorithm is supported by
// this key, that hash function is used to generate the signature otherwise the
// the default hashing algorithm for this key is used. Returns the signature
// and the name of the JWK signature algorithm used, e.g., "RS256", "RS384",
// "RS512".
func (k *rsaPrivateKey) Sign(data io.Reader, hashID crypto.Hash) (sigBase64Url, alg string, err error) {
	// Generate a signature of the data using the internal alg.
	sigAlg := rsaPKCS1v15SignatureAlgorithmForHashID(hashID)
	hasher := sigAlg.HashID().New()

	_, err = io.Copy(hasher, data)
	if err != nil {
		return "", "", fmt.Errorf("error reading data to sign: %s", err)
	}
	hash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, sigAlg.HashID(), hash)
	if err != nil {
		return "", "", fmt.Errorf("error producing signature: %s", err)
	}

	sigBase64Url = base64.URLEncoding.EncodeToString(signature)
	alg = sigAlg.HeaderParam()

	return
}

func (k *rsaPrivateKey) toMap() map[string]interface{} {
	k.Precompute() // Make sure the precomputed values are stored.
	jwk := k.rsaPublicKey.toMap()

	jwk["d"] = base64.URLEncoding.EncodeToString(k.D.Bytes())
	jwk["p"] = base64.URLEncoding.EncodeToString(k.Primes[0].Bytes())
	jwk["q"] = base64.URLEncoding.EncodeToString(k.Primes[1].Bytes())
	jwk["dp"] = base64.URLEncoding.EncodeToString(k.Precomputed.Dp.Bytes())
	jwk["dq"] = base64.URLEncoding.EncodeToString(k.Precomputed.Dq.Bytes())
	jwk["qi"] = base64.URLEncoding.EncodeToString(k.Precomputed.Qinv.Bytes())

	otherPrimes := k.Primes[2:]

	if len(otherPrimes) > 0 {
		otherPrimesInfo := make([]interface{}, len(otherPrimes))
		for i, r := range otherPrimes {
			otherPrimeInfo := make(map[string]string, 3)
			otherPrimeInfo["r"] = base64.URLEncoding.EncodeToString(r.Bytes())
			crtVal := k.Precomputed.CRTValues[i]
			otherPrimeInfo["d"] = base64.URLEncoding.EncodeToString(crtVal.Exp.Bytes())
			otherPrimeInfo["t"] = base64.URLEncoding.EncodeToString(crtVal.Coeff.Bytes())
			otherPrimesInfo[i] = otherPrimeInfo
		}
		jwk["oth"] = otherPrimesInfo
	}

	return jwk
}

// MarshalJSON serializes this Private Key using the JWK JSON serialization format for
// RSA keys.
func (k *rsaPrivateKey) MarshalJSON() (data []byte, err error) {
	return json.Marshal(k.toMap())
}

func rsaPrivateKeyFromMap(jwk map[string]interface{}) (*rsaPrivateKey, error) {
	// JWK key type (kty) has already been determined to be "RSA".
	// Need to extract the public key information, then extract the private
	// key values.
	publicKey, err := rsaPublicKeyFromMap(jwk)
	if err != nil {
		return nil, err
	}

	// The JWA spec for RSA Private Keys (draft rfc section 5.3.2) states that
	// only the private key exponent 'd' is REQUIRED, the others are just for
	// signature/decryption optimizations and SHOULD be included when the JWK
	// is produced. We MAY choose to accept a JWK which only includes 'd', but
	// we're going to go ahead and not choose to accept it without the extra
	// fields. Only the 'oth' field will be optional (for multi-prime keys).
	privateExponent, err := parseRSAPrivateKeyParamFromMap(jwk, "d")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key exponent: %s", err)
	}
	firstPrimeFactor, err := parseRSAPrivateKeyParamFromMap(jwk, "p")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
	}
	secondPrimeFactor, err := parseRSAPrivateKeyParamFromMap(jwk, "q")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
	}
	firstFactorCRT, err := parseRSAPrivateKeyParamFromMap(jwk, "dp")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
	}
	secondFactorCRT, err := parseRSAPrivateKeyParamFromMap(jwk, "dq")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
	}
	crtCoeff, err := parseRSAPrivateKeyParamFromMap(jwk, "qi")
	if err != nil {
		return nil, fmt.Errorf("JWK RSA Private Key CRT coefficient: %s", err)
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: *publicKey.PublicKey,
		D:         privateExponent,
		Primes:    []*big.Int{firstPrimeFactor, secondPrimeFactor},
		Precomputed: rsa.PrecomputedValues{
			Dp:   firstFactorCRT,
			Dq:   secondFactorCRT,
			Qinv: crtCoeff,
		},
	}

	if _, ok := jwk["oth"]; ok {
		// Should be an array of more JSON objects.
		otherPrimesInfo, ok := jwk["oth"].([]interface{})
		if !ok {
			return nil, errors.New("JWK RSA Private Key: Invalid other primes info: must be an array")
		}
		numOtherPrimeFactors := len(otherPrimesInfo)
		if numOtherPrimeFactors == 0 {
			return nil, errors.New("JWK RSA Privake Key: Invalid other primes info: must be absent or non-empty")
		}
		otherPrimeFactors := make([]*big.Int, numOtherPrimeFactors)
		productOfPrimes := new(big.Int).Mul(firstPrimeFactor, secondPrimeFactor)
		crtValues := make([]rsa.CRTValue, numOtherPrimeFactors)

		for i, val := range otherPrimesInfo {
			otherPrimeinfo, ok := val.(map[string]interface{})
			if !ok {
				return nil, errors.New("JWK RSA Private Key: Invalid other prime info: must be a JSON object")
			}

			otherPrimeFactor, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "r")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key prime factor: %s", err)
			}
			otherFactorCRT, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "d")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key CRT exponent: %s", err)
			}
			otherCrtCoeff, err := parseRSAPrivateKeyParamFromMap(otherPrimeinfo, "t")
			if err != nil {
				return nil, fmt.Errorf("JWK RSA Private Key CRT coefficient: %s", err)
			}

			crtValue := crtValues[i]
			crtValue.Exp = otherFactorCRT
			crtValue.Coeff = otherCrtCoeff
			crtValue.R = productOfPrimes
			otherPrimeFactors[i] = otherPrimeFactor
			productOfPrimes = new(big.Int).Mul(productOfPrimes, otherPrimeFactor)
		}

		privateKey.Primes = append(privateKey.Primes, otherPrimeFactors...)
		privateKey.Precomputed.CRTValues = crtValues
	}

	key := &rsaPrivateKey{
		rsaPublicKey: *publicKey,
		PrivateKey:   privateKey,
	}

	return key, nil
}

/*
 *	Key Generation Functions.
 */

func generateRSAPrivateKey(bits int) (k *rsaPrivateKey, err error) {
	k = new(rsaPrivateKey)
	k.PrivateKey, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}

	k.rsaPublicKey.PublicKey = &k.PrivateKey.PublicKey

	return
}

// GenerateRSA2048PrivateKey generates a JWK key pair using 2048-bit RSA.
func GenerateRSA2048PrivateKey() (PrivateKey, error) {
	k, err := generateRSAPrivateKey(2048)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA 2048-bit key: %s", err)
	}

	return k, nil
}

// GenerateRSA3072PrivateKey generates a JWK key pair using 3072-bit RSA.
func GenerateRSA3072PrivateKey() (PrivateKey, error) {
	k, err := generateRSAPrivateKey(3072)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA 3072-bit key: %s", err)
	}

	return k, nil
}

// GenerateRSA4096PrivateKey generates a JWK key pair using 4096-bit RSA.
func GenerateRSA4096PrivateKey() (PrivateKey, error) {
	k, err := generateRSAPrivateKey(4096)
	if err != nil {
		return nil, fmt.Errorf("error generating RSA 4096-bit key: %s", err)
	}

	return k, nil
}
