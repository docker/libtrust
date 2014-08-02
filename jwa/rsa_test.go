package jwa

import (
	"bytes"
	"encoding/json"
	"log"
	"testing"
)

var rsaKeys []PrivateKey

func init() {
	var err error
	rsaKeys, err = generateRSATestKeys()
	if err != nil {
		log.Fatal(err)
	}
}

func generateRSATestKeys() (keys []PrivateKey, err error) {
	rsa2048Key, err := GenerateRSA2048PrivateKey()
	if err != nil {
		return
	}

	rsa3072Key, err := GenerateRSA3072PrivateKey()
	if err != nil {
		return
	}

	rsa4096Key, err := GenerateRSA4096PrivateKey()
	if err != nil {
		return
	}

	keys = []PrivateKey{rsa2048Key, rsa3072Key, rsa4096Key}

	return
}

func TestRSAKeys(t *testing.T) {
	for _, rsaKey := range rsaKeys {
		if rsaKey.KeyType() != "RSA" {
			t.Fatalf("key type must be %q, instead got %q", "RSA", rsaKey.KeyType())
		}
	}
}

func TestRSASignVerify(t *testing.T) {
	message := "Hello, World!"
	data := bytes.NewReader([]byte(message))

	sigAlgs := []*signatureAlgorithm{rs256, rs384, rs512}

	for i, rsaKey := range rsaKeys {
		sigAlg := sigAlgs[i]

		t.Logf("%s signature of %q with kid: %s\n", sigAlg.HeaderParam(), message, rsaKey.KeyID())

		data.Seek(0, 0) // Reset the byte reader

		// Sign
		sig, alg, err := rsaKey.Sign(data, sigAlg.HashID())
		if err != nil {
			t.Fatal(err)
		}

		data.Seek(0, 0) // Reset the byte reader

		// Verify
		err = rsaKey.Verify(data, alg, sig)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMarshalUnmarshalRSAKeys(t *testing.T) {
	data := bytes.NewReader([]byte("This is a test. I repeat: this is only a test."))
	sigAlgs := []*signatureAlgorithm{rs256, rs384, rs512}

	for i, rsaKey := range rsaKeys {
		sigAlg := sigAlgs[i]
		privateJWKJSON, err := json.MarshalIndent(rsaKey, "", "    ")
		if err != nil {
			t.Fatal(err)
		}

		publicJWKJSON, err := json.MarshalIndent(rsaKey.PublicKey(), "", "    ")
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("JWK Private Key: %s", string(privateJWKJSON))
		t.Logf("JWK Public Key: %s", string(publicJWKJSON))

		privKey2, err := UnmarshalPrivateKeyJSON(privateJWKJSON)
		if err != nil {
			t.Fatal(err)
		}

		pubKey2, err := UnmarshalPublicKeyJSON(publicJWKJSON)
		if err != nil {
			t.Fatal(err)
		}

		// Ensure we can sign/verify a message with the unmarshalled keys.
		data.Seek(0, 0) // Reset the byte reader
		signature, alg, err := privKey2.Sign(data, sigAlg.HashID())
		if err != nil {
			t.Fatal(err)
		}

		data.Seek(0, 0) // Reset the byte reader
		err = pubKey2.Verify(data, alg, signature)
		if err != nil {
			t.Fatal(err)
		}

		// It's a good idea to validate the Private Key to make sure our
		// (un)marshal process didn't corrupt the extra parameters.
		k := privKey2.(*rsaPrivateKey)
		err = k.PrivateKey.Validate()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestRSAGeneratePEMCertKeyPair(t *testing.T) {
	for _, rsaKey := range rsaKeys {
		certPEM, keyPEM, err := rsaKey.GeneratePEMCertKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Certificate:\n%s\n", string(certPEM))
		t.Logf("Private Key:\n%s\n", string(keyPEM))
	}
}
