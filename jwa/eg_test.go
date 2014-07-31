package jwa

import (
	"bytes"
	"encoding/json"
	"testing"
)

func generateECTestKeys(t *testing.T) []PrivateKey {
	p256Key, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	p384Key, err := GenerateECP384PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	p521Key, err := GenerateECP521PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	return []PrivateKey{p256Key, p384Key, p521Key}
}

func TestECKeys(t *testing.T) {

	ecKeys := generateECTestKeys(t)

	for _, ecKey := range ecKeys {
		if ecKey.Kty() != "EC" {
			t.Fatalf("key type must be %q, instead got %q", "EC", ecKey.Kty())
		}
	}
}

func TestECSignVerify(t *testing.T) {
	ecKeys := generateECTestKeys(t)

	message := "Hello, World!"
	data := bytes.NewReader([]byte(message))

	sigAlgs := []*signatureAlgorithm{es256, es384, es512}

	for i, ecKey := range ecKeys {
		sigAlg := sigAlgs[i]

		t.Logf("%s signature of %q with kid: %s\n", sigAlg.HeaderParam(), message, ecKey.Kid())

		data.Seek(0, 0) // Reset the byte reader

		// Sign
		sig, alg, err := ecKey.Sign(data, sigAlg.HashID())
		if err != nil {
			t.Fatal(err)
		}

		data.Seek(0, 0) // Reset the byte reader

		// Verify
		err = ecKey.Verify(data, alg, sig)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestMarshalUnmarshalECKeys(t *testing.T) {
	ecKeys := generateECTestKeys(t)
	data := bytes.NewReader([]byte("This is a test. I repeat: this is only a test."))
	sigAlgs := []*signatureAlgorithm{es256, es384, es512}

	for i, ecKey := range ecKeys {
		sigAlg := sigAlgs[i]
		privateJWKJSON, err := json.MarshalIndent(ecKey, "", "    ")
		if err != nil {
			t.Fatal(err)
		}

		publicJWKJSON, err := json.MarshalIndent(ecKey.PublicKey(), "", "    ")
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
	}
}
