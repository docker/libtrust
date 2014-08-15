package libtrust

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"
)

func makeTempFile(t *testing.T, prefix string) (filename string) {
	file, err := ioutil.TempFile("", prefix)
	if err != nil {
		t.Fatal(err)
	}

	filename = file.Name()
	file.Close()

	return
}

func TestKeyFiles(t *testing.T) {
	key, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	privateKeyFilename := makeTempFile(t, "private_key")
	privateKeyFilenamePEM := privateKeyFilename + ".pem"
	privateKeyFilenameJWK := privateKeyFilename + ".jwk"

	publicKeyFilename := makeTempFile(t, "public_key")
	publicKeyFilenamePEM := publicKeyFilename + ".pem"
	publicKeyFilenameJWK := publicKeyFilename + ".jwk"

	if err = SaveKey(privateKeyFilenamePEM, key); err != nil {
		t.Fatal(err)
	}

	if err = SaveKey(privateKeyFilenameJWK, key); err != nil {
		t.Fatal(err)
	}

	if err = SavePublicKey(publicKeyFilenamePEM, key.PublicKey()); err != nil {
		t.Fatal(err)
	}

	if err = SavePublicKey(publicKeyFilenameJWK, key.PublicKey()); err != nil {
		t.Fatal(err)
	}

	loadedPEMKey, err := LoadKeyFile(privateKeyFilenamePEM)
	if err != nil {
		t.Fatal(err)
	}

	loadedJWKKey, err := LoadKeyFile(privateKeyFilenameJWK)
	if err != nil {
		t.Fatal(err)
	}

	loadedPEMPublicKey, err := LoadPublicKeyFile(publicKeyFilenamePEM)
	if err != nil {
		t.Fatal(err)
	}

	loadedJWKPublicKey, err := LoadPublicKeyFile(publicKeyFilenameJWK)
	if err != nil {
		t.Fatal(err)
	}

	if key.KeyID() != loadedPEMKey.KeyID() {
		t.Fatal(errors.New("key IDs do not match"))
	}

	if key.KeyID() != loadedJWKKey.KeyID() {
		t.Fatal(errors.New("key IDs do not match"))
	}

	if key.KeyID() != loadedPEMPublicKey.KeyID() {
		t.Fatal(errors.New("key IDs do not match"))
	}

	if key.KeyID() != loadedJWKPublicKey.KeyID() {
		t.Fatal(errors.New("key IDs do not match"))
	}

	os.Remove(privateKeyFilename)
	os.Remove(privateKeyFilenamePEM)
	os.Remove(privateKeyFilenameJWK)
	os.Remove(publicKeyFilename)
	os.Remove(publicKeyFilenamePEM)
	os.Remove(publicKeyFilenameJWK)
}

func TestTrustedHostKeysFile(t *testing.T) {
	trustedHostKeysFilename := makeTempFile(t, "trusted_host_keys")

	hostAddress1 := "docker.example.com:2376"
	hostKey1, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedHostKey(trustedHostKeysFilename, hostAddress1, hostKey1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	trustedHostKeysMapping, err := LoadTrustedHostKeysFile(trustedHostKeysFilename)
	if err != nil {
		t.Fatal(err)
	}

	for addr, hostKey := range trustedHostKeysMapping {
		t.Logf("Host Address: %s\n", addr)
		t.Logf("Host Key: %s\n\n", hostKey)
	}

	hostAddress2 := "192.168.59.103:2376"
	hostKey2, err := GenerateECP384PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedHostKey(trustedHostKeysFilename, hostAddress2, hostKey2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	trustedHostKeysMapping, err = LoadTrustedHostKeysFile(trustedHostKeysFilename)
	if err != nil {
		t.Fatal(err)
	}

	for addr, hostKey := range trustedHostKeysMapping {
		t.Logf("Host Address: %s\n", addr)
		t.Logf("Host Key: %s\n\n", hostKey)
	}

	os.Remove(trustedHostKeysFilename)
}

func TestTrustedClientKeysFile(t *testing.T) {
	trustedClientKeysFilename := makeTempFile(t, "trusted_client_keys")

	clientKey1, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedClientKey(trustedClientKeysFilename, "Client Key #1", clientKey1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	trustedClientKeys, err := LoadTrustedClientKeysFile(trustedClientKeysFilename)
	if err != nil {
		t.Fatal(err)
	}

	for _, clientKey := range trustedClientKeys {
		t.Logf("Client Key: %s\n", clientKey)
	}

	clientKey2, err := GenerateECP384PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedClientKey(trustedClientKeysFilename, "Client Key #2", clientKey2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	trustedClientKeys, err = LoadTrustedClientKeysFile(trustedClientKeysFilename)
	if err != nil {
		t.Fatal(err)
	}

	for _, clientKey := range trustedClientKeys {
		t.Logf("Client Key: %s\n", clientKey)
	}

	os.Remove(trustedClientKeysFilename)
}
