package libtrust

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func createPublicKeysFile(name string, n int) error {
	keys := make([]PublicKey, n)
	for i := range keys {
		pk, err := GenerateJWAKey(EC256)
		if err != nil {
			return err
		}
		keys[i] = &jwaPublicKey{
			key: pk.(*jwaKey).key.PublicKey(),
		}
	}

	return CreatePublicKeysFile(name, keys)
}

func createPublicKeysFiles(dir string, n int) error {
	for i := 0; i < n; i++ {
		pk, err := GenerateJWAKey(EC256)
		if err != nil {
			return err
		}

		jsonName := fmt.Sprintf("key-%d.json", i)

		f, err := os.OpenFile(path.Join(dir, jsonName), os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()

		buf, err := json.MarshalIndent(pk.(*jwaKey).key.PublicKey(), "", "   ")
		if err != nil {
			return err
		}
		_, err = f.Write(buf)
	}

	return nil
}

func TestLoadPublicKeysFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "libtrust-unittest-")
	if err != nil {
		t.Fatalf("Error creating directory: %s", err)
	}
	testfile := "public_keys.json"
	name := path.Join(dir, testfile)
	err = createPublicKeysFile(name, 20)
	if err != nil {
		t.Fatalf("Error creating public keys file: %s", err)
	}
	t.Logf("Creating public keys file: %s", name)

	publicKeys, err := LoadPublicKeysFile(name, "")
	if err != nil {
		t.Fatalf("Error loading public keys file: %s", err)
	}

	if len(publicKeys) != 20 {
		t.Fatalf("Unexpected number of public keys\n\tExpecting: 20\n\tActual: %d", len(publicKeys))
	}
}

func TestPublicKeyDirectory(t *testing.T) {
	dir, err := ioutil.TempDir("", "libtrust-unittest-")
	if err != nil {
		t.Fatalf("Error creating directory: %s", err)
	}
	err = createPublicKeysFiles(dir, 25)
	if err != nil {
		t.Fatalf("Error creating public key files: %s", err)
	}
	t.Logf("Creating public key directory: %s", dir)

	publicKeys, err := LoadPublicKeysFile("", dir)
	if err != nil {
		t.Fatalf("Error loading public keys file: %s", err)
	}

	if len(publicKeys) != 25 {
		t.Fatalf("Unexpected number of public keys\n\tExpecting: 25\n\tActual: %d", len(publicKeys))
	}
}
