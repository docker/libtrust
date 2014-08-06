package libtrust

import (
	"io/ioutil"
	"path"
	"testing"
)

func TestSaveLoadFile(t *testing.T) {
	dir, err := ioutil.TempDir("", "libtrust-unittest-")
	if err != nil {
		t.Fatalf("Error creating directory: %s", err)
	}
	testfile := "save_test1.json"
	name := path.Join(dir, testfile)
	key, err := GenerateJWAKey(EC256)
	if err != nil {
		t.Fatalf("Error generating key: %s", err)
	}

	t.Logf("Saving file to: %s", name)

	err = SaveKeyFile(key, name)
	if err != nil {
		t.Fatalf("Error saving file: %s", err)
	}

	loadKey, err := LoadKeyFile(name, nil)
	if err != nil {
		t.Fatalf("Error loading file: %s", err)
	}

	if loadKey.String() != key.String() {
		t.Fatalf("Mismatched key string\n\tExpected: %s\n\tActual: %s", key.String(), loadKey.String())
	}

}
