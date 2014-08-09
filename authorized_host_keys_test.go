package libtrust

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/libtrust/jwa"
)

func TestTrustedHostKeysFile(t *testing.T) {
	knownHostsFile, err := ioutil.TempFile("", "known_docker_hosts")
	if err != nil {
		t.Fatal(err)
	}
	knownHostsFilename := knownHostsFile.Name()
	knownHostsFile.Close()

	hostAddress1 := "docker.example.com:2376"
	hostKey1, err := jwa.GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedHostKey(knownHostsFilename, hostAddress1, hostKey1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	knownHostsKeyMapping, err := LoadTrustedHostKeysFile(knownHostsFilename)
	if err != nil {
		t.Fatal(err)
	}

	for addr, hostKey := range knownHostsKeyMapping {
		t.Logf("Host Address: %s\n", addr)
		t.Logf("Host Key: %s\n\n", hostKey)
	}

	hostAddress2 := "192.168.59.103:2376"
	hostKey2, err := jwa.GenerateECP384PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	err = SaveTrustedHostKey(knownHostsFilename, hostAddress2, hostKey2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	knownHostsKeyMapping, err = LoadTrustedHostKeysFile(knownHostsFilename)
	if err != nil {
		t.Fatal(err)
	}

	for addr, hostKey := range knownHostsKeyMapping {
		t.Logf("Host Address: %s\n", addr)
		t.Logf("Host Key: %s\n\n", hostKey)
	}

	os.Remove(knownHostsFilename)
}
