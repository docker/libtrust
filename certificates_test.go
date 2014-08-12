package libtrust

import (
	"net"
	"testing"
)

func TestGenerateCertificates(t *testing.T) {
	key, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = GenerateSelfSignedServerCert(key, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}

	_, err = GenerateSelfSignedClientCert(key)
	if err != nil {
		t.Fatal(err)
	}
}

func TestGenerateCACertPool(t *testing.T) {
	key, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	caKey1, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	caKey2, err := GenerateECP256PrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = GenerateCACertPool(key, []PublicKey{caKey1.PublicKey(), caKey2.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
}
