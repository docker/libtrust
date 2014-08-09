package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/docker/libtrust"
)

var (
	serverAddress            = "localhost:8888"
	clientPrivateKeyFilename = "client_data/private_key.json"
	trustedHostsFilename     = "client_data/trusted_hosts.json"
)

func main() {
	key, err := libtrust.LoadKeyFile(clientPrivateKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	cryptoPrivateKey := key.CryptoPrivateKey()
	var pemBlockType string
	var derPrivateKey []byte

	switch cryptoPrivateKey := cryptoPrivateKey.(type) {
	case *ecdsa.PrivateKey:
		pemBlockType = "EC PRIVATE KEY"
		derPrivateKey, err = x509.MarshalECPrivateKey(cryptoPrivateKey)
		if err != nil {
			log.Fatal(err)
		}
	case *rsa.PrivateKey:
		pemBlockType = "RSA PRIVATE KEY"
		derPrivateKey = x509.MarshalPKCS1PrivateKey(cryptoPrivateKey)
	default:
		log.Fatal("private key is of unknown type, must be ECDSA or RSA")
	}

	encodedPrivKey := pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: derPrivateKey})

	cert, err := libtrust.GenerateSelfSignedClientCert(key)
	if err != nil {
		log.Fatal(err)
	}

	encodedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	fmt.Printf("Client Key:\n\n%s\n", string(encodedPrivKey))
	fmt.Printf("Client Cert:\n\n%s\n", string(encodedCert))
}
