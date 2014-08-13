package main

import (
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

	keyPEMBlock, err := key.PEMBlock()
	if err != nil {
		log.Fatal(err)
	}

	encodedPrivKey := pem.EncodeToMemory(keyPEMBlock)

	cert, err := libtrust.GenerateSelfSignedClientCert(key)
	if err != nil {
		log.Fatal(err)
	}

	encodedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	fmt.Printf("Client Key:\n\n%s\n", string(encodedPrivKey))
	fmt.Printf("Client Cert:\n\n%s\n", string(encodedCert))
}
