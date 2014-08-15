package main

import (
	"log"

	"github.com/docker/libtrust"
)

func main() {
	// Generate and save client key.
	clientKey, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	err = libtrust.SaveKey("client_data/private_key.json", clientKey)
	if err != nil {
		log.Fatal(err)
	}

	err = libtrust.SavePublicKey("client_data/public_key.json", clientKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}

	// Generate and save server key.
	serverKey, err := libtrust.GenerateECP256PrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	err = libtrust.SaveKey("server_data/private_key.json", serverKey)
	if err != nil {
		log.Fatal(err)
	}

	err = libtrust.SavePublicKey("server_data/public_key.json", serverKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}

	// Generate Authorized Keys file for server.
	err = libtrust.SaveTrustedClientKey("server_data/trusted_clients.json", "TLS Demo Client", clientKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}

	// Generate Known Host Keys file for client.
	err = libtrust.SaveTrustedHostKey("client_data/trusted_hosts.json", "localhost:8888", serverKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
}
