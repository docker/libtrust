package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/docker/libtrust"
)

var (
	serverAddress        = "localhost:8888"
	privateKeyFilename   = "client_data/private_key.json"
	trustedHostsFilename = "client_data/trusted_hosts.json"
)

func main() {
	// Load Client Key.
	clientKey, err := libtrust.LoadKeyFile(privateKeyFilename)
	if err != nil {
		log.Fatal(err)
	}

	// Generate Client Certificate.
	selfSignedClientCert, err := libtrust.GenerateSelfSignedClientCert(clientKey)
	if err != nil {
		log.Fatal(err)
	}

	// Load trusted host keys.
	hostKeys, err := libtrust.LoadTrustedHostKeysFile(trustedHostsFilename)
	if err != nil {
		log.Fatal(err)
	}

	// Ensure the host we want to connect to is trusted!
	serverKey, ok := hostKeys[serverAddress]
	if !ok {
		log.Fatalf("%q is not a known and trusted host", serverAddress)
	}

	// Generate a CA pool with the trusted host's key.
	caPool, err := libtrust.GenerateCACertPool(clientKey, []libtrust.PublicKey{serverKey})
	if err != nil {
		log.Fatal(err)
	}

	// Create HTTP Client.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{
					tls.Certificate{
						Certificate: [][]byte{selfSignedClientCert.Raw},
						PrivateKey:  clientKey.CryptoPrivateKey(),
						Leaf:        selfSignedClientCert,
					},
				},
				RootCAs: caPool,
			},
		},
	}

	var makeRequest = func(url string) {
		resp, err := client.Get(url)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		log.Println(resp.Status)
		log.Println(string(body))
	}

	// Make the request to the trusted server!
	makeRequest(fmt.Sprintf("https://%s", serverAddress))
}
