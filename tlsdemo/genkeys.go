package main

import (
	"encoding/json"
	"fmt"
	"github.com/docker/libtrust/jwa"
	"log"
)

func main() {
	clientKey, err := jwa.GenerateECP256PrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	serverKey, err := jwa.GenerateECP256PrivateKey()
	if err != nil {
		log.Fatal(err)
	}

	clientKeyJSON, err := json.MarshalIndent(clientKey, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	serverKeyJSON, err := json.MarshalIndent(serverKey, "", "    ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Client Key: %s\n", clientKeyJSON)
	fmt.Printf("Server Key: %s\n", serverKeyJSON)
}
