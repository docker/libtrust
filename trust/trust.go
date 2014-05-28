package main

import (
	"fmt"
	"os"
	"github.com/docker/libtrust"
)

func main() {
	fmt.Printf("Generating keypair...\n")
	id, err := libtrust.NewId()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	data := id.Export()
	fmt.Printf("%s\n", data)
}
