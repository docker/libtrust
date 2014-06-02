package libtrust

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

func getPrivateKeyBlocks(b []byte) []*pem.Block {
	remaining := b
	blocks := make([]*pem.Block, 0, 1)
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

func ImportKeyFile(filename string) (*RsaId, error) {
	pemBytes, readErr := ioutil.ReadFile(filename)
	if readErr != nil {
		return nil, readErr
	}
	blocks := getPrivateKeyBlocks(pemBytes)

	if len(blocks) == 0 {
		return nil, errors.New("No private key blocks")
	}

	if len(blocks) > 1 {
		return nil, errors.New("Multiple private key blocks")
	}

	k, err := x509.ParsePKCS1PrivateKey(blocks[0].Bytes)
	if err != nil {
		return nil, err
	}

	return &RsaId{k}, nil
}

func (id *RsaId) ExportKeyFile(filename string) error {
	block := new(pem.Block)
	block.Type = "RSA PRIVATE KEY"
	block.Bytes = x509.MarshalPKCS1PrivateKey(id.k)

	f, openErr := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(0600))
	defer f.Close()
	if openErr != nil {
		return openErr
	}

	encodeErr := pem.Encode(f, block)
	if encodeErr != nil {
		return encodeErr
	}

	return nil
}
