package libtrust

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

var (
	// ErrKeyFileDoesNotExist indicates that the private key file does not exist.
	ErrKeyFileDoesNotExist = errors.New("key file does not exist")
)

/*
	Loading and Saving of Public and Private Keys in either PEM or JWK format.
*/

// LoadKeyFile opens the given filename and attempts to read a Private Key
// encoded in either PEM or JWK format (if .json or .jwk file extension).
func LoadKeyFile(filename string) (PrivateKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, ErrKeyFileDoesNotExist
	} else if err != nil {
		return nil, fmt.Errorf("unable to read private key file %s: %s", filename, err)
	}

	var key PrivateKey

	if strings.HasSuffix(filename, ".json") || strings.HasSuffix(filename, ".jwk") {
		key, err = UnmarshalPrivateKeyJWK(contents)
		if err != nil {
			return nil, fmt.Errorf("unable to decode private key JWK: %s", err)
		}
	} else {
		key, err = UnmarshalPrivateKeyPEM(contents)
		if err != nil {
			return nil, fmt.Errorf("unable to decode private key PEM: %s", err)
		}
	}

	return key, nil
}

// LoadPublicKeyFile opens the given filename and attempts to read a Public Key
// encoded in either PEM or JWK format (if .json or .jwk file extension).
func LoadPublicKeyFile(filename string) (PublicKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, ErrKeyFileDoesNotExist
	} else if err != nil {
		return nil, fmt.Errorf("unable to read public key file %s: %s", filename, err)
	}

	var key PublicKey

	if strings.HasSuffix(filename, ".json") || strings.HasSuffix(filename, ".jwk") {
		key, err = UnmarshalPublicKeyJWK(contents)
		if err != nil {
			return nil, fmt.Errorf("unable to decode public key JWK: %s", err)
		}
	} else {
		key, err = UnmarshalPublicKeyPEM(contents)
		if err != nil {
			return nil, fmt.Errorf("unable to decode public key PEM: %s", err)
		}
	}

	return key, nil
}

// SaveKey saves the given key to a file using the provided filename.
// This process will overwrite any existing file at the provided location.
func SaveKey(filename string, key PrivateKey) error {
	var encodedKey []byte
	var err error

	if strings.HasSuffix(filename, ".json") || strings.HasSuffix(filename, ".jwk") {
		// Encode in JSON Web Key format.
		encodedKey, err = json.MarshalIndent(key, "", "    ")
		if err != nil {
			return fmt.Errorf("unable to encode private key JWK: %s", err)
		}
	} else {
		// Encode in PEM format.
		pemBlock, err := key.PEMBlock()
		if err != nil {
			return fmt.Errorf("unable to encode private key PEM: %s", err)
		}
		encodedKey = pem.EncodeToMemory(pemBlock)
	}

	err = ioutil.WriteFile(filename, encodedKey, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("unable to write private key file %s: %s", filename, err)
	}

	return nil
}

// SavePublicKey saves the given public key to the file.
func SavePublicKey(filename string, key PublicKey) error {
	var encodedKey []byte
	var err error

	if strings.HasSuffix(filename, ".json") || strings.HasSuffix(filename, ".jwk") {
		// Encode in JSON Web Key format.
		encodedKey, err = json.MarshalIndent(key, "", "    ")
		if err != nil {
			return fmt.Errorf("unable to encode public key JWK: %s", err)
		}
	} else {
		// Encode in PEM format.
		pemBlock, err := key.PEMBlock()
		if err != nil {
			return fmt.Errorf("unable to encode public key PEM: %s", err)
		}
		encodedKey = pem.EncodeToMemory(pemBlock)
	}

	err = ioutil.WriteFile(filename, encodedKey, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write public key file %s: %s", filename, err)
	}

	return nil
}

type jwkSet struct {
	Keys []json.RawMessage `json:"keys"`
}

func loadJsonKeySet(filename string) ([]json.RawMessage, error) {
	var set jwkSet
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyFileDoesNotExist
		}
		return nil, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)

	err = decoder.Decode(&set)
	if err != nil {
		if err == io.EOF {
			return nil, nil
		}
		return nil, err
	}

	return set.Keys, nil
}

func loadJsonKeySetFile(filename string) ([]PublicKey, error) {
	messages, err := loadJsonKeySet(filename)
	if err != nil {
		return nil, err
	}

	keys := make([]PublicKey, len(messages))
	for i, raw := range messages {
		key, err := UnmarshalPublicKeyJWK(raw)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return keys, nil
}

// LoadKeySetFile loads a key set
func LoadKeySetFile(filename string) ([]PublicKey, error) {
	return loadJsonKeySetFile(filename)
}

// AddKeySetFile adds a key to a key set
func AddKeySetFile(filename string, key PublicKey) error {
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("unable to encode trusted client key: %s", err)
	}

	rawEntries, err := loadJsonKeySet(filename)
	if err != nil && err != ErrKeyFileDoesNotExist {
		return err
	}

	rawEntries = append(rawEntries, json.RawMessage(encodedKey))
	entriesWrapper := jwkSet{Keys: rawEntries}

	encodedEntries, err := json.MarshalIndent(entriesWrapper, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode trusted client keys: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedEntries, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write trusted client keys file %s: %s", filename, err)
	}

	return nil
}
