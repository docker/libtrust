package libtrust

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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

// SaveKey does something.
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

// SavePublicKey does something.
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

/*
	Manage Trusted Host Keys in a JSON file.
*/

type trustedHostKeysEntry struct {
	// A TCP address <hostname_or_ip:port>
	Address      string          `json:"address"`
	RawPublicKey json.RawMessage `json:"publicKey"`
}

type trustedHostKeysFile struct {
	TrustedHostKeys []trustedHostKeysEntry `json:"trustedHostKeys"`
}

func loadTrustedHostKeysFile(filename string) ([]trustedHostKeysEntry, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return make([]trustedHostKeysEntry, 0), nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to read trusted host keys file %s: %s", filename, err)
	}

	var rawContent trustedHostKeysFile

	if len(contents) != 0 {
		err = json.Unmarshal(contents, &rawContent)
		if err != nil {
			return nil, fmt.Errorf("unable to decode trusted host keys file: %s", err)
		}
	} else {
		rawContent = trustedHostKeysFile{TrustedHostKeys: make([]trustedHostKeysEntry, 0)}
	}

	return rawContent.TrustedHostKeys, nil
}

// LoadTrustedHostKeysFile opens the given file and loads the trusted host
// entries.
func LoadTrustedHostKeysFile(filename string) (map[string]PublicKey, error) {
	rawEntries, err := loadTrustedHostKeysFile(filename)
	if err != nil {
		return nil, err
	}

	hostKeyMapping := make(map[string]PublicKey, len(rawEntries))

	for _, entry := range rawEntries {
		decodedKey, err := UnmarshalPublicKeyJWK(entry.RawPublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode trusted host key: %s", err)
		}
		hostKeyMapping[entry.Address] = decodedKey
	}

	return hostKeyMapping, nil
}

// SaveTrustedHostKey opens the given file and adds an entry for the given address
// and public key.
func SaveTrustedHostKey(filename, hostAddress string, key PublicKey) error {
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("unable to encode trusted host key: %s", err)
	}

	rawEntries, err := loadTrustedHostKeysFile(filename)
	if err != nil {
		return err
	}

	rawEntries = append(rawEntries, trustedHostKeysEntry{hostAddress, json.RawMessage(encodedKey)})
	entriesWrapper := trustedHostKeysFile{rawEntries}

	encodedEntries, err := json.MarshalIndent(entriesWrapper, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode trusted host keys: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedEntries, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write trusted host keys file %s: %s", filename, err)
	}

	return nil
}

/*
	Manage Trusted Client Keys in a JSON file.
*/

type trustedClientKeysEntry struct {
	Comment      string          `json:"comment"`
	RawPublicKey json.RawMessage `json:"publicKey"`
}

type trustedClientKeysFile struct {
	TrustedClientKeys []trustedClientKeysEntry `json:"trustedClientKeys"`
}

func loadTrustedClientKeysFileRaw(filename string) ([]trustedClientKeysEntry, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to read trusted client keys file %s: %s", filename, err)
	}

	var rawContent trustedClientKeysFile

	if len(contents) != 0 {
		err = json.Unmarshal(contents, &rawContent)
		if err != nil {
			return nil, fmt.Errorf("unable to decode trusted client keys file: %s", err)
		}
	} else {
		rawContent = trustedClientKeysFile{make([]trustedClientKeysEntry, 0)}
	}

	return rawContent.TrustedClientKeys, nil
}

// LoadTrustedClientKeysFile does something.
func LoadTrustedClientKeysFile(filename string) ([]PublicKey, error) {
	rawEntries, err := loadTrustedClientKeysFileRaw(filename)
	if err != nil {
		return nil, err
	}

	keyEntries := make([]PublicKey, len(rawEntries))

	for i, entry := range rawEntries {
		key, err := UnmarshalPublicKeyJWK(entry.RawPublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode trusted client key: %s", err)
		}
		keyEntries[i] = key
	}

	return keyEntries, nil
}

// SaveTrustedClientKey does something.
func SaveTrustedClientKey(filename, comment string, key PublicKey) error {
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("unable to encode trusted client key: %s", err)
	}

	rawEntries, err := loadTrustedClientKeysFileRaw(filename)
	if err != nil {
		return err
	}

	rawEntries = append(rawEntries, trustedClientKeysEntry{comment, json.RawMessage(encodedKey)})
	entriesWrapper := trustedClientKeysFile{rawEntries}

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
