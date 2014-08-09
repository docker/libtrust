package libtrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/docker/libtrust/jwa"
)

var (
	// ErrKeyFileDoesNotExist indicates that the private key file does not exist.
	ErrKeyFileDoesNotExist = errors.New("key file does not exist")
)

// LoadKeyFile does something.
func LoadKeyFile(filename string) (jwa.PrivateKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, ErrKeyFileDoesNotExist
	} else if err != nil {
		return nil, fmt.Errorf("unable to read private key file %s: %s", filename, err)
	}

	key, err := jwa.UnmarshalPrivateKeyJSON(contents)
	if err != nil {
		return nil, fmt.Errorf("unable to decode private key: %s", err)
	}

	return key, nil
}

// SaveKey does something.
func SaveKey(filename string, key jwa.PrivateKey) error {
	encodedKey, err := json.MarshalIndent(key, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode private key: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedKey, os.FileMode(0600))
	if err != nil {
		return fmt.Errorf("unable to write private key file %s: %s", filename, err)
	}

	return nil
}

// SavePublicKey does something.
func SavePublicKey(filename string, key jwa.PublicKey) error {
	encodedKey, err := json.MarshalIndent(key, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode public key: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedKey, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write public key file %s: %s", filename, err)
	}

	return nil
}

// LoadTrustedHostKeysFile opens the given file and loads the trusted host
// entries.
func LoadTrustedHostKeysFile(filename string) (map[string]jwa.PublicKey, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return make(map[string]jwa.PublicKey), nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to read known hosts file %s: %s", filename, err)
	}

	rawEntries := make(map[string]json.RawMessage)

	if len(contents) != 0 {
		err = json.Unmarshal(contents, &rawEntries)
		if err != nil {
			return nil, fmt.Errorf("unable to decode known hosts file: %s", err)
		}
	}

	hostKeyMapping := make(map[string]jwa.PublicKey, len(rawEntries))

	for address, rawEntry := range rawEntries {
		decodedKey, err := jwa.UnmarshalPublicKeyJSON(rawEntry)
		if err != nil {
			return nil, fmt.Errorf("unable to decode host key: %s", err)
		}
		hostKeyMapping[address] = decodedKey
	}

	return hostKeyMapping, nil
}

// SaveTrustedHostKey opens the given file and adds an entry for the given address
// and public key.
func SaveTrustedHostKey(filename, hostAddress string, hostKey jwa.PublicKey) error {
	knownHostEntries, err := LoadTrustedHostKeysFile(filename)
	if err != nil {
		return err
	}

	knownHostEntries[hostAddress] = hostKey

	encodedKnownHostEntries, err := json.MarshalIndent(knownHostEntries, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode host keys: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedKnownHostEntries, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write known hosts file %s: %s", filename, err)
	}

	return nil
}

type authorizedKeysEntry struct {
	Comment      string          `json:"comment"`
	RawPublicKey json.RawMessage `json:"publicKey"`
}

func loadTrustedClientKeysFileRaw(filename string) ([]authorizedKeysEntry, error) {
	contents, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("unable to read authorized keys file %s: %s", filename, err)
	}

	var rawEntries []authorizedKeysEntry

	if len(contents) != 0 {
		err = json.Unmarshal(contents, &rawEntries)
		if err != nil {
			return nil, fmt.Errorf("unable to decode authorized keys file: %s", err)
		}
	} else {
		rawEntries = make([]authorizedKeysEntry, 0)
	}

	return rawEntries, nil
}

// LoadTrustedClientKeysFile does something.
func LoadTrustedClientKeysFile(filename string) ([]jwa.PublicKey, error) {
	rawEntries, err := loadTrustedClientKeysFileRaw(filename)
	if err != nil {
		return nil, err
	}

	keyEntries := make([]jwa.PublicKey, len(rawEntries))

	for i, entry := range rawEntries {
		key, err := jwa.UnmarshalPublicKeyJSON(entry.RawPublicKey)
		if err != nil {
			return nil, fmt.Errorf("unable to decode authorized key: %s", err)
		}
		keyEntries[i] = key
	}

	return keyEntries, nil
}

// SaveTrustedClientKey does something.
func SaveTrustedClientKey(filename, comment string, key jwa.PublicKey) error {
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("unable to encode authorized key: %s", err)
	}

	rawEntries, err := loadTrustedClientKeysFileRaw(filename)
	if err != nil {
		return err
	}

	rawEntries = append(rawEntries, authorizedKeysEntry{comment, json.RawMessage(encodedKey)})

	encodedEntries, err := json.MarshalIndent(rawEntries, "", "    ")
	if err != nil {
		return fmt.Errorf("unable to encode authorized keys: %s", err)
	}

	err = ioutil.WriteFile(filename, encodedEntries, os.FileMode(0644))
	if err != nil {
		return fmt.Errorf("unable to write authorized keys file %s: %s", filename, err)
	}

	return nil
}
