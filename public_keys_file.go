package libtrust

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/docker/libtrust/jwa"
)

func LoadPublicKeysFile(name, keyDir string) ([]PublicKey, error) {
	var jwks []json.RawMessage
	if name != "" {
		f, err := os.Open(name)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, ErrKeyFileDoesNotExist
			}
			return nil, err
		}
		defer f.Close()

		decoder := json.NewDecoder(f)

		err = decoder.Decode(&jwks)
		if err != nil {
			return nil, err
		}
	}

	if keyDir != "" {
		files, err := filepath.Glob(filepath.Join(keyDir, "*.json"))
		if err != nil {
			return nil, err
		}
		for _, fName := range files {
			b, err := ioutil.ReadFile(fName)
			if err != nil {
				return nil, err
			}

			jwks = append(jwks, json.RawMessage(b))
		}
	}

	pks := make([]PublicKey, len(jwks))
	for i, jwk := range jwks {
		key := &jwaPublicKey{}
		var err error
		key.key, err = jwa.UnmarshalPublicKeyJSON(jwk)
		if err != nil {
			return nil, err
		}
		pks[i] = key
	}

	return pks, nil
}

func CreatePublicKeysFile(jsonFile string, keys []PublicKey) error {
	jwks := make([]interface{}, len(keys))

	for i, key := range keys {
		var jwk interface{}
		switch kv := key.(type) {
		case *jwaPublicKey:
			jwk = kv.key
		default:
			return ErrUnsupportKeyType
		}

		jwks[i] = jwk
	}

	f, err := os.OpenFile(jsonFile, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	buf, err := json.MarshalIndent(jwks, "", "   ")
	if err != nil {
		return err
	}
	_, err = f.Write(buf)
	return err

}
