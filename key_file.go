package libtrust

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/docker/libtrust/jwa"
)

var (
	ErrKeyFileDoesNotExist = errors.New("key file does not exist")
	ErrUnsupportKeyType    = errors.New("unsupported key type")
)

type keyFile struct {
	KeyType string      `json:"keyType"`
	KeyID   string      `json:"keyId"`
	Key     interface{} `json:"key"`
}

type decodeKeyFile struct {
	KeyType string          `json:"keyType"`
	KeyID   string          `json:"keyId"`
	Key     json.RawMessage `json:"key"`
}

type PassphraseCallback func(string) string

func LoadKeyFile(name string, passphrase PassphraseCallback) (Key, error) {
	f, err := os.Open(name)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyFileDoesNotExist
		}
		return nil, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)

	kf := &decodeKeyFile{}

	err = decoder.Decode(kf)
	if err != nil {
		return nil, err
	}

	if kf.KeyType == "jwk" || kf.KeyType == "" {
		pk, err := jwa.UnmarshalPrivateKeyJSON(kf.Key)
		if err != nil {
			return nil, err
		}

		return newJWAKey(pk), nil
	} else if kf.KeyType == "jwe" {
		//pk, err = jwa.UnmarshalEncryptedKeyJSON([]byte(kf.Key), passphrase(kf.KeyID))

		return &jwaKey{}, nil
	}

	return nil, ErrUnsupportKeyType
}

func NewKeyFile(name string) (Key, error) {
	key, err := GenerateJWAKey(EC256)
	if err != nil {
		return nil, err
	}
	err = SaveKeyFile(key, name)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SaveKeyFile(key Key, name string) error {
	var kf keyFile
	switch kv := key.(type) {
	case *jwaKey:
		kf.KeyType = "jwk"
		kf.KeyID = kv.String()
		kf.Key = kv.key
	default:
		return ErrUnsupportKeyType
	}

	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	buf, err := json.MarshalIndent(kf, "", "   ")
	if err != nil {
		return err
	}
	_, err = f.Write(buf)
	return err
}

func SavePublicKey(key PublicKey, name string) error {
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf []byte
	switch key.(type) {
	case *jwaPublicKey:
		buf, err = json.MarshalIndent(key, "", "   ")
		if err != nil {
			return err
		}
	default:
		return ErrUnsupportKeyType
	}

	_, err = f.Write(buf)
	return err
}
