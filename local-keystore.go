package dataprotection

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"
)

type localKeyFile struct {
	fp   string
	keys []RotationKey
}

type localKeyFileFormat struct {
	ID        string `json:"id"`
	Secret    string `json:"secret"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

func newLocalFile(fp string) *localKeyFile {
	return &localKeyFile{fp, nil}
}

func WithFile(fp string) ProtectorOption {
	return func(p *Protector) error {
		p.backend = newLocalFile(fp)
		return nil
	}
}

func (l *localKeyFile) GetKeys() ([]RotationKey, error) {
	b, err := ioutil.ReadFile(l.fp)
	if err != nil {
		if err := ioutil.WriteFile(l.fp, []byte("[]"), 0644); err != nil {
			return nil, fmt.Errorf("local file error: %w", err)
		}
		b = []byte("[]")
	}

	var localKeys []*localKeyFileFormat
	if err := json.Unmarshal(b, &localKeys); err != nil {
		return nil, fmt.Errorf("local file error: invalid JSON: %w", err)
	}

	var keys []RotationKey
	for _, lk := range localKeys {
		notBefore, err := time.Parse(time.RFC3339, lk.NotBefore)
		if err != nil {
			continue
		}

		notAfter, err := time.Parse(time.RFC3339, lk.NotAfter)
		if err != nil {
			continue
		}

		decodedSecret, err := base64.RawURLEncoding.DecodeString(lk.Secret)
		if err != nil {
			continue
		}

		keys = append(keys, RotationKey{
			ID:        lk.ID,
			Secret:    decodedSecret,
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})
	}

	return keys, nil
}

func (l *localKeyFile) AddKey(key RotationKey) error {
	keys := append(l.keys, key)

	var localKeys []*localKeyFileFormat
	for _, k := range keys {
		encodedSecret := base64.RawURLEncoding.EncodeToString(k.Secret)

		localKeys = append(localKeys, &localKeyFileFormat{
			ID:        k.ID,
			Secret:    encodedSecret,
			NotBefore: k.NotBefore.Format(time.RFC3339),
			NotAfter:  k.NotAfter.Format(time.RFC3339),
		})
	}

	raw, err := json.Marshal(localKeys)
	if err != nil {
		return fmt.Errorf("local file error: could not serialize keys")
	}

	if err := ioutil.WriteFile(l.fp, raw, 0644); err != nil {
		return fmt.Errorf("local file error: could not write keys")
	}

	l.keys = keys

	return nil
}
