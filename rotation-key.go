package dataprotection

import (
	"encoding/base64"
	"time"
)

type RotationKey struct {
	ID        string
	Secret    []byte
	NotBefore time.Time
	NotAfter  time.Time
}

func (k RotationKey) Valid() bool {
	if time.Now().UTC().Before(k.NotBefore) {
		return false
	}

	if time.Now().UTC().After(k.NotAfter) {
		return false
	}

	return true
}

func (k RotationKey) EncodeID() string {
	prefix := []byte(k.ID)[:8]
	return base64.RawURLEncoding.EncodeToString(prefix)
}

func ExtractKeyID(b []byte) (string, []byte) {
	prefix, rest := b[:11], b[11:]
	return string(prefix), rest
}
