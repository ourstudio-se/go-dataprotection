package dataprotection

import (
	"encoding/base64"
	"time"
)

// SymmetricKey is a key used for encrypting
// and decrypting secrets
type SymmetricKey struct {
	ID        string
	Secret    []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// Valid validates a SymmetricKey, making sure
// it hasn't expired or isn't set for usage yet
func (k SymmetricKey) Valid() bool {
	if time.Now().UTC().Before(k.NotBefore) {
		return false
	}

	if time.Now().UTC().After(k.NotAfter) {
		return false
	}

	return true
}

// EncodeID returns the SymmetricKey ID in
// an encoded form
func (k SymmetricKey) EncodeID() string {
	prefix := []byte(k.ID)[:8]
	return base64.RawURLEncoding.EncodeToString(prefix)
}

// ExtractKeyID returns the SymmetricKey ID
// from a ciphered byte array
func ExtractKeyID(b []byte) (string, []byte) {
	prefix, rest := b[:11], b[11:]
	return string(prefix), rest
}
