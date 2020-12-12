package dataprotection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// AES256 is the default crypto scheme
// used for encrypting and decrypting secrets
type AES256 struct {
	Authenticator
	keyset map[string]SymmetricKey
}

const aes256KeySize = 32

// NewAES256 instantiates encryption/decryption with
// an Authenticator for signing and verifing secrets
func NewAES256(validator Authenticator) *AES256 {
	keyset := make(map[string]SymmetricKey)
	return &AES256{validator, keyset}
}

// GenerateKey returns a new SymmetricKey to be used
// for AES256 encryption/decryption
func (a *AES256) GenerateKey() (SymmetricKey, error) {
	b := make([]byte, aes256KeySize)
	if _, err := rand.Read(b); err != nil {
		return SymmetricKey{}, fmt.Errorf("AES256: unable to generate rotation key: %w", err)
	}

	return SymmetricKey{
		ID:        uuid.New().String(),
		Secret:    b,
		NotAfter:  time.Now().UTC().Add(time.Hour * 24 * 30 * 3),
		NotBefore: time.Now().UTC(),
	}, nil
}

// WithKey adds a SymmetricKey to be used for
// encrypting and decrypting AES256 secrets
func (a *AES256) WithKey(key SymmetricKey) error {
	prefix := key.EncodeID()
	if _, ok := a.keyset[prefix]; ok {
		return fmt.Errorf("AES256: key with prefix %s already exists", prefix)
	}

	a.keyset[prefix] = key
	return nil
}

// Protect encrypts the secrets, signs it, and
// returns the result with the key ID in the
// generated output
func (a *AES256) Protect(plain []byte) ([]byte, error) {
	key, err := a.latestKey()
	if err != nil {
		return nil, fmt.Errorf("AES256: signing key not available: %w", err)
	}

	signed, err := a.protect(plain, key)
	if err != nil {
		return nil, err
	}

	return a.wrapKeyID(key, signed), nil
}

func (a *AES256) protect(plain []byte, key SymmetricKey) ([]byte, error) {
	c, err := aes.NewCipher(key.Secret)
	if err != nil {
		return nil, errors.New("AES256: unable to create cipher")
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, errors.New("AES256: unable to create cipher mode")
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("AES256: unable to protect data: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	signed, err := a.Sign(key.Secret, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES256: unable to sign data: %w", err)
	}

	return signed, nil
}

// Unprotect reads the key ID from the ciphertext (to
// know which key to use for decryption), verifies the
// signature, and decrypts the secret
func (a *AES256) Unprotect(ciphertext []byte) ([]byte, error) {
	key, ciphertext, err := a.unwrapKeyID(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES256: key mismatch: %w", err)
	}

	return a.unprotect(ciphertext, key)
}

func (a *AES256) unprotect(ciphertext []byte, key SymmetricKey) ([]byte, error) {
	ciphertext, err := a.Verify(key.Secret, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES256: verification failed: %w", err)
	}

	c, err := aes.NewCipher(key.Secret)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("AES256: cipher text too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("AES256: unable to unprotect data: %w", err)
	}

	return plain, nil
}

func (a *AES256) wrapKeyID(key SymmetricKey, ciphertext []byte) []byte {
	keyID := []byte(key.EncodeID())
	return append(keyID, ciphertext...)
}

func (a *AES256) unwrapKeyID(ciphertext []byte) (SymmetricKey, []byte, error) {
	keyID, rest := ExtractKeyID(ciphertext)
	key, ok := a.keyset[keyID]
	if !ok {
		return SymmetricKey{}, nil, fmt.Errorf("could not find key {%s}", keyID)
	}

	return key, rest, nil
}

func (a *AES256) latestKey() (SymmetricKey, error) {
	if len(a.keyset) == 0 {
		return SymmetricKey{}, errors.New("no keys available")
	}

	key := SymmetricKey{}
	for _, v := range a.keyset {
		if len(key.Secret) == 0 {
			key = v
			continue
		}

		if !v.Valid() {
			continue
		}

		if key.NotAfter.After(v.NotAfter) {
			continue
		}

		key = v
	}

	return key, nil
}
