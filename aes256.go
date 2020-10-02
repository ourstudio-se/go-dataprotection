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

type AES256 struct {
	Authenticator
	signer RotationKey
	keyset map[string]RotationKey
}

const aes256KeySize = 32

func NewAES256(validator Authenticator) *AES256 {
	keyset := make(map[string]RotationKey)
	return &AES256{validator, RotationKey{}, keyset}
}

func (a *AES256) GenerateKey() (RotationKey, error) {
	b := make([]byte, aes256KeySize)
	if _, err := rand.Read(b); err != nil {
		return RotationKey{}, fmt.Errorf("AES256: unable to generate rotation key: %w", err)
	}

	return RotationKey{
		ID:        uuid.New().String(),
		Secret:    b,
		NotAfter:  time.Now().UTC().Add(time.Hour * 24 * 30 * 3),
		NotBefore: time.Now().UTC(),
	}, nil
}

func (a *AES256) WithKey(key RotationKey) error {
	if len(a.signer.Secret) == 0 {
		a.signer = key
	}

	prefix := a.signer.EncodeID()
	if _, ok := a.keyset[prefix]; ok {
		return fmt.Errorf("AES256: key with prefix %s already exists", prefix)
	}

	a.keyset[prefix] = key
	return nil
}

func (a *AES256) Protect(plain []byte) ([]byte, error) {
	key := a.signer

	if len(key.Secret) == 0 {
		return nil, errors.New("AES256: signing key not initialized")
	}

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

	return a.withKeyID(key, signed), nil
}

func (a *AES256) Unprotect(ciphertext []byte) ([]byte, error) {
	key, ciphertext, err := a.fromKeyID(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("AES256: key mismatch: %w", err)
	}

	ciphertext, err = a.Verify(key.Secret, ciphertext)
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

func (a *AES256) withKeyID(key RotationKey, ciphertext []byte) []byte {
	keyID := []byte(key.EncodeID())
	return append(keyID, ciphertext...)
}

func (a *AES256) fromKeyID(ciphertext []byte) (RotationKey, []byte, error) {
	keyID, rest := ExtractKeyID(ciphertext)

	key, ok := a.keyset[keyID]
	if !ok {
		return RotationKey{}, nil, fmt.Errorf("could not find key {%s}", keyID)
	}

	return key, rest, nil
}
