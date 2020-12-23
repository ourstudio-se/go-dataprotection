package dataprotection

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
)

const hs256SignatureSize = 32

// HMACSHA256 creates SHA256 signatures, and
// verifies them
type HMACSHA256 struct{}

// NewHMACSHA256 sets up a new signer/verifier
// for SHA256
func NewHMACSHA256() *HMACSHA256 {
	return &HMACSHA256{}
}

// Sign a payload with the specified key
func (HMACSHA256) Sign(key, raw []byte) ([]byte, error) {
	h := hmac.New(sha256.New, key)
	if _, err := h.Write(raw); err != nil {
		return nil, fmt.Errorf("HMACSHA256: signing failed: %w", err)
	}

	return append(raw, h.Sum(nil)...), nil
}

// Verify a payload with the specified key
func (HMACSHA256) Verify(key, raw []byte) ([]byte, error) {
	sig, rest := raw[len(raw)-hs256SignatureSize:], raw[:len(raw)-hs256SignatureSize]

	h := hmac.New(sha256.New, key)
	if _, err := h.Write(rest); err != nil {
		return nil, fmt.Errorf("HMACSHA256: verification failed: %w", err)
	}

	if !bytes.Equal(h.Sum(nil), sig) {
		return nil, errors.New("HMACSHA256: signature mismatch")
	}

	return rest, nil
}
