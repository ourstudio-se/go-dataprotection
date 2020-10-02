package dataprotection

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHMACSHA256(t *testing.T) {
	payload := make([]byte, 100)
	key := []byte("my-key")

	hmac := NewHMACSHA256()
	signed, err := hmac.Sign(key, payload)
	assert.NoError(t, err)

	rest, err := hmac.Verify(key, signed)
	assert.NoError(t, err)

	assert.True(t, bytes.Equal(payload, rest))
}
