package dataprotection

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	table := []struct {
		name     string
		key      RotationKey
		expected bool
	}{
		{
			name: "Within date range",
			key: RotationKey{
				NotBefore: time.Now().UTC().Add(-1 * time.Hour),
				NotAfter:  time.Now().UTC().Add(1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "Expired",
			key: RotationKey{
				NotBefore: time.Now().UTC().Add(-1 * time.Hour),
				NotAfter:  time.Now().UTC().Add(-1 * time.Minute),
			},
			expected: false,
		},
		{
			name: "Not yet active",
			key: RotationKey{
				NotBefore: time.Now().UTC().Add(1 * time.Minute),
				NotAfter:  time.Now().UTC().Add(1 * time.Hour),
			},
			expected: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			actual := tt.key.Valid()
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestEncodeID(t *testing.T) {
	b := make([]byte, 128)
	_, err := rand.Read(b)
	assert.NoError(t, err)

	key := RotationKey{}
	key.ID = hex.EncodeToString(b)

	actual := key.EncodeID()
	expected := base64.RawURLEncoding.Strict().EncodeToString([]byte(key.ID))

	assert.True(t, strings.HasPrefix(expected, actual))
}

func TestExtractKeyID(t *testing.T) {
	b := make([]byte, 128)
	_, err := rand.Read(b)
	assert.NoError(t, err)

	key := RotationKey{}
	key.ID = hex.EncodeToString(b)

	expected := key.EncodeID()

	payload := make([]byte, 100)
	full := append([]byte(expected), payload...)

	actual, _ := ExtractKeyID(full)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}
