package dataprotection

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSchemeValidator(t *testing.T) {
	table := []struct {
		input Scheme
		err   bool
	}{
		{
			input: AES256_HMACSHA256,
			err:   false,
		},
		{
			input: Scheme("f"),
			err:   true,
		},
	}

	for _, tt := range table {
		t.Run(string(tt.input), func(t *testing.T) {
			_, err := schemeValidator(tt.input)
			assert.Equal(t, tt.err, err != nil)
		})
	}
}
