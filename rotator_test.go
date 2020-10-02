package dataprotection

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRotationSchemeValidator(t *testing.T) {
	table := []struct {
		name     string
		policy   Policy
		expected bool
	}{
		{
			name:     "RotateDaily",
			policy:   RotateDaily,
			expected: true,
		},
		{
			name:     "RotateWeekly",
			policy:   RotateWeekly,
			expected: true,
		},
		{
			name:     "RotateMonthly",
			policy:   RotateMonthly,
			expected: true,
		},
		{
			name:     "RotateQuarterly",
			policy:   RotateQuarterly,
			expected: true,
		},
		{
			name:     "Custom policy as empty",
			policy:   Policy(""),
			expected: false,
		},
		{
			name:     "Custom policy",
			policy:   Policy("week"),
			expected: false,
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRotationPolicy(tt.policy)
			assert.Equal(t, tt.expected, err == nil)
		})
	}
}

func TestNonBlockingErrorChan(t *testing.T) {
	kr := &KeyRotator{}
	kr.errch = make(chan error)

	ok := kr.writeError(errors.New("1"))
	assert.False(t, ok)
}
