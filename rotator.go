package dataprotection

import (
	"errors"
	"fmt"

	"github.com/mileusna/crontab"
)

// Policy defines a key rotation scheme
type Policy string

const (
	// RotateDaily forces a key rotation every day
	// at midnight
	RotateDaily Policy = Policy("0 0 * * *")

	// RotateWeekly forces a key rotation every week
	RotateWeekly = Policy("0 0 * * 0")

	// RotateMonthly forces a key rotation every month
	RotateMonthly = Policy("0 0 1 * *")

	// RotateQuarterly forces a key rotation every three months
	RotateQuarterly = Policy("0 0 1 */3 *")
)

// KeyRotator is an implementation of handling
// key rotation on a schedule
type KeyRotator struct {
	backend Backend
	impl    schemer
	errch   chan error
}

// NewKeyRotationPolicy sets up key rotation for a Protector,
// with a specified rotation policy: RotateDaily, RotateWeekly,
// RotateMontly, or RotateQuarterly
func NewKeyRotationPolicy(policy Policy, p *Protector) (*KeyRotator, error) {
	if err := validateRotationPolicy(policy); err != nil {
		return nil, fmt.Errorf("rotation policy: invalid policy: %w", err)
	}

	if p == nil || p.backend == nil || p.impl == nil {
		return nil, errors.New("rotation policy: invalid Protector")
	}

	errch := make(chan error)
	kr := &KeyRotator{p.backend, p.impl, errch}

	ctab := crontab.New()
	if err := ctab.AddJob(string(policy), kr.rotate); err != nil {
		return nil, fmt.Errorf("rotation policy: unable to create policy: %w", err)
	}

	return kr, nil
}

// Errors returns a channel for reading any errors
// occurring during key rotation
func (kr *KeyRotator) Errors() <-chan error {
	return kr.errch
}

func (kr *KeyRotator) writeError(err error) bool {
	select {
	case kr.errch <- err:
		return true
	default:
		return false
	}
}

func (kr *KeyRotator) rotate() {
	key, err := kr.impl.GenerateKey()
	if err != nil {
		_ = kr.writeError(err)
		return
	}

	if err := kr.backend.AddKey(key); err != nil {
		_ = kr.writeError(err)
		return
	}

	if err := kr.impl.WithKey(key); err != nil {
		_ = kr.writeError(err)
		return
	}
}

func validateRotationPolicy(policy Policy) error {
	switch policy {
	case RotateDaily, RotateWeekly, RotateMonthly, RotateQuarterly:
		return nil
	default:
		return fmt.Errorf("unsupported policy %s", string(policy))
	}
}
