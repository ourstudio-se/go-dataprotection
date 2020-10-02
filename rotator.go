package dataprotection

import (
	"errors"
	"fmt"

	"github.com/mileusna/crontab"
)

type Policy string

const (
	RotateDaily     Policy = Policy("0 0 * * *")
	RotateWeekly           = Policy("0 0 * * 0")
	RotateMonthly          = Policy("0 0 1 * *")
	RotateQuarterly        = Policy("0 0 1 */3 *")
)

type KeyRotator struct {
	backend Backend
	impl    schemer
	errch   chan error
}

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
