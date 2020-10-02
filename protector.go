package dataprotection

import (
	"fmt"
	"os"
	"path/filepath"
)

type Backend interface {
	GetKeys() ([]RotationKey, error)
	AddKey(RotationKey) error
}

type schemer interface {
	GenerateKey() (RotationKey, error)
	WithKey(RotationKey) error
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

type Scheme string

const (
	AES256_HMACSHA256 Scheme = "AES256_HMACSHA256"
)

type Protector struct {
	backend Backend
	scheme  Scheme
	impl    schemer
}

type ProtectorOption func(*Protector) error

func WithBackend(backend Backend) ProtectorOption {
	return func(p *Protector) error {
		p.backend = backend
		return nil
	}
}

func New(scheme Scheme, opts ...ProtectorOption) (*Protector, error) {
	p := &Protector{
		backend: nil,
		scheme:  AES256_HMACSHA256,
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, fmt.Errorf("data protection: invalid option: %w", err)
		}
	}

	if p.backend == nil {
		l, err := defaultLocalKeyFile()
		if err != nil {
			return nil, fmt.Errorf("data protection: could not create local key file: %w", err)
		}

		withFile := WithFile(l)
		if err := withFile(p); err != nil {
			return nil, fmt.Errorf("data protection: %w", err)
		}
	}

	keys, err := p.backend.GetKeys()
	if err != nil {
		return nil, fmt.Errorf("data protection: %w", err)
	}

	impl, err := schemeValidator(p.scheme)
	if err != nil {
		return nil, err
	}

	if len(keys) == 0 {
		key, err := impl.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("data protection: key error: %w", err)
		}

		if err := p.backend.AddKey(key); err != nil {
			return nil, fmt.Errorf("data protection: key error: %w", err)
		}

		keys = append(keys, key)
	}

	for _, k := range keys {
		if err := impl.WithKey(k); err != nil {
			return nil, fmt.Errorf("data protection: %w", err)
		}
	}

	p.impl = impl
	return p, nil
}

func (p *Protector) WithRotationPolicy(policy Policy) (*KeyRotator, error) {
	kr, err := NewKeyRotationPolicy(policy, p)
	if err != nil {
		return nil, fmt.Errorf("data protection: rotation policy failure: %w", err)
	}

	return kr, nil
}

func (p *Protector) Protect(b []byte) ([]byte, error) {
	return p.impl.Protect(b)
}

func (p *Protector) Unprotect(b []byte) ([]byte, error) {
	return p.impl.Unprotect(b)
}

func schemeValidator(scheme Scheme) (schemer, error) {
	switch scheme {
	case AES256_HMACSHA256:
		return NewAES256(NewHMACSHA256()), nil

	default:
		return nil, fmt.Errorf("data protection: unsupported scheme: %s", scheme)
	}
}

func defaultLocalKeyFile() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("%s%sdata-protection-keys", cwd, string(filepath.Separator))
	return path, nil
}
