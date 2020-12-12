package dataprotection

import (
	"fmt"
	"os"
	"path/filepath"
)

// Backend is an interface to accept any
// storage medium for the SymmetricKey set
type Backend interface {
	GetKeys() ([]SymmetricKey, error)
	AddKey(SymmetricKey) error
}

type schemer interface {
	GenerateKey() (SymmetricKey, error)
	WithKey(SymmetricKey) error
	Protect([]byte) ([]byte, error)
	Unprotect([]byte) ([]byte, error)
}

// Scheme defines which encryption and
// signature scheme to use
type Scheme string

const (
	// AES256_HMACSHA256 is the default scheme
	AES256_HMACSHA256 Scheme = "AES256_HMACSHA256"
)

// Protector acts as a proxy for storing and using
// SymmetricKey sets, allowing for protecting and
// unprotecting secrets - as well as handling any
// rotation policies
type Protector struct {
	backend Backend
	scheme  Scheme
	impl    schemer
}

// ProtectorOption handles functional options for
// setting up a Protector
type ProtectorOption func(*Protector) error

// WithBackend specifies a new storage medium
// for any SymmetricKey set
func WithBackend(backend Backend) ProtectorOption {
	return func(p *Protector) error {
		p.backend = backend
		return nil
	}
}

// New instantiates a new Protector with a
// specified scheme and options
//
// Example:
//   New(AES256_HMACSHA256,
//		WithBackend(&CustomBackend{}))
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

// WithRotationPolicy adds a rotation policy
// for the SymmetricKey protector
func (p *Protector) WithRotationPolicy(policy Policy) (*KeyRotator, error) {
	kr, err := NewKeyRotationPolicy(policy, p)
	if err != nil {
		return nil, fmt.Errorf("data protection: rotation policy failure: %w", err)
	}

	return kr, nil
}

// Protect a secret, returning a signed and encrypted
// value of it
func (p *Protector) Protect(b []byte) ([]byte, error) {
	return p.impl.Protect(b)
}

// Unprotect a signed and encrypted value, returning
// the protected secret
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
