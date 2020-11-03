package dataprotection

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type fakeAuth struct{}

func (a *fakeAuth) Sign(_ []byte, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func (a *fakeAuth) Verify(_ []byte, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}

func TestProtectUnprotect(t *testing.T) {
	a := NewAES256(&fakeAuth{})
	k, _ := a.GenerateKey()
	_ = a.WithKey(k)

	msg := "test-message"
	p, err := a.Protect([]byte(msg))
	assert.NoError(t, err)

	u, err := a.Unprotect(p)
	assert.NoError(t, err)

	assert.Equal(t, msg, string(u))
}

func TestProtectUnprotectWithKeyLookup(t *testing.T) {
	a := NewAES256(&fakeAuth{})
	k1, _ := a.GenerateKey()
	k1.NotBefore = time.Now().UTC().Add(time.Hour * -2)
	k1.NotAfter = time.Now().UTC().Add(time.Hour * -1)

	k2, _ := a.GenerateKey()
	k2.NotBefore = time.Now().UTC()
	k2.NotAfter = time.Now().UTC().Add(time.Hour * 2)

	_ = a.WithKey(k1)
	_ = a.WithKey(k2)

	msg := "test-message"
	rp, err := a.protect([]byte(msg), k1)
	assert.NoError(t, err)

	p := a.wrapKeyID(k1, rp)

	u, err := a.Unprotect(p)
	assert.NoError(t, err)

	assert.Equal(t, msg, string(u))
}

func TestNewest(t *testing.T) {
	k1 := RotationKey{
		ID:        "k1",
		Secret:    []byte("abc"),
		NotAfter:  time.Now().UTC(),
		NotBefore: time.Now().UTC().Add(time.Hour * -2),
	}
	k2 := RotationKey{
		ID:        "k2",
		Secret:    []byte("cba"),
		NotAfter:  time.Now().UTC().Add(time.Hour * 2),
		NotBefore: time.Now().UTC().Add(time.Hour * -1),
	}

	sut := &AES256{}
	sut.keyset = map[string]RotationKey{
		"k1": k1,
		"k2": k2,
	}

	n, err := sut.latestKey()
	assert.NoError(t, err)

	assert.Equal(t, k2.ID, n.ID)
}
