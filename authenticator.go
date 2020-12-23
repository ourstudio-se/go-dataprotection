package dataprotection

// Authenticator is an abstraction for
// signing and verifing payloads
type Authenticator interface {
	Sign([]byte, []byte) ([]byte, error)
	Verify([]byte, []byte) ([]byte, error)
}
