package dataprotection

type Authenticator interface {
	Sign([]byte, []byte) ([]byte, error)
	Verify([]byte, []byte) ([]byte, error)
}
