package session

import "testing"

// Kept in-package, unlike the integration tests, since it needs access
// to the unexported generateToken/tokenBytes.
func TestGenerateTokenIsRandomAndCorrectLength(t *testing.T) {
	a, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	b, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if a == b {
		t.Error("expected two independently generated tokens to differ")
	}
	if len(a) != tokenBytes*2 { // hex-encoded, 2 chars per byte
		t.Errorf("expected a %d-character token, got %d", tokenBytes*2, len(a))
	}
}
