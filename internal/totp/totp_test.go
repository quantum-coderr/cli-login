package totp

import (
	"testing"
	"time"

	otplib "github.com/pquerna/otp/totp"
)

func TestGenerateSecretProducesValidSecretAndURL(t *testing.T) {
	secret, otpauthURL, err := GenerateSecret("alice", Issuer)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if secret == "" {
		t.Fatal("expected a non-empty secret")
	}
	if otpauthURL == "" {
		t.Fatal("expected a non-empty otpauth URL")
	}
	const wantPrefix = "otpauth://totp/"
	if len(otpauthURL) < len(wantPrefix) || otpauthURL[:len(wantPrefix)] != wantPrefix {
		t.Errorf("expected otpauth URL to start with %q, got %q", wantPrefix, otpauthURL)
	}

	// Round-trip: a code generated from the returned secret via the
	// underlying library should validate against that same secret.
	code, err := otplib.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("otplib.GenerateCode: %v", err)
	}
	if !VerifyCode(secret, code) {
		t.Error("expected a code generated from the secret to verify successfully")
	}
}

func TestGenerateSecretIsUniquePerCall(t *testing.T) {
	s1, _, err := GenerateSecret("alice", Issuer)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	s2, _, err := GenerateSecret("alice", Issuer)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if s1 == s2 {
		t.Error("expected two independently generated secrets to differ")
	}
}

func TestVerifyCode(t *testing.T) {
	secret, _, err := GenerateSecret("bob", Issuer)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}

	validCode, err := otplib.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("otplib.GenerateCode: %v", err)
	}

	if !VerifyCode(secret, validCode) {
		t.Error("expected VerifyCode to accept a code generated from the same secret")
	}

	// A code generated from a different secret must not validate.
	otherSecret, _, err := GenerateSecret("carol", Issuer)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	wrongCode, err := otplib.GenerateCode(otherSecret, time.Now())
	if err != nil {
		t.Fatalf("otplib.GenerateCode: %v", err)
	}
	if wrongCode != validCode && VerifyCode(secret, wrongCode) {
		t.Error("expected VerifyCode to reject a code generated from a different secret")
	}

	if VerifyCode(secret, "000000") && validCode != "000000" {
		t.Error("expected VerifyCode to reject an arbitrary/incorrect code")
	}
}
