// Package totp wraps github.com/pquerna/otp/totp for generating and
// verifying TOTP codes. It knows nothing about the DB or users.
package totp

import (
	"fmt"

	// Aliased since this package is also named totp, avoids confusing
	// totp.Generate(...) inside package totp.
	otplib "github.com/pquerna/otp/totp"
)

// Issuer is the label authenticator apps show for accounts created by
// this system (e.g. Google Authenticator shows "CLILoginSystem (alice)").
const Issuer = "CLILoginSystem"

// GenerateSecret creates a new TOTP secret, returning the base32 secret
// and an otpauth:// URL for the caller to display.
func GenerateSecret(username, issuer string) (secret string, otpauthURL string, err error) {
	key, err := otplib.Generate(otplib.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", fmt.Errorf("totp: generate secret: %w", err)
	}
	return key.Secret(), key.String(), nil
}

// VerifyCode checks code against secret, allowing the library's default
// clock skew of one 30-second step either way.
func VerifyCode(secret, code string) bool {
	return otplib.Validate(code, secret)
}
