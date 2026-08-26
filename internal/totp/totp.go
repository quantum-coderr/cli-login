// Package totp wraps github.com/pquerna/otp/totp for generating and
// verifying TOTP-based 2FA codes. It knows nothing about the DB or users
// — internal/auth is what wires a secret to a user row and a code to a
// login attempt.
package totp

import (
	"fmt"

	// Aliased because this package is also named "totp" — otherwise
	// `totp.Generate(...)` inside a file that's itself `package totp`
	// reads confusingly even though it's unambiguous to the compiler.
	otplib "github.com/pquerna/otp/totp"
)

// Issuer is the label authenticator apps show for accounts created by
// this system (e.g. Google Authenticator shows "CLILoginSystem (alice)").
const Issuer = "CLILoginSystem"

// GenerateSecret creates a new TOTP secret for username under issuer,
// returning the raw base32 secret (to persist) and the otpauth:// URL
// (for manual entry or QR-code generation — this package just returns
// the string; Phase 4 decides how to display it).
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

// VerifyCode checks a 6-digit code against secret. It uses the library's
// default validation options (30s period, ±1 step skew, i.e. it accepts
// the previous/current/next 30-second window) rather than an exact
// match, so a code isn't rejected just because the client's clock or the
// network round-trip cost it a few seconds.
func VerifyCode(secret, code string) bool {
	return otplib.Validate(code, secret)
}
