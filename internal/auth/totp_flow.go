package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/quantum-coderr/cli-login/internal/models"
	"github.com/quantum-coderr/cli-login/internal/session"
	"github.com/quantum-coderr/cli-login/internal/totp"
)

// EnableTOTP starts 2FA setup: it generates a new secret and stores it on
// the user row, but deliberately does NOT set totp_enabled — that only
// happens once ConfirmTOTP proves the user actually scanned it correctly.
// Returns ErrTOTPAlreadyEnabled rather than overwriting an active setup.
func EnableTOTP(ctx context.Context, db *sql.DB, userID string) (secret string, otpauthURL string, err error) {
	var username string
	var totpEnabled bool
	if err := db.QueryRowContext(ctx,
		`SELECT username, totp_enabled FROM users WHERE id = $1`, userID,
	).Scan(&username, &totpEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", fmt.Errorf("auth: user %s not found", userID)
		}
		return "", "", fmt.Errorf("auth: look up user for EnableTOTP: %w", err)
	}
	if totpEnabled {
		return "", "", ErrTOTPAlreadyEnabled
	}

	secret, otpauthURL, err = totp.GenerateSecret(username, totp.Issuer)
	if err != nil {
		return "", "", fmt.Errorf("auth: generate TOTP secret: %w", err)
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_secret = $1 WHERE id = $2`, secret, userID,
	); err != nil {
		return "", "", fmt.Errorf("auth: store pending TOTP secret: %w", err)
	}

	return secret, otpauthURL, nil
}

// ConfirmTOTP checks code against the pending secret EnableTOTP stored,
// and only flips totp_enabled to true if it's correct. A wrong code
// leaves 2FA disabled — setup must be retried (or re-started via
// EnableTOTP), never silently activated on a bad code.
func ConfirmTOTP(ctx context.Context, db *sql.DB, userID, code string) error {
	var secret sql.NullString
	var totpEnabled bool
	if err := db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_enabled FROM users WHERE id = $1`, userID,
	).Scan(&secret, &totpEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("auth: user %s not found", userID)
		}
		return fmt.Errorf("auth: look up user for ConfirmTOTP: %w", err)
	}

	if totpEnabled {
		return ErrTOTPAlreadyEnabled
	}
	if !secret.Valid || secret.String == "" {
		// Nothing pending to confirm — EnableTOTP was never called (or
		// was already confirmed/disabled since).
		return ErrTOTPNotEnabled
	}

	if !totp.VerifyCode(secret.String, code) {
		return ErrInvalidTOTPCode
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_enabled = TRUE WHERE id = $1`, userID,
	); err != nil {
		return fmt.Errorf("auth: activate TOTP: %w", err)
	}
	return nil
}

// TOTPDisableVerification is the proof-of-identity DisableTOTP requires
// before turning 2FA off — either the account's current password or a
// valid TOTP code, never neither. This stops a session hijacker who
// doesn't know the password or have the authenticator app from silently
// disabling 2FA out from under the real owner.
type TOTPDisableVerification struct {
	Password string
	TOTPCode string
}

// DisableTOTP turns 2FA off, clearing the stored secret, after verifying
// either the password or a TOTP code (see TOTPDisableVerification).
func DisableTOTP(ctx context.Context, db *sql.DB, userID string, verification TOTPDisableVerification) error {
	var passwordHash string
	var secret sql.NullString
	var totpEnabled bool
	if err := db.QueryRowContext(ctx,
		`SELECT password_hash, totp_secret, totp_enabled FROM users WHERE id = $1`, userID,
	).Scan(&passwordHash, &secret, &totpEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("auth: user %s not found", userID)
		}
		return fmt.Errorf("auth: look up user for DisableTOTP: %w", err)
	}

	if !totpEnabled {
		return ErrTOTPNotEnabled
	}

	switch {
	case verification.Password != "":
		if !verifyPassword(passwordHash, verification.Password) {
			return ErrInvalidCredentials
		}
	case verification.TOTPCode != "":
		if !secret.Valid || !totp.VerifyCode(secret.String, verification.TOTPCode) {
			return ErrInvalidTOTPCode
		}
	default:
		// Neither factor supplied — nothing to verify.
		return ErrInvalidCredentials
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID,
	); err != nil {
		return fmt.Errorf("auth: disable TOTP: %w", err)
	}
	return nil
}

// CompleteLogin is the full login flow Phase 4's CLI calls: password
// check (via LoginUser), then a TOTP challenge if the account has 2FA
// enabled, and only on success does it issue a session.
//
// A wrong TOTP code counts as a failed login attempt against the same
// failed_attempts/lockout counter LoginUser uses for bad passwords —
// otherwise someone who already knows a password could brute-force TOTP
// codes with no lockout protection at all.
func CompleteLogin(ctx context.Context, db *sql.DB, username, password, totpCode string) (*models.User, *models.Session, error) {
	user, err := LoginUser(ctx, db, username, password)
	if err != nil {
		return nil, nil, err
	}

	if user.TOTPEnabled {
		if totpCode == "" {
			return nil, nil, ErrTOTPRequired
		}
		if !user.TOTPSecret.Valid || !totp.VerifyCode(user.TOTPSecret.String, totpCode) {
			if err := recordFailedAttempt(ctx, db, user.ID, user.FailedAttempts); err != nil {
				return nil, nil, fmt.Errorf("auth: record failed TOTP attempt: %w", err)
			}
			return nil, nil, ErrInvalidTOTPCode
		}
	}

	sess, err := session.CreateSession(ctx, db, user.ID, SessionDuration)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: create session: %w", err)
	}

	return user, sess, nil
}
