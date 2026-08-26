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

// EnableTOTP generates and stores a new TOTP secret, but leaves
// totp_enabled false until ConfirmTOTP verifies it. Returns
// ErrTOTPAlreadyEnabled if 2FA is already on.
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

// ConfirmTOTP checks code against the pending secret from EnableTOTP and
// only flips totp_enabled to true if it matches.
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
		return ErrTOTPNotEnabled // nothing pending to confirm
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

// TOTPDisableVerification is what DisableTOTP requires to prove
// identity: the account's password or a valid TOTP code.
type TOTPDisableVerification struct {
	Password string
	TOTPCode string
}

// DisableTOTP verifies identity (see TOTPDisableVerification), then
// turns 2FA off and clears the stored secret.
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
		return ErrInvalidCredentials // neither factor supplied
	}

	if _, err := db.ExecContext(ctx,
		`UPDATE users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID,
	); err != nil {
		return fmt.Errorf("auth: disable TOTP: %w", err)
	}
	return nil
}

// CompleteLogin checks the password, then a TOTP code if 2FA is on, and
// only issues a session once both pass. A wrong TOTP code counts as a
// failed attempt too, so it can't be used to brute-force past the lockout.
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
