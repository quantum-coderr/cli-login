// Package auth implements registration, login, and account lockout. It
// has no knowledge of TOTP or the CLI layer.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/quantum-coderr/cli-login/internal/models"
)

// MaxUsernameLength and MaxPasswordLength cap input size before it ever
// reaches the database. MaxPasswordLength matches bcrypt's own 72 byte
// limit, so a too-long password fails here with a clear error instead of
// inside bcrypt.
const (
	MaxUsernameLength = 64
	MaxPasswordLength = 72
)

// Auth policy, set once at startup via Configure(). Package-level rather
// than parameters since LoginUser/CompleteLogin/RegisterUser signatures
// are fixed.
var (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	// SessionDuration is what CompleteLogin passes to session.CreateSession.
	SessionDuration = 30 * time.Minute
	// MinPasswordLength is the shortest password RegisterUser accepts.
	MinPasswordLength = 8
)

// Configure sets the package's auth policy. Call once at startup, not
// safe to call while logins are in flight.
func Configure(maxFailedAttempts int, lockoutDuration, sessionDuration time.Duration, minPasswordLength int) {
	MaxFailedAttempts = maxFailedAttempts
	LockoutDuration = lockoutDuration
	SessionDuration = sessionDuration
	MinPasswordLength = minPasswordLength
}

// RegisterUser creates a new user with a bcrypt-hashed password. The
// returned User has PasswordHash cleared.
func RegisterUser(ctx context.Context, db *sql.DB, username, password string) (*models.User, error) {
	// Trim so " rohan" and "rohan" aren't treated as different accounts.
	// Password is left alone, whitespace there may be intentional.
	username = strings.TrimSpace(username)

	if username == "" {
		return nil, ErrInvalidUsername
	}
	if len(username) > MaxUsernameLength {
		return nil, ErrUsernameTooLong
	}
	if len(password) < MinPasswordLength {
		return nil, ErrWeakPassword
	}
	if len(password) > MaxPasswordLength {
		return nil, ErrPasswordTooLong
	}

	var exists bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)`, username,
	).Scan(&exists); err != nil {
		return nil, fmt.Errorf("auth: check existing user: %w", err)
	}
	if exists {
		return nil, ErrUserExists
	}

	hash, err := hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("auth: hash password: %w", err)
	}

	user := &models.User{}
	err = db.QueryRowContext(ctx, `
		INSERT INTO users (username, password_hash, totp_enabled, failed_attempts, created_at)
		VALUES ($1, $2, FALSE, 0, now())
		RETURNING id, username, password_hash, totp_secret, totp_enabled,
		          failed_attempts, locked_until, created_at, last_login_at
	`, username, hash).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.TOTPEnabled,
		&user.FailedAttempts, &user.LockedUntil, &user.CreatedAt, &user.LastLoginAt,
	)
	if err != nil {
		return nil, fmt.Errorf("auth: insert user: %w", err)
	}

	user.PasswordHash = ""
	return user, nil
}

// LoginUser verifies a username/password pair and applies lockout policy.
// It does not create a session, see CompleteLogin.
func LoginUser(ctx context.Context, db *sql.DB, username, password string) (*models.User, error) {
	username = strings.TrimSpace(username) // same trimming as RegisterUser

	var user models.User
	err := db.QueryRowContext(ctx, `
		SELECT id, username, password_hash, totp_secret, totp_enabled,
		       failed_attempts, locked_until, created_at, last_login_at
		FROM users WHERE username = $1
	`, username).Scan(
		&user.ID, &user.Username, &user.PasswordHash, &user.TOTPSecret, &user.TOTPEnabled,
		&user.FailedAttempts, &user.LockedUntil, &user.CreatedAt, &user.LastLoginAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		// Same error as a wrong password, don't reveal whether the username exists.
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("auth: look up user: %w", err)
	}

	if user.LockedUntil.Valid && user.LockedUntil.Time.After(time.Now()) {
		return nil, &AccountLockedError{Until: user.LockedUntil.Time}
	}

	if !verifyPassword(user.PasswordHash, password) {
		if err := recordFailedAttempt(ctx, db, user.ID, user.FailedAttempts); err != nil {
			return nil, fmt.Errorf("auth: record failed attempt: %w", err)
		}
		return nil, ErrInvalidCredentials
	}

	now := time.Now()
	if _, err := db.ExecContext(ctx, `
		UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = $2 WHERE id = $1
	`, user.ID, now); err != nil {
		return nil, fmt.Errorf("auth: reset failed attempts: %w", err)
	}

	user.PasswordHash = ""
	user.FailedAttempts = 0
	user.LockedUntil = sql.NullTime{}
	user.LastLoginAt = sql.NullTime{Time: now, Valid: true}

	// No session created here on purpose: CompleteLogin still needs to
	// check TOTP before a session should exist.
	return &user, nil
}

// recordFailedAttempt increments failed_attempts and locks the account
// if the new count reaches MaxFailedAttempts. previousCount is the
// caller's already-read count, to avoid a read-then-write round trip.
func recordFailedAttempt(ctx context.Context, db *sql.DB, userID string, previousCount int) error {
	newCount := previousCount + 1

	if newCount >= MaxFailedAttempts {
		lockedUntil := time.Now().Add(LockoutDuration)
		_, err := db.ExecContext(ctx,
			`UPDATE users SET failed_attempts = $1, locked_until = $2 WHERE id = $3`,
			newCount, lockedUntil, userID,
		)
		return err
	}

	_, err := db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = $1 WHERE id = $2`,
		newCount, userID,
	)
	return err
}

// hashPassword and verifyPassword wrap bcrypt as small, testable units.
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
