// Package auth implements core authentication logic: registration,
// credential verification, and failed-attempt lockout. It has no
// knowledge of TOTP (Phase 3) or the CLI/prompt layer (Phase 4) — it's
// meant to be a plain library other layers call into.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/quantum-coderr/cli-login/internal/models"
)

// Auth policy. These have working defaults but are meant to be set once
// at startup via Configure(), from internal/config (env vars
// MAX_FAILED_ATTEMPTS / LOCKOUT_DURATION_MINUTES / SESSION_TIMEOUT_MINUTES /
// MIN_PASSWORD_LENGTH). They're package-level rather than parameters to
// LoginUser/CompleteLogin/RegisterUser because those signatures are fixed
// by the spec — this keeps them clean while still making the policy
// configurable.
var (
	MaxFailedAttempts = 5
	LockoutDuration   = 15 * time.Minute
	// SessionDuration is how long a session issued by CompleteLogin
	// (Phase 3) stays valid. session.CreateSession itself still takes an
	// explicit duration — this is just what CompleteLogin passes it,
	// since CompleteLogin's own signature has no duration parameter.
	SessionDuration = 30 * time.Minute
	// MinPasswordLength is the shortest password RegisterUser accepts.
	// Deliberately simple — full password policy is out of scope for this
	// size of project.
	MinPasswordLength = 8
)

// Configure sets the package's auth policy. Call once at startup (main.go
// does, from internal/config) before serving any logins. Not safe to call
// concurrently with in-flight LoginUser/CompleteLogin/RegisterUser calls.
func Configure(maxFailedAttempts int, lockoutDuration, sessionDuration time.Duration, minPasswordLength int) {
	MaxFailedAttempts = maxFailedAttempts
	LockoutDuration = lockoutDuration
	SessionDuration = sessionDuration
	MinPasswordLength = minPasswordLength
}

// RegisterUser creates a new user with a bcrypt-hashed password.
//
// The returned User has PasswordHash cleared: nothing past this point in
// Phase 2 needs it on the returned struct (LoginUser re-fetches its own
// row to compare hashes), so it's zeroed here rather than left for a
// future CLI layer to accidentally log or print.
func RegisterUser(ctx context.Context, db *sql.DB, username, password string) (*models.User, error) {
	if username == "" {
		return nil, ErrInvalidUsername
	}
	if len(password) < MinPasswordLength {
		return nil, ErrWeakPassword
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
// It does NOT create a session — see the note below.
//
// Returned User has PasswordHash cleared, for the same reason as in
// RegisterUser.
func LoginUser(ctx context.Context, db *sql.DB, username, password string) (*models.User, error) {
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
		// Same error as a wrong password below — an unknown username must
		// not be distinguishable from a wrong password.
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

	// Deliberately no session.CreateSession call here. Phase 3 will wrap
	// LoginUser with a TOTP challenge (checked via user.TOTPEnabled /
	// user.TOTPSecret), and a session should only be issued once that
	// second factor also passes. Keeping issuance out of LoginUser means
	// Phase 3 can insert its check between "password ok" and "session
	// created" without changing this function's signature or behavior.
	return &user, nil
}

// recordFailedAttempt increments failed_attempts for a user and, if the
// new count reaches MaxFailedAttempts, locks the account for
// LockoutDuration. previousCount is the failed_attempts value already
// read by the caller, so this issues one UPDATE rather than a
// read-then-write round trip.
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

// hashPassword and verifyPassword wrap bcrypt so the hashing/comparison
// logic is a small, independently testable unit (see auth_test.go) rather
// than inlined in RegisterUser/LoginUser.
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
