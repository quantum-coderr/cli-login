// Package session manages session tokens: issuing them at login,
// validating them on later requests, and deleting them on logout.
package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/quantum-coderr/cli-login/internal/models"
)

// ErrSessionNotFound covers both "no such token" and "token exists but
// expired" — deliberately not distinguished, so callers can't use timing
// or error content to probe for valid-but-expired tokens.
var ErrSessionNotFound = errors.New("session: not found or expired")

// tokenBytes is how much randomness goes into each session token: 32
// bytes (256 bits), hex-encoded to a 64-character string. That's well
// beyond brute-force range.
const tokenBytes = 32

// CreateSession issues a new session for userID, valid for duration from
// now.
func CreateSession(ctx context.Context, db *sql.DB, userID string, duration time.Duration) (*models.Session, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("session: generate token: %w", err)
	}

	session := &models.Session{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(duration),
	}

	err = db.QueryRowContext(ctx, `
		INSERT INTO sessions (token, user_id, created_at, expires_at)
		VALUES ($1, $2, now(), $3)
		RETURNING created_at, expires_at
	`, token, userID, session.ExpiresAt).Scan(&session.CreatedAt, &session.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("session: insert: %w", err)
	}

	return session, nil
}

// ValidateSession looks up token and returns the session if it exists and
// hasn't expired.
func ValidateSession(ctx context.Context, db *sql.DB, token string) (*models.Session, error) {
	var s models.Session
	err := db.QueryRowContext(ctx, `
		SELECT token, user_id, created_at, expires_at FROM sessions WHERE token = $1
	`, token).Scan(&s.Token, &s.UserID, &s.CreatedAt, &s.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("session: look up: %w", err)
	}

	if s.ExpiresAt.Before(time.Now()) {
		return nil, ErrSessionNotFound
	}

	return &s, nil
}

// InvalidateSession deletes a session row (logout). Deleting a token that
// doesn't exist is not an error — logging out is idempotent.
func InvalidateSession(ctx context.Context, db *sql.DB, token string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE token = $1`, token); err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}

// generateToken produces a random session token using crypto/rand.
// math/rand must never be used here — it's not cryptographically secure
// and its output is predictable given enough samples, which would make
// session tokens guessable.
func generateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
