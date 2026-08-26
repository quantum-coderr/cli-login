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

// ErrSessionNotFound covers both a missing and an expired token, kept
// indistinguishable so callers can't probe which is which.
var ErrSessionNotFound = errors.New("session: not found or expired")

// tokenBytes is 32 bytes (256 bits) of randomness per token, well beyond
// brute-force range.
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

// InvalidateSession deletes a session row. Deleting a missing token is
// not an error, logout is idempotent.
func InvalidateSession(ctx context.Context, db *sql.DB, token string) error {
	if _, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE token = $1`, token); err != nil {
		return fmt.Errorf("session: delete: %w", err)
	}
	return nil
}

// generateToken uses crypto/rand, never math/rand, which is predictable
// and would make tokens guessable.
func generateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
