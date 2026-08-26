// External test package (session_test, not session): auth imports
// session, so an in-package test file here that also imports auth would
// cycle. See session_test.go for the one test needing in-package access.
package session_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	// Registers the "pgx" driver.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/quantum-coderr/cli-login/internal/auth"
	"github.com/quantum-coderr/cli-login/internal/session"
)

// ---------------------------------------------------------------------
// Integration tests, require a real Postgres reachable via DATABASE_URL.
// See internal/auth/auth_test.go for how to run these against the
// docker-compose db. Skipped automatically if DATABASE_URL isn't set.
// ---------------------------------------------------------------------

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test (requires a running Postgres, see docker-compose)")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	// Registered here, not via defer, so it runs after later cleanups
	// like setupTestUser's user delete (t.Cleanup is LIFO).
	t.Cleanup(func() { db.Close() })
	return db
}

// setupTestUser registers a throwaway user (via internal/auth, so this
// also exercises the two packages together) and schedules its cleanup.
// Deleting the user cascades to its sessions (ON DELETE CASCADE).
func setupTestUser(t *testing.T, db *sql.DB, username string) string {
	t.Helper()
	ctx := context.Background()

	_, _ = db.Exec(`DELETE FROM users WHERE username = $1`, username) // leftover from a previous failed run

	user, err := auth.RegisterUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("setup: RegisterUser: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec(`DELETE FROM users WHERE username = $1`, username); err != nil {
			t.Errorf("cleanup user %q: %v", username, err)
		}
	})
	return user.ID
}

func TestCreateValidateInvalidateIntegration(t *testing.T) {
	db := openTestDB(t)

	userID := setupTestUser(t, db, "sessiontest_basic")
	ctx := context.Background()

	sess, err := session.CreateSession(ctx, db, userID, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	got, err := session.ValidateSession(ctx, db, sess.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("expected user_id %q, got %q", userID, got.UserID)
	}

	if err := session.InvalidateSession(ctx, db, sess.Token); err != nil {
		t.Fatalf("InvalidateSession: %v", err)
	}

	if _, err := session.ValidateSession(ctx, db, sess.Token); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after invalidation, got %v", err)
	}
}

func TestValidateExpiredSessionIntegration(t *testing.T) {
	db := openTestDB(t)

	userID := setupTestUser(t, db, "sessiontest_expired")
	ctx := context.Background()

	// A negative duration puts expires_at in the past immediately.
	sess, err := session.CreateSession(ctx, db, userID, -1*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := session.ValidateSession(ctx, db, sess.Token); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for an expired session, got %v", err)
	}
}

func TestInvalidateUnknownTokenIsNotAnError(t *testing.T) {
	db := openTestDB(t)

	if err := session.InvalidateSession(context.Background(), db, "token-that-does-not-exist"); err != nil {
		t.Errorf("InvalidateSession on an unknown token should be a no-op, got %v", err)
	}
}

// A real user might have the CLI open in two terminals at once, each
// with its own session. Logging out of one should not touch the other.
func TestMultipleSessionsPerUserIntegration(t *testing.T) {
	db := openTestDB(t)

	userID := setupTestUser(t, db, "sessiontest_multi")
	ctx := context.Background()

	sessA, err := session.CreateSession(ctx, db, userID, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession (A): %v", err)
	}
	sessB, err := session.CreateSession(ctx, db, userID, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession (B): %v", err)
	}
	if sessA.Token == sessB.Token {
		t.Fatal("expected two separately created sessions to have different tokens")
	}

	if err := session.InvalidateSession(ctx, db, sessA.Token); err != nil {
		t.Fatalf("InvalidateSession (A): %v", err)
	}

	if _, err := session.ValidateSession(ctx, db, sessA.Token); !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("expected session A to be gone after invalidating it, got %v", err)
	}
	if _, err := session.ValidateSession(ctx, db, sessB.Token); err != nil {
		t.Errorf("expected session B to still be valid, got %v", err)
	}
}
