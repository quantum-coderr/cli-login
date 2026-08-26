package session

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	// Registers the "pgx" driver for the integration tests below.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/quantum-coderr/cli-login/internal/auth"
)

// ---------------------------------------------------------------------
// Pure logic test — no DB required.
// ---------------------------------------------------------------------

func TestGenerateTokenIsRandomAndCorrectLength(t *testing.T) {
	a, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	b, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if a == b {
		t.Error("expected two independently generated tokens to differ")
	}
	if len(a) != tokenBytes*2 { // hex-encoded, 2 chars per byte
		t.Errorf("expected a %d-character token, got %d", tokenBytes*2, len(a))
	}
}

// ---------------------------------------------------------------------
// Integration tests — require a real Postgres reachable via DATABASE_URL.
// See internal/auth/auth_test.go for how to run these against the
// docker-compose db. Skipped automatically if DATABASE_URL isn't set.
// ---------------------------------------------------------------------

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping integration test (requires a running Postgres — see docker-compose)")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping db: %v", err)
	}
	// Registered here (rather than left to the caller as `defer db.Close()`)
	// so it participates in t.Cleanup's LIFO order: cleanups registered
	// later (e.g. setupTestUser's user-delete) are guaranteed to run
	// before this Close, instead of racing a same-function defer that
	// would close the DB out from under a later-registered cleanup.
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

	sess, err := CreateSession(ctx, db, userID, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("expected a non-empty token")
	}

	got, err := ValidateSession(ctx, db, sess.Token)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("expected user_id %q, got %q", userID, got.UserID)
	}

	if err := InvalidateSession(ctx, db, sess.Token); err != nil {
		t.Fatalf("InvalidateSession: %v", err)
	}

	if _, err := ValidateSession(ctx, db, sess.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound after invalidation, got %v", err)
	}
}

func TestValidateExpiredSessionIntegration(t *testing.T) {
	db := openTestDB(t)

	userID := setupTestUser(t, db, "sessiontest_expired")
	ctx := context.Background()

	// A negative duration puts expires_at in the past immediately.
	sess, err := CreateSession(ctx, db, userID, -1*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if _, err := ValidateSession(ctx, db, sess.Token); !errors.Is(err, ErrSessionNotFound) {
		t.Errorf("expected ErrSessionNotFound for an expired session, got %v", err)
	}
}

func TestInvalidateUnknownTokenIsNotAnError(t *testing.T) {
	db := openTestDB(t)

	if err := InvalidateSession(context.Background(), db, "token-that-does-not-exist"); err != nil {
		t.Errorf("InvalidateSession on an unknown token should be a no-op, got %v", err)
	}
}
