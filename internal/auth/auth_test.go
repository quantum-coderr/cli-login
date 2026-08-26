package auth

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	// Registers the "pgx" driver for the integration tests below.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// ---------------------------------------------------------------------
// Pure logic tests — no DB required, run with a plain `go test ./...`.
// ---------------------------------------------------------------------

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected a non-empty hash")
	}
	if !verifyPassword(hash, "correct-horse-battery-staple") {
		t.Error("verifyPassword should succeed for the correct password")
	}
	if verifyPassword(hash, "wrong-password") {
		t.Error("verifyPassword should fail for an incorrect password")
	}
}

func TestHashPasswordSaltsEachCall(t *testing.T) {
	h1, err := hashPassword("same-password")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	h2, err := hashPassword("same-password")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if h1 == h2 {
		t.Error("expected two hashes of the same password to differ (bcrypt salts each hash)")
	}
	// Both must still verify correctly despite differing.
	if !verifyPassword(h1, "same-password") || !verifyPassword(h2, "same-password") {
		t.Error("both salted hashes should verify against the original password")
	}
}

// ---------------------------------------------------------------------
// Integration tests — require a real Postgres reachable via DATABASE_URL.
// They're skipped automatically if DATABASE_URL isn't set.
//
// Run them against the Phase 1 docker-compose db (which publishes
// 5432 to the host):
//
//	docker compose up -d db
//	DATABASE_URL="postgres://cli_login_user:changeme@localhost:5432/cli_login?sslmode=disable" \
//	  go test ./internal/auth/... -v
//
// Each test cleans up the rows it creates, so it's safe to re-run.
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
	return db
}

func cleanupUser(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM users WHERE username = $1`, username); err != nil {
		t.Fatalf("cleanup user %q: %v", username, err)
	}
}

func TestRegisterAndLoginIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_register_login"
	const password = "correct-horse-battery-staple"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if user.PasswordHash != "" {
		t.Error("RegisterUser must not return the password hash to the caller")
	}

	if _, err := RegisterUser(ctx, db, username, password); !errors.Is(err, ErrUserExists) {
		t.Errorf("expected ErrUserExists on duplicate registration, got %v", err)
	}

	loggedIn, err := LoginUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if loggedIn.Username != username {
		t.Errorf("expected username %q, got %q", username, loggedIn.Username)
	}
	if !loggedIn.LastLoginAt.Valid {
		t.Error("expected last_login_at to be set after a successful login")
	}
	if loggedIn.PasswordHash != "" {
		t.Error("LoginUser must not return the password hash to the caller")
	}

	if _, err := LoginUser(ctx, db, username, "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for a wrong password, got %v", err)
	}

	if _, err := LoginUser(ctx, db, "no-such-user-xyz", password); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for an unknown username (must not leak existence), got %v", err)
	}
}

func TestLoginLockoutIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_lockout"
	const password = "correct-horse-battery-staple"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	if _, err := RegisterUser(ctx, db, username, password); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	// Use a low threshold/short lockout for the test rather than the
	// package defaults, and restore them afterward.
	origMax, origLockout, origSession, origMinLen := MaxFailedAttempts, LockoutDuration, SessionDuration, MinPasswordLength
	Configure(2, 200*time.Millisecond, origSession, origMinLen)
	defer Configure(origMax, origLockout, origSession, origMinLen)

	for i := 0; i < 2; i++ {
		if _, err := LoginUser(ctx, db, username, "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i, err)
		}
	}

	// Account should now be locked, even with the correct password.
	_, err := LoginUser(ctx, db, username, password)
	var lockedErr *AccountLockedError
	if !errors.As(err, &lockedErr) {
		t.Fatalf("expected *AccountLockedError after exceeding MaxFailedAttempts, got %v", err)
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Error("AccountLockedError should satisfy errors.Is(err, ErrAccountLocked)")
	}
	if !lockedErr.Until.After(time.Now()) {
		t.Error("expected AccountLockedError.Until to be in the future")
	}
}
