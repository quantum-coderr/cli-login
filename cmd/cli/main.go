// Phase 3: connect to Postgres, run migrations, then exercise core auth +
// TOTP/2FA logic (see the TEMPORARY block below). No interactive CLI yet
// — that's Phase 4.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	// Used only to simulate an authenticator app producing a code from a
	// secret — the real verification path is internal/totp.VerifyCode,
	// used internally by internal/auth. Aliased since internal/totp is
	// also named "totp".
	pqotp "github.com/pquerna/otp/totp"

	"github.com/quantum-coderr/cli-login/internal/auth"
	"github.com/quantum-coderr/cli-login/internal/config"
	"github.com/quantum-coderr/cli-login/internal/db"
)

func main() {
	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is not set")
	}

	conn, err := db.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer conn.Close()

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}

	if err := db.RunMigrations(conn, migrationsDir); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	log.Println("Connected and migrated successfully")

	// Apply lockout/session policy from env (MAX_FAILED_ATTEMPTS /
	// LOCKOUT_DURATION_MINUTES / SESSION_TIMEOUT_MINUTES) before any
	// login is attempted.
	auth.Configure(cfg.MaxFailedAttempts, cfg.LockoutDuration, cfg.SessionTimeout)

	// -----------------------------------------------------------------
	// TEMPORARY - remove in Phase 4.
	//
	// Phase 4 replaces this whole block with the real interactive CLI.
	// This just exercises the auth/session/TOTP logic end-to-end against
	// the real DB so Phases 2-3 can be verified without a CLI: register a
	// test user (or note it already exists on a re-run), log in, show a
	// wrong-password attempt correctly failing, then set up and confirm
	// TOTP and exercise CompleteLogin (Phase 3) through to a session.
	// -----------------------------------------------------------------
	ctx := context.Background()
	const testUsername = "phase2_test_user"
	const testPassword = "correct-horse-battery-staple"

	user, err := auth.RegisterUser(ctx, conn, testUsername, testPassword)
	switch {
	case err == nil:
		fmt.Printf("[TEMP] registered user %q (id=%s)\n", user.Username, user.ID)
	case errors.Is(err, auth.ErrUserExists):
		fmt.Printf("[TEMP] user %q already exists, skipping registration\n", testUsername)
	default:
		log.Fatalf("[TEMP] RegisterUser failed: %v", err)
	}

	loggedIn, err := auth.LoginUser(ctx, conn, testUsername, testPassword)
	if err != nil {
		log.Fatalf("[TEMP] LoginUser (correct password) failed: %v", err)
	}
	fmt.Printf("[TEMP] login succeeded for %q (last_login_at=%s)\n", loggedIn.Username, loggedIn.LastLoginAt.Time)

	if _, err := auth.LoginUser(ctx, conn, testUsername, "wrong-password"); err != nil {
		fmt.Printf("[TEMP] login with wrong password correctly failed: %v\n", err)
	} else {
		log.Fatal("[TEMP] login with wrong password unexpectedly succeeded")
	}

	// --- Phase 3: TOTP / 2FA ---
	//
	// If a previous run of this temp block already enabled TOTP on the
	// test user, disable it first so Enable -> Confirm demonstrates
	// fresh every time (using the password as the disable verification).
	if loggedIn.TOTPEnabled {
		if err := auth.DisableTOTP(ctx, conn, loggedIn.ID, auth.TOTPDisableVerification{Password: testPassword}); err != nil {
			log.Fatalf("[TEMP] DisableTOTP (resetting state from a previous run) failed: %v", err)
		}
		fmt.Println("[TEMP] disabled TOTP left over from a previous run, to demo Enable/Confirm fresh")
	}

	secret, otpauthURL, err := auth.EnableTOTP(ctx, conn, loggedIn.ID)
	if err != nil {
		log.Fatalf("[TEMP] EnableTOTP failed: %v", err)
	}
	fmt.Printf("[TEMP] TOTP secret generated for %q (not yet active)\n", testUsername)
	fmt.Printf("[TEMP] otpauth URL: %s\n", otpauthURL)

	// Simulate what an authenticator app would produce after scanning the
	// otpauth URL/secret above — using pquerna/otp's GenerateCode directly,
	// independent of our own internal/totp.VerifyCode, so this is a real
	// end-to-end check rather than the code checking itself.
	code, err := pqotp.GenerateCode(secret, time.Now())
	if err != nil {
		log.Fatalf("[TEMP] GenerateCode failed: %v", err)
	}

	if err := auth.ConfirmTOTP(ctx, conn, loggedIn.ID, code); err != nil {
		log.Fatalf("[TEMP] ConfirmTOTP failed: %v", err)
	}
	fmt.Printf("[TEMP] TOTP confirmed and active for %q\n", testUsername)

	if _, _, err := auth.EnableTOTP(ctx, conn, loggedIn.ID); errors.Is(err, auth.ErrTOTPAlreadyEnabled) {
		fmt.Println("[TEMP] EnableTOTP on an already-enabled account correctly rejected")
	} else {
		log.Fatalf("[TEMP] expected ErrTOTPAlreadyEnabled, got: %v", err)
	}

	// CompleteLogin is what Phase 4 will actually call — exercise it here
	// since it's the real integration point for everything above.
	if _, _, err := auth.CompleteLogin(ctx, conn, testUsername, testPassword, ""); errors.Is(err, auth.ErrTOTPRequired) {
		fmt.Println("[TEMP] CompleteLogin without a TOTP code correctly requires one")
	} else {
		log.Fatalf("[TEMP] expected ErrTOTPRequired, got: %v", err)
	}

	if _, _, err := auth.CompleteLogin(ctx, conn, testUsername, testPassword, "000000"); errors.Is(err, auth.ErrInvalidTOTPCode) {
		fmt.Println("[TEMP] CompleteLogin with a wrong TOTP code correctly rejected")
	} else {
		log.Fatalf("[TEMP] expected ErrInvalidTOTPCode, got: %v", err)
	}

	loginCode, err := pqotp.GenerateCode(secret, time.Now())
	if err != nil {
		log.Fatalf("[TEMP] GenerateCode failed: %v", err)
	}
	finalUser, sess, err := auth.CompleteLogin(ctx, conn, testUsername, testPassword, loginCode)
	if err != nil {
		log.Fatalf("[TEMP] CompleteLogin with a valid TOTP code failed: %v", err)
	}
	fmt.Printf("[TEMP] CompleteLogin succeeded for %q, session expires %s\n",
		finalUser.Username, sess.ExpiresAt.Format(time.RFC3339))
	// -----------------------------------------------------------------
	// END TEMPORARY
	// -----------------------------------------------------------------
}
