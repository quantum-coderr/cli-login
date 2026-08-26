// Phase 2: connect to Postgres, run migrations, then exercise core auth
// logic (see the TEMPORARY block below). No interactive CLI yet — that's
// Phase 4.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

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

	// Apply lockout policy from env (MAX_FAILED_ATTEMPTS /
	// LOCKOUT_DURATION_MINUTES) before any login is attempted.
	auth.Configure(cfg.MaxFailedAttempts, cfg.LockoutDuration)

	// -----------------------------------------------------------------
	// TEMPORARY - remove in Phase 4.
	//
	// Phase 4 replaces this whole block with the real interactive CLI.
	// This just exercises RegisterUser/LoginUser end-to-end against the
	// real DB so Phase 2 can be verified without a CLI: register a test
	// user (or note it already exists on a re-run), log in with the
	// correct password, then show a wrong-password attempt correctly
	// failing.
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
	// -----------------------------------------------------------------
	// END TEMPORARY
	// -----------------------------------------------------------------
}
