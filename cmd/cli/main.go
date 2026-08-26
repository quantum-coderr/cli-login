// Phase 4: connect to Postgres, run migrations, then hand off to the
// interactive CLI (internal/cli). This is the real entry point now — the
// Phase 2/3 TEMPORARY verification blocks are gone.
package main

import (
	"context"
	"log"
	"os"

	"github.com/quantum-coderr/cli-login/internal/auth"
	"github.com/quantum-coderr/cli-login/internal/cli"
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

	// Apply lockout/session policy from env (MAX_FAILED_ATTEMPTS /
	// LOCKOUT_DURATION_MINUTES / SESSION_TIMEOUT_MINUTES) before serving
	// any logins.
	auth.Configure(cfg.MaxFailedAttempts, cfg.LockoutDuration, cfg.SessionTimeout, cfg.MinPasswordLength)

	c, err := cli.NewCLI(conn)
	if err != nil {
		log.Fatalf("failed to start CLI: %v", err)
	}
	defer c.Close()

	// Ctrl+C/Ctrl+D typed at the prompt are handled inside internal/cli.Run
	// itself: readline puts the terminal in raw mode while reading, so the
	// kernel never generates a SIGINT for Ctrl+C in the first place — it
	// arrives as a plain byte that Readline() turns into ErrInterrupt, and
	// Ctrl+D arrives as io.EOF. Both are handled there as a graceful exit
	// (invalidating the session first if logged in). No OS-level signal
	// handler is needed for that; installing one here would only catch
	// signals delivered outside readline's raw-mode read (e.g. `docker
	// stop`), which should keep the normal Go default of terminating the
	// process rather than being caught and left unhandled.
	if err := c.Run(context.Background()); err != nil {
		log.Fatalf("cli exited with error: %v", err)
	}
}
