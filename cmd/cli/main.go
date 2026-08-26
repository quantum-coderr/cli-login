// Entry point: connects to Postgres, runs migrations, then hands off to
// the interactive prompt in internal/cli.
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

	// Must happen before the CLI starts serving logins.
	auth.Configure(cfg.MaxFailedAttempts, cfg.LockoutDuration, cfg.SessionTimeout, cfg.MinPasswordLength)

	c, err := cli.NewCLI(conn)
	if err != nil {
		log.Fatalf("failed to start CLI: %v", err)
	}
	defer c.Close()

	// No signal handling here: internal/cli.Run already handles Ctrl+C
	// and Ctrl+D itself via readline's raw mode.
	if err := c.Run(context.Background()); err != nil {
		log.Fatalf("cli exited with error: %v", err)
	}
}
