// Package db handles the Postgres connection and running SQL migrations.
package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	// Registers the pgx driver so the rest of the app can use plain database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Connect opens a connection to Postgres and retries a few times if it
// is not ready yet, since the db container can report healthy before
// Postgres actually accepts connections.
func Connect(dsn string) (*sql.DB, error) {
	const (
		maxAttempts = 5
		baseDelay   = 2 * time.Second
	)

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		// sql.Open only validates the DSN, it doesn't dial anything.
		return nil, fmt.Errorf("db: open: %w", err)
	}

	var pingErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		pingErr = conn.Ping()
		if pingErr == nil {
			return conn, nil
		}

		if attempt == maxAttempts {
			break
		}

		delay := baseDelay * time.Duration(attempt) // 2s, 4s, 6s, 8s
		fmt.Printf("db: ping failed (attempt %d/%d): %v — retrying in %s\n", attempt, maxAttempts, pingErr, delay)
		time.Sleep(delay)
	}

	conn.Close()
	return nil, fmt.Errorf("db: could not reach database after %d attempts: %w", maxAttempts, pingErr)
}

// RunMigrations applies any unapplied "*.up.sql" files in dir, tracking
// progress in a schema_migrations table so it's safe to call on every
// startup.
func RunMigrations(conn *sql.DB, dir string) error {
	if _, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return fmt.Errorf("db: create schema_migrations: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("db: read migrations dir %q: %w", dir, err)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		files = append(files, e.Name())
	}
	// Zero-padded filenames sort correctly as plain strings.
	sort.Strings(files)

	for _, filename := range files {
		version := strings.TrimSuffix(filename, ".up.sql")

		var alreadyApplied bool
		if err := conn.QueryRow(
			`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
		).Scan(&alreadyApplied); err != nil {
			return fmt.Errorf("db: check migration %q: %w", version, err)
		}
		if alreadyApplied {
			continue
		}

		sqlBytes, err := os.ReadFile(filepath.Join(dir, filename))
		if err != nil {
			return fmt.Errorf("db: read migration %q: %w", filename, err)
		}

		// One transaction so a failed migration is never left half-applied.
		tx, err := conn.Begin()
		if err != nil {
			return fmt.Errorf("db: begin tx for %q: %w", version, err)
		}

		if _, err := tx.Exec(string(sqlBytes)); err != nil {
			tx.Rollback()
			return fmt.Errorf("db: apply migration %q: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			tx.Rollback()
			return fmt.Errorf("db: record migration %q: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("db: commit migration %q: %w", version, err)
		}

		fmt.Printf("db: applied migration %s\n", version)
	}

	return nil
}
