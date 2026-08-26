// Package config reads process configuration from environment variables
// once at startup, applying sensible defaults for anything unset.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds everything Phase 2's auth/session logic needs. It's meant
// to be loaded once in main() and threaded through (or used to configure
// package-level policy, e.g. auth.Configure) rather than re-read per call.
type Config struct {
	DatabaseURL string

	// MaxFailedAttempts is how many consecutive failed logins are allowed
	// before an account is locked.
	MaxFailedAttempts int
	// LockoutDuration is how long an account stays locked after hitting
	// MaxFailedAttempts.
	LockoutDuration time.Duration
	// SessionTimeout is how long a session is valid for after creation.
	SessionTimeout time.Duration
}

// Load reads Config from the environment. Missing/empty vars fall back to
// defaults rather than erroring — only DATABASE_URL has no sane default,
// and callers are expected to check for that themselves (main.go already
// does, via db.Connect failing on an empty DSN).
func Load() Config {
	return Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		MaxFailedAttempts: getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:   time.Duration(getEnvInt("LOCKOUT_DURATION_MINUTES", 15)) * time.Minute,
		SessionTimeout:    time.Duration(getEnvInt("SESSION_TIMEOUT_MINUTES", 30)) * time.Minute,
	}
}

func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}
