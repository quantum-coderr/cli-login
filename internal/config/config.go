// Package config reads process configuration from environment variables
// once at startup, applying sensible defaults for anything unset.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds everything the auth and session logic needs, loaded once
// at startup rather than re-read per call.
type Config struct {
	// DatabaseURL is the Postgres connection string.
	DatabaseURL string

	// MaxFailedAttempts is how many failed logins lock an account.
	MaxFailedAttempts int
	// LockoutDuration is how long an account stays locked.
	LockoutDuration time.Duration
	// SessionTimeout is how long a session stays valid.
	SessionTimeout time.Duration
	// MinPasswordLength is the shortest password RegisterUser accepts.
	MinPasswordLength int
}

// Load reads Config from the environment, falling back to defaults for
// anything unset. DatabaseURL has no default, callers must check for it.
func Load() Config {
	return Config{
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		MaxFailedAttempts: getEnvInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:   time.Duration(getEnvInt("LOCKOUT_DURATION_MINUTES", 15)) * time.Minute,
		SessionTimeout:    time.Duration(getEnvInt("SESSION_TIMEOUT_MINUTES", 30)) * time.Minute,
		MinPasswordLength: getEnvInt("MIN_PASSWORD_LENGTH", 8),
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
