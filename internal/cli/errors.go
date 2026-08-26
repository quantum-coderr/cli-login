package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/quantum-coderr/cli-login/internal/auth"
	"github.com/quantum-coderr/cli-login/internal/session"
)

// errorMessage maps known auth/session errors to a user-facing string,
// so a raw Go error never reaches the terminal.
func errorMessage(err error) string {
	if err == nil {
		return ""
	}

	var lockedErr *auth.AccountLockedError
	switch {
	case errors.As(err, &lockedErr):
		return fmt.Sprintf("Account is locked. Try again at %s.", lockedErr.Until.Format(time.RFC1123))
	case errors.Is(err, auth.ErrUserExists):
		return "That username is already taken."
	case errors.Is(err, auth.ErrInvalidUsername):
		return "Username cannot be empty."
	case errors.Is(err, auth.ErrUsernameTooLong):
		return fmt.Sprintf("Username must be at most %d characters.", auth.MaxUsernameLength)
	case errors.Is(err, auth.ErrWeakPassword):
		return fmt.Sprintf("Password must be at least %d characters.", auth.MinPasswordLength)
	case errors.Is(err, auth.ErrPasswordTooLong):
		return fmt.Sprintf("Password must be at most %d characters.", auth.MaxPasswordLength)
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "Invalid username or password."
	case errors.Is(err, auth.ErrInvalidTOTPCode):
		return "Invalid authentication code."
	case errors.Is(err, auth.ErrTOTPRequired):
		return "A two-factor code is required."
	case errors.Is(err, auth.ErrTOTPAlreadyEnabled):
		return "Two-factor authentication is already enabled."
	case errors.Is(err, auth.ErrTOTPNotEnabled):
		return "Two-factor authentication is not enabled."
	case errors.Is(err, session.ErrSessionNotFound):
		return "Session is no longer valid."
	default:
		// Unknown error, still never leak the raw text.
		return "Something went wrong. Please try again."
	}
}
