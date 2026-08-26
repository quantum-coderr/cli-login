package auth

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors so callers can branch with errors.Is() instead of
// matching error strings.
var (
	ErrInvalidUsername    = errors.New("auth: username must not be empty")
	ErrUsernameTooLong    = errors.New("auth: username is too long")
	ErrWeakPassword       = errors.New("auth: password does not meet minimum requirements")
	ErrPasswordTooLong    = errors.New("auth: password is too long")
	ErrUserExists         = errors.New("auth: username is already taken")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrAccountLocked is the sentinel to check. LoginUser actually
	// returns *AccountLockedError, which satisfies errors.Is against it.
	ErrAccountLocked = errors.New("auth: account is locked")

	// TOTP errors.
	ErrTOTPRequired       = errors.New("auth: TOTP code required")
	ErrInvalidTOTPCode    = errors.New("auth: invalid TOTP code")
	ErrTOTPAlreadyEnabled = errors.New("auth: TOTP is already enabled")
	ErrTOTPNotEnabled     = errors.New("auth: TOTP is not enabled")
)

// AccountLockedError reports that an account is locked, and until when.
// It wraps ErrAccountLocked (via Is) so callers can do either:
//
//	errors.Is(err, auth.ErrAccountLocked)              // just check the kind
//	errors.As(err, &lockedErr); lockedErr.Until         // get the unlock time
type AccountLockedError struct {
	Until time.Time
}

// Error implements the error interface.
func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("auth: account locked, try again at %s", e.Until.Format(time.RFC3339))
}

// Is lets errors.Is(err, ErrAccountLocked) succeed for any *AccountLockedError.
func (e *AccountLockedError) Is(target error) bool {
	return target == ErrAccountLocked
}
