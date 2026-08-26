package auth

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors so callers (the future CLI layer) can branch with
// errors.Is() instead of matching error strings.
var (
	ErrInvalidUsername    = errors.New("auth: username must not be empty")
	ErrWeakPassword       = errors.New("auth: password does not meet minimum requirements")
	ErrUserExists         = errors.New("auth: username is already taken")
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrAccountLocked is the sentinel to check with errors.Is(). The
	// actual error returned by LoginUser is *AccountLockedError, which
	// carries the unlock time and satisfies errors.Is(err, ErrAccountLocked).
	ErrAccountLocked = errors.New("auth: account is locked")

	// TOTP / 2FA (Phase 3).
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

func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("auth: account locked, try again at %s", e.Until.Format(time.RFC3339))
}

// Is lets errors.Is(err, ErrAccountLocked) succeed for any *AccountLockedError.
func (e *AccountLockedError) Is(target error) bool {
	return target == ErrAccountLocked
}
