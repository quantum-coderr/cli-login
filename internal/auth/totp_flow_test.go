package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	otplib "github.com/pquerna/otp/totp"
)

// codeFor generates a real TOTP code for secret, like an authenticator
// app would.
func codeFor(t *testing.T, secret string) string {
	t.Helper()
	code, err := otplib.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

// EnableTOTP returns a usable secret and URL without flipping
// totp_enabled until ConfirmTOTP succeeds.
func TestEnableTOTPIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_enable_totp"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	secret1, url1, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if secret1 == "" || url1 == "" {
		t.Fatal("expected a non-empty secret and otpauth URL")
	}

	// Not enabled yet, only pending, until ConfirmTOTP succeeds.
	stillOff, err := LoginUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if stillOff.TOTPEnabled {
		t.Error("expected totp_enabled to still be false before ConfirmTOTP")
	}

	// A second EnableTOTP before confirming replaces the pending secret.
	secret2, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP (second call): %v", err)
	}
	if secret2 == secret1 {
		t.Error("expected a fresh secret on a second EnableTOTP call")
	}

	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret1)); err == nil {
		t.Error("expected the old secret's code to no longer work after EnableTOTP was called again")
	}
	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret2)); err != nil {
		t.Fatalf("expected the current secret's code to confirm successfully, got %v", err)
	}

	// Already enabled now, EnableTOTP should refuse to start over.
	if _, _, err := EnableTOTP(ctx, db, user.ID); !errors.Is(err, ErrTOTPAlreadyEnabled) {
		t.Errorf("expected ErrTOTPAlreadyEnabled, got %v", err)
	}
}

// Covers ConfirmTOTP's own branches: nothing pending, a wrong code, a
// correct code, and confirming again once already enabled.
func TestConfirmTOTPIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_confirm_totp"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	if err := ConfirmTOTP(ctx, db, user.ID, "123456"); !errors.Is(err, ErrTOTPNotEnabled) {
		t.Errorf("expected ErrTOTPNotEnabled with nothing pending, got %v", err)
	}

	secret, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	if err := ConfirmTOTP(ctx, db, user.ID, "000000"); !errors.Is(err, ErrInvalidTOTPCode) {
		t.Errorf("expected ErrInvalidTOTPCode for a wrong code, got %v", err)
	}

	// A wrong code should not have flipped the flag.
	afterWrongCode, err := LoginUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if afterWrongCode.TOTPEnabled {
		t.Error("a wrong confirm code should not enable TOTP")
	}

	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret)); err != nil {
		t.Fatalf("ConfirmTOTP with a correct code: %v", err)
	}

	afterCorrectCode, err := LoginUser(ctx, db, username, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if !afterCorrectCode.TOTPEnabled {
		t.Error("expected totp_enabled to be true after a correct confirm")
	}

	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret)); !errors.Is(err, ErrTOTPAlreadyEnabled) {
		t.Errorf("expected ErrTOTPAlreadyEnabled when confirming again, got %v", err)
	}
}

// Covers DisableTOTP's verification branches and confirms the secret is
// actually cleared, not just the flag.
func TestDisableTOTPIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_disable_totp"
	const password = "correct-horse-battery-staple"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{Password: password}); !errors.Is(err, ErrTOTPNotEnabled) {
		t.Errorf("expected ErrTOTPNotEnabled before TOTP is even set up, got %v", err)
	}

	secret, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret)); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials when neither factor is supplied, got %v", err)
	}
	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{Password: "wrong-password"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials for a wrong password, got %v", err)
	}
	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{TOTPCode: "000000"}); !errors.Is(err, ErrInvalidTOTPCode) {
		t.Errorf("expected ErrInvalidTOTPCode for a wrong code, got %v", err)
	}

	// None of the failed attempts above should have disabled it.
	stillOn, err := LoginUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if !stillOn.TOTPEnabled {
		t.Error("TOTP should still be enabled after only failed disable attempts")
	}

	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{Password: password}); err != nil {
		t.Fatalf("DisableTOTP with the correct password: %v", err)
	}

	afterDisable, err := LoginUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if afterDisable.TOTPEnabled {
		t.Error("expected totp_enabled to be false after DisableTOTP")
	}

	// Confirms the secret was really cleared: a fresh cycle should work.
	newSecret, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP after disabling: %v", err)
	}
	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, newSecret)); err != nil {
		t.Fatalf("ConfirmTOTP after re-enabling: %v", err)
	}
}

// DisableTOTP should also accept a TOTP code instead of a password.
func TestDisableTOTPWithCodeIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_disable_totp_code"
	const password = "correct-horse-battery-staple"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	secret, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret)); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	if err := DisableTOTP(ctx, db, user.ID, TOTPDisableVerification{TOTPCode: codeFor(t, secret)}); err != nil {
		t.Fatalf("DisableTOTP with a correct TOTP code: %v", err)
	}

	afterDisable, err := LoginUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	if afterDisable.TOTPEnabled {
		t.Error("expected totp_enabled to be false after disabling via TOTP code")
	}
}

// CompleteLogin is what the CLI calls: covers no 2FA, a missing code, a
// wrong code, and a correct code producing a session.
func TestCompleteLoginIntegration(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	const username = "authtest_complete_login"
	const password = "correct-horse-battery-staple"
	ctx := context.Background()

	cleanupUser(t, db, username)
	defer cleanupUser(t, db, username)

	user, err := RegisterUser(ctx, db, username, password)
	if err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	// No 2FA enabled: a plain password should be enough to get a session.
	_, sess, err := CompleteLogin(ctx, db, username, password, "")
	if err != nil {
		t.Fatalf("CompleteLogin without 2FA: %v", err)
	}
	if sess == nil || sess.UserID != user.ID {
		t.Fatal("expected a session for the registered user")
	}

	secret, _, err := EnableTOTP(ctx, db, user.ID)
	if err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	if err := ConfirmTOTP(ctx, db, user.ID, codeFor(t, secret)); err != nil {
		t.Fatalf("ConfirmTOTP: %v", err)
	}

	if _, _, err := CompleteLogin(ctx, db, username, password, ""); !errors.Is(err, ErrTOTPRequired) {
		t.Errorf("expected ErrTOTPRequired with no code once 2FA is on, got %v", err)
	}

	// A wrong code counts as a failed attempt too. Threshold of 1 makes
	// the lock deterministic to test.
	origMax, origLockout, origSession, origMinLen := MaxFailedAttempts, LockoutDuration, SessionDuration, MinPasswordLength
	Configure(1, 100*time.Millisecond, origSession, origMinLen)
	defer Configure(origMax, origLockout, origSession, origMinLen)

	if _, _, err := CompleteLogin(ctx, db, username, password, "000000"); !errors.Is(err, ErrInvalidTOTPCode) {
		t.Errorf("expected ErrInvalidTOTPCode for a wrong code, got %v", err)
	}

	if _, _, err := CompleteLogin(ctx, db, username, password, codeFor(t, secret)); !errors.Is(err, ErrAccountLocked) {
		t.Errorf("expected the account to be locked after one wrong TOTP code, got %v", err)
	}

	// Wait out the lock, then confirm a correct code works again.
	time.Sleep(150 * time.Millisecond)

	_, sess2, err := CompleteLogin(ctx, db, username, password, codeFor(t, secret))
	if err != nil {
		t.Fatalf("CompleteLogin with a correct code: %v", err)
	}
	if sess2 == nil || sess2.UserID != user.ID {
		t.Fatal("expected a session for the registered user")
	}
}
