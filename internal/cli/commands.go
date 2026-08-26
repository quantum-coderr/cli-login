package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/quantum-coderr/cli-login/internal/auth"
	"github.com/quantum-coderr/cli-login/internal/session"
)

// commandDef is one entry in a state's command list: name, a `help`
// summary, and the handler. Also drives tab-completion.
type commandDef struct {
	name    string
	summary string
	run     func(ctx context.Context) error
}

func (c *CLI) loggedOutCommands() []commandDef {
	return []commandDef{
		{"register", "create a new account", c.cmdRegister},
		{"login", "log in to your account", c.cmdLogin},
		{"help", "show available commands", c.wrap(c.cmdHelp)},
		{"exit", "quit the CLI", c.cmdExit},
	}
}

func (c *CLI) loggedInCommands() []commandDef {
	return []commandDef{
		{"whoami", "show your account details", c.wrap(c.cmdWhoami)},
		{"enable-2fa", "turn on two-factor authentication", c.cmdEnableTOTP},
		{"disable-2fa", "turn off two-factor authentication", c.cmdDisableTOTP},
		{"logout", "log out of your account", c.cmdLogout},
		{"help", "show available commands", c.wrap(c.cmdHelp)},
		{"exit", "log out and quit the CLI", c.cmdExit},
	}
}

// currentCommands is the source of truth for what's valid right now,
// used for dispatch, tab-completion, and `help` alike.
func (c *CLI) currentCommands() []commandDef {
	if c.loggedIn() {
		return c.loggedInCommands()
	}
	return c.loggedOutCommands()
}

func (c *CLI) findCommand(name string) (commandDef, bool) {
	for _, cmd := range c.currentCommands() {
		if cmd.name == name {
			return cmd, true
		}
	}
	return commandDef{}, false
}

// wrap adapts a no-error, no-context function to commandDef's handler shape.
func (c *CLI) wrap(fn func()) func(context.Context) error {
	return func(context.Context) error {
		fn()
		return nil
	}
}

// isSixDigitCode rejects obviously-invalid TOTP input before we bother
// verifying it or hitting the database.
func isSixDigitCode(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// --- register ---

func (c *CLI) cmdRegister(ctx context.Context) error {
	username, err := c.readLine("Username: ")
	if err != nil {
		return cancelOr(err)
	}

	password, err := c.readPassword("Password: ")
	if err != nil {
		return cancelOr(err)
	}
	confirm, err := c.readPassword("Confirm password: ")
	if err != nil {
		return cancelOr(err)
	}
	if password != confirm {
		fmt.Println("Passwords do not match.")
		return nil
	}

	if _, err := auth.RegisterUser(ctx, c.db, username, password); err != nil {
		fmt.Println(errorMessage(err))
		return nil
	}

	fmt.Printf("Account %q created. Use 'login' to sign in.\n", username)
	return nil
}

// --- login ---

func (c *CLI) cmdLogin(ctx context.Context) error {
	username, err := c.readLine("Username: ")
	if err != nil {
		return cancelOr(err)
	}
	password, err := c.readPassword("Password: ")
	if err != nil {
		return cancelOr(err)
	}

	user, sess, loginErr := auth.CompleteLogin(ctx, c.db, username, password, "")
	if errors.Is(loginErr, auth.ErrTOTPRequired) {
		code, err := c.readLine("Enter 2FA code: ")
		if err != nil {
			return cancelOr(err)
		}
		if !isSixDigitCode(code) {
			fmt.Println("Authentication code must be exactly 6 digits.")
			return nil
		}
		user, sess, loginErr = auth.CompleteLogin(ctx, c.db, username, password, code)
	}
	if loginErr != nil {
		fmt.Println(errorMessage(loginErr))
		return nil
	}

	c.user = user
	c.session = sess
	fmt.Println("Login successful.")
	c.cmdWhoami() // auto-show details on login, per spec
	return nil
}

// --- whoami ---

func (c *CLI) cmdWhoami() {
	u, s := c.user, c.session

	mfa := "disabled"
	if u.TOTPEnabled {
		mfa = "enabled"
	}
	lastLogin := "N/A"
	if u.LastLoginAt.Valid {
		lastLogin = u.LastLoginAt.Time.Format(time.RFC1123)
	}

	fmt.Println()
	fmt.Printf("  %-17s %s\n", "Username:", u.Username)
	fmt.Printf("  %-17s %s\n", "Registered:", u.CreatedAt.Format(time.RFC1123))
	fmt.Printf("  %-17s %s\n", "2FA:", mfa)
	fmt.Printf("  %-17s %s\n", "Last login:", lastLogin)
	fmt.Printf("  %-17s %s\n", "Session expires:", s.ExpiresAt.Format(time.RFC1123))
	fmt.Println()
}

// --- enable-2fa ---

func (c *CLI) cmdEnableTOTP(ctx context.Context) error {
	secret, otpauthURL, err := auth.EnableTOTP(ctx, c.db, c.user.ID)
	if err != nil {
		fmt.Println(errorMessage(err))
		return nil
	}

	fmt.Println()
	fmt.Println("Scan this with your authenticator app (Google Authenticator, Authy, etc.):")
	fmt.Println()
	if qr, err := renderQRCode(otpauthURL); err == nil {
		fmt.Println(qr)
	} else {
		fmt.Println("Could not render a QR code, use the secret below instead.")
		fmt.Println()
	}

	fmt.Println("If you can't scan it, enter the secret manually:")
	fmt.Println()
	fmt.Printf("  Secret:      %s\n", secret)
	fmt.Printf("  otpauth URL: %s\n", otpauthURL)
	fmt.Println()

	code, err := c.readLine("Enter the code from your authenticator app to confirm: ")
	if err != nil {
		return cancelOr(err)
	}
	if !isSixDigitCode(code) {
		fmt.Println("Authentication code must be exactly 6 digits.")
		return nil
	}

	if err := auth.ConfirmTOTP(ctx, c.db, c.user.ID, code); err != nil {
		fmt.Println(errorMessage(err))
		return nil
	}

	c.user.TOTPEnabled = true // keep local state in sync without a re-fetch
	fmt.Println("Two-factor authentication is now enabled.")
	return nil
}

// --- disable-2fa ---

func (c *CLI) cmdDisableTOTP(ctx context.Context) error {
	// c.user stays fresh in-memory, so this check needs no DB round-trip
	// and avoids prompting for a method we'd reject anyway.
	if !c.user.TOTPEnabled {
		fmt.Println("Two-factor authentication is not currently enabled on this account.")
		return nil
	}

	choice, err := c.readLine("Verify with 'p' (password) or 't' (TOTP code): ")
	if err != nil {
		return cancelOr(err)
	}

	var verification auth.TOTPDisableVerification
	switch strings.ToLower(choice) {
	case "p", "password":
		pw, err := c.readPassword("Password: ")
		if err != nil {
			return cancelOr(err)
		}
		verification.Password = pw
	case "t", "totp", "code":
		code, err := c.readLine("TOTP code: ")
		if err != nil {
			return cancelOr(err)
		}
		if !isSixDigitCode(code) {
			fmt.Println("Authentication code must be exactly 6 digits.")
			return nil
		}
		verification.TOTPCode = code
	default:
		fmt.Println("Please choose 'p' (password) or 't' (TOTP code).")
		return nil
	}

	if err := auth.DisableTOTP(ctx, c.db, c.user.ID, verification); err != nil {
		// ErrInvalidCredentials here always means "wrong password", disable-2fa
		// never asks for a username, so the generic login-style wording
		// (errorMessage's default for this error) would be confusing.
		if errors.Is(err, auth.ErrInvalidCredentials) {
			fmt.Println("Incorrect password.")
		} else {
			fmt.Println(errorMessage(err))
		}
		return nil
	}

	c.user.TOTPEnabled = false
	fmt.Println("Two-factor authentication is now disabled.")
	return nil
}

// --- logout ---

func (c *CLI) cmdLogout(ctx context.Context) error {
	if err := session.InvalidateSession(ctx, c.db, c.session.Token); err != nil {
		// Still clear local state, don't trap the user in a logged-in CLI.
		// Worded as its own thing rather than the generic errorMessage()
		// text, which would read oddly right next to "Logged out." below.
		fmt.Println("Could not confirm the session was cleared on the server, logging out locally anyway.")
	}
	c.clearSession()
	fmt.Println("Logged out.")
	return nil
}

// --- help ---

func (c *CLI) cmdHelp() {
	fmt.Println()
	fmt.Println("Available commands:")
	for _, cmd := range c.currentCommands() {
		fmt.Printf("  %-13s %s\n", cmd.name, cmd.summary)
	}
	fmt.Println()
}

// --- exit ---

func (c *CLI) cmdExit(ctx context.Context) error {
	c.quit(ctx)
	return errQuit
}
