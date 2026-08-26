// Package cli implements the interactive REPL, a thin layer over
// auth/session/totp: no SQL or business rules here.
package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/chzyer/readline"

	"github.com/quantum-coderr/cli-login/internal/models"
	"github.com/quantum-coderr/cli-login/internal/session"
)

// loggedOutPrompt is shown when there's no active session. The logged-in
// prompt is built per-user (see currentPrompt), e.g. "user@alice> ".
const loggedOutPrompt = "login> "

// errQuit signals "the user asked to exit" up through command dispatch to
// Run, which treats it as a normal (non-error) end of the loop.
var errQuit = errors.New("cli: quit")

// errCancelled marks a sub-prompt aborted with Ctrl+C/Ctrl+D. cancelOr
// turns it into a printed message, it never escapes a command handler.
var errCancelled = errors.New("cli: cancelled")

// CLI holds the session state: the DB handle, and the logged-in user and
// session, if any. Both nil means logged out.
type CLI struct {
	db      *sql.DB
	rl      *readline.Instance
	user    *models.User
	session *models.Session
}

// NewCLI builds a CLI ready to Run. Call Close when done.
func NewCLI(db *sql.DB) (*CLI, error) {
	c := &CLI{db: db}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          loggedOutPrompt,
		HistoryLimit:    1000,
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		AutoComplete:    &commandCompleter{cli: c},
	})
	if err != nil {
		return nil, fmt.Errorf("cli: init readline: %w", err)
	}
	c.rl = rl

	return c, nil
}

// Close releases the underlying terminal/readline resources.
func (c *CLI) Close() error {
	return c.rl.Close()
}

// Run is the interactive loop: read a command, dispatch it, repeat until
// the user exits.
func (c *CLI) Run(ctx context.Context) error {
	fmt.Println("CLI Login System — type 'help' for a list of commands.")

	for {
		c.checkSessionExpiry(ctx)
		c.rl.SetPrompt(c.currentPrompt())

		line, err := c.rl.Readline()
		switch {
		case errors.Is(err, readline.ErrInterrupt):
			// Ctrl+C on an empty line means quit; with text typed, clear it.
			if len(strings.TrimSpace(line)) == 0 {
				c.quit(ctx)
				return nil
			}
			continue
		case errors.Is(err, io.EOF):
			// Ctrl+D
			c.quit(ctx)
			return nil
		case err != nil:
			return fmt.Errorf("cli: read line: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		cmd, ok := c.findCommand(line)
		if !ok {
			fmt.Printf("Unknown command: %q. Type 'help' for a list of commands.\n", line)
			continue
		}

		if err := cmd.run(ctx); err != nil {
			if errors.Is(err, errQuit) {
				return nil
			}
			// Not a mapped error, those print inside the handler already.
			fmt.Printf("Internal error: %v\n", err)
		}
	}
}

// quit invalidates the session if logged in, then says goodbye. Shared
// by the `exit` command and Ctrl+C/Ctrl+D.
func (c *CLI) quit(ctx context.Context) {
	fmt.Println()
	if c.loggedIn() {
		_ = session.InvalidateSession(ctx, c.db, c.session.Token)
		c.clearSession()
	}
	fmt.Println("Goodbye!")
}

// checkSessionExpiry drops back to the logged-out state if the current
// session has expired, rather than letting stale state persist into the
// next command.
func (c *CLI) checkSessionExpiry(ctx context.Context) {
	if !c.loggedIn() {
		return
	}
	if _, err := session.ValidateSession(ctx, c.db, c.session.Token); err != nil {
		fmt.Println("Session expired, please log in again.")
		c.clearSession()
	}
}

func (c *CLI) loggedIn() bool {
	return c.user != nil && c.session != nil
}

func (c *CLI) clearSession() {
	c.user = nil
	c.session = nil
}

func (c *CLI) currentPrompt() string {
	if c.loggedIn() {
		return fmt.Sprintf("user@%s> ", c.user.Username)
	}
	return loggedOutPrompt
}

// readLine shows a one-off prompt and restores the normal one after.
// Ctrl+C/Ctrl+D here cancel just this command, see errCancelled.
func (c *CLI) readLine(prompt string) (string, error) {
	c.rl.SetPrompt(prompt)
	defer c.rl.SetPrompt(c.currentPrompt())

	line, err := c.rl.Readline()
	if err != nil {
		if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
			return "", errCancelled
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// readPassword is readLine's masked-input counterpart: characters aren't
// echoed, and the value never touches command history.
func (c *CLI) readPassword(prompt string) (string, error) {
	pw, err := c.rl.ReadPassword(prompt)
	if err != nil {
		if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
			return "", errCancelled
		}
		return "", err
	}
	return string(pw), nil
}

// cancelOr turns errCancelled into a printed message and nil, so the loop
// just re-prompts. Any other error passes through unchanged.
func cancelOr(err error) error {
	if errors.Is(err, errCancelled) {
		fmt.Println("Cancelled.")
		return nil
	}
	return err
}

// commandCompleter suggests only commands valid for the CLI's current
// state, checked live on every keypress.
type commandCompleter struct {
	cli *CLI
}

func (comp *commandCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	word := string(line[:pos])
	if strings.ContainsAny(word, " \t") {
		// Only complete the command name, none take inline arguments.
		return nil, 0
	}

	var candidates [][]rune
	for _, cmd := range comp.cli.currentCommands() {
		if strings.HasPrefix(cmd.name, word) {
			candidates = append(candidates, []rune(cmd.name[len(word):]))
		}
	}
	return candidates, len(word)
}
