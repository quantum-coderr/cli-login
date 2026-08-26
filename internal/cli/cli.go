// Package cli implements the interactive REPL on top of the Phase 2/3
// auth/session/totp packages. It's a thin presentation layer: command
// handlers call into those packages and format the results/errors for a
// terminal — no SQL, no business rules, live here.
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

// errCancelled signals that a sub-prompt inside a command (e.g. the
// password prompt during register) was aborted with Ctrl+C/Ctrl+D. It
// never escapes a command handler — cancelOr turns it into a printed
// "Cancelled." and a nil return, so the main loop just shows the prompt
// again.
var errCancelled = errors.New("cli: cancelled")

// CLI holds the interactive session's state: the DB handle every command
// needs, and the currently logged-in user/session, if any. Both nil means
// logged out.
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
// the user exits (via the `exit` command, Ctrl+C on an empty line, or
// Ctrl+D).
func (c *CLI) Run(ctx context.Context) error {
	fmt.Println("CLI Login System — type 'help' for a list of commands.")

	for {
		c.checkSessionExpiry(ctx)
		c.rl.SetPrompt(c.currentPrompt())

		line, err := c.rl.Readline()
		switch {
		case errors.Is(err, readline.ErrInterrupt):
			// Ctrl+C: on an empty line this means "I want out", matching
			// common shell behavior; with partial text typed, just clear
			// it and show the prompt again rather than quitting on a
			// stray keypress.
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
			// Not one of the mapped auth/session/totp errors — those are
			// already printed inside the handler via errorMessage(). This
			// is something unexpected (e.g. a DB/infra failure).
			fmt.Printf("Internal error: %v\n", err)
		}
	}
}

// quit performs the shared "leaving the CLI" cleanup: invalidate the
// session if one is active, then say goodbye. Used by both the `exit`
// command and Ctrl+C/Ctrl+D.
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

// readLine shows a one-off sub-prompt (e.g. "Username: ") and restores
// the normal state prompt afterward. Ctrl+C/Ctrl+D here cancel just the
// current command, not the whole CLI — see errCancelled.
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

// cancelOr turns errCancelled into a printed message and a nil return (so
// the main loop just re-prompts), and passes any other error straight
// through. Every command handler routes its sub-prompt errors through
// this so cancellation is handled identically everywhere.
func cancelOr(err error) error {
	if errors.Is(err, errCancelled) {
		fmt.Println("Cancelled.")
		return nil
	}
	return err
}

// commandCompleter implements readline.AutoCompleter, suggesting only the
// commands valid for the CLI's current state (logged in vs out) — it
// consults c.currentCommands() live on every keypress, so it never needs
// to be rebuilt when the state changes.
type commandCompleter struct {
	cli *CLI
}

func (comp *commandCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	word := string(line[:pos])
	if strings.ContainsAny(word, " \t") {
		// Only complete the command name itself, not arguments — none of
		// our commands take inline arguments (they prompt interactively).
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
