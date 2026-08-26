# CLI Login System

A containerized command line login system written in Go. It has username and
password registration with bcrypt hashing, account lockout after repeated
failed logins, optional TOTP based two factor authentication compatible with
apps like Google Authenticator, and session tokens with expiry. Everything
runs behind an interactive terminal prompt built on readline, backed by
Postgres.

This was built as a learning project, working through the pieces of a real
login system one at a time: the database and migrations first, then
password auth, then 2FA, then the interactive CLI, then packaging it for
Docker, and finally this pass of polish and tests.

## Prerequisites

- Docker and Docker Compose. This is the normal way to run the project,
  everything (the app and Postgres) runs in containers.
- Go 1.25 or later, only needed if you want to build or run the CLI
  directly on your machine instead of through Docker, or if you want to
  run the test suite.

## Setup

Clone the repository, then create your own `.env` file from the example:

```bash
cp .env.example .env
```

The defaults in `.env.example` work fine for local development as is. If
you want different Postgres credentials or different auth policy values,
edit `.env` after copying it. `.env` is gitignored on purpose, it holds
whatever secrets you put in it and should never be committed.

First run:

```bash
docker compose up -d db
docker compose build app
docker compose run --rm -it app
```

The first command starts Postgres and waits for it to report healthy. The
second builds the app image. The third runs the CLI attached to your
terminal. On first start the app connects to the database and applies the
migrations automatically, you do not need to run them by hand.

`run --rm -it` is the command you will use most often: it gives you a real
interactive terminal, and removes the container when you exit so you are
not left with a pile of stopped containers. See the "Full end to end test"
section below for a walkthrough covering the whole system in one sitting.

## Command reference

The prompt changes depending on whether you are logged in, `login>` when
logged out, `user@yourname>` once logged in. Available commands depend on
that same state, and tab completion only suggests commands valid for
where you currently are.

### Logged out

| Command    | What it does                          |
|------------|----------------------------------------|
| `register` | Create a new account                   |
| `login`    | Log in to an existing account          |
| `help`     | List the commands available right now  |
| `exit`     | Quit the CLI                           |

### Logged in

| Command       | What it does                                    |
|---------------|--------------------------------------------------|
| `whoami`      | Show your account details                       |
| `enable-2fa`  | Turn on two factor authentication               |
| `disable-2fa` | Turn off two factor authentication              |
| `logout`      | Log out and return to the logged out prompt     |
| `help`        | List the commands available right now           |
| `exit`        | Log out (invalidating your session) and quit    |

`register` asks for a username, then a password, then asks you to type the
password again to confirm it, none of which is echoed to the terminal.
`login` asks for username and password, and if the account has 2FA turned
on it will also ask for a 6 digit code before letting you in. `enable-2fa`
shows a scannable QR code right in the terminal, plus the secret and
otpauth URL as text below it for anyone who'd rather type it in by hand
or whose terminal can't render the QR cleanly. Either way, it then asks
you to confirm with a code from your app before it actually turns 2FA on,
so you cannot lock yourself out by scanning something wrong.
`disable-2fa` asks you to prove it is really you, either with your current
password or a valid 2FA code, before turning it off.

## Walkthrough example

A full session covering registration through to disabling 2FA again. Run
`docker compose run --rm -it app` and follow along:

```
login> register
Username: alice
Password: (typed, not shown)
Confirm password: (typed, not shown)
Account "alice" created. Use 'login' to sign in.

login> login
Username: alice
Password: (typed, not shown)
Login successful.
  (account details are shown automatically here)

user@alice> whoami
  (shows username, registration date, 2FA status, last login, session expiry)

user@alice> enable-2fa
  A QR code is printed here, scan it with your authenticator app, or use
  the secret and otpauth URL shown below it to add the account by hand
Enter the code from your authenticator app to confirm: 123456
Two-factor authentication is now enabled.

user@alice> logout
Logged out.

login> login
Username: alice
Password: (typed, not shown)
Enter 2FA code: 123456
Login successful.
  (whoami output now shows 2FA: enabled)

user@alice> disable-2fa
Verify with 'p' (password) or 't' (TOTP code): p
Password: (typed, not shown)
Two-factor authentication is now disabled.

user@alice> exit
Goodbye!
```

## Database schema

Two tables, created by `migrations/0001_init.up.sql`.

**users**

- `id`: UUID primary key, generated by Postgres.
- `username`: unique, this is how a person is identified, whitespace is
  trimmed before it is checked or stored.
- `password_hash`: the bcrypt hash, never the plaintext password.
- `totp_secret`: the base32 TOTP secret, only set once `enable-2fa` has
  been started, and cleared again when 2FA is disabled.
- `totp_enabled`: whether 2FA is actually active. This only flips to true
  once the user confirms a code, not as soon as a secret is generated.
- `failed_attempts`: consecutive failed logins, reset to 0 on a
  successful login.
- `locked_until`: set when `failed_attempts` reaches the configured
  threshold, cleared again on the next successful login.
- `created_at`, `last_login_at`: self explanatory, `last_login_at` is
  null until the first successful login.

**sessions**

- `token`: primary key, a random 256 bit value generated with
  `crypto/rand`, not a predictable ID.
- `user_id`: which user this session belongs to, foreign key into
  `users`, sessions are deleted automatically if the user row is deleted.
- `created_at`, `expires_at`: when the session was issued and when it
  stops being valid.

There is also a `schema_migrations` table the migration runner uses to
track which migration files have already been applied, so starting the
app again does not try to re-run something that already ran.

## Security notes

A few notes on how the auth is actually implemented, written plainly
rather than as a marketing pitch.

- Passwords are hashed with bcrypt before they are ever stored. The
  plaintext password is never written to the database or to a log.
- After enough consecutive failed logins (5 by default, configurable),
  the account is locked for a period of time (15 minutes by default,
  also configurable) rather than allowing unlimited guesses.
- Two factor authentication uses standard TOTP, the same protocol Google
  Authenticator, Authy, and most other authenticator apps use, so any of
  them will work.
- A wrong 2FA code during login counts as a failed attempt against the
  same lockout counter as a wrong password. Otherwise someone who already
  knew the password could just keep guessing codes with no penalty.
- Sessions expire after a set amount of time (30 minutes by default,
  configurable) rather than staying valid forever.
- Session tokens are generated with `crypto/rand`, the cryptographically
  secure random source, not `math/rand`, which is predictable and not
  safe for anything security related.
- Looking up a username that does not exist and entering a wrong password
  for a username that does exist both return the exact same error
  message, so the login prompt cannot be used to check which usernames
  are registered.

## Running tests

Some tests are pure logic and run with no setup:

```bash
go test ./...
```

The rest are integration tests against a real Postgres instance, they are
skipped automatically if `DATABASE_URL` is not set. To run the full suite:

```bash
docker compose up -d db
DATABASE_URL="postgres://cli_login_user:changeme@localhost:5432/cli_login?sslmode=disable" \
  go test ./... -v
```

Adjust the username, password, and database name in that URL if you
changed them in your `.env`. Each integration test cleans up the rows it
creates, so it is safe to run repeatedly.

## Resetting the database

To reset back to an empty database:

```bash
docker compose down -v
```

The `-v` removes the named volume Postgres stores its data in. A plain
`docker compose down` (without `-v`) stops the containers but keeps the
volume, so your data is still there the next time you bring it back up,
that is the difference between "restart" and "actually wipe everything."

After a `down -v`, the next `docker compose run --rm -it app` starts
against a completely empty database and reapplies the migrations from
scratch.

## Viewing logs

Both services log to their container's standard output, there is no log
file on disk. `docker compose logs` reliably covers `db`. It does not
cover `app` in its normal, most common form, see the note below before
you go looking for `app` output there.

To follow `db`'s logs live:

```bash
docker compose logs -f db
```

Drop `-f` to just print what has been logged so far instead of
following. A stopped or crashed `db` container's logs stick around this
way too, as long as the container was not removed, `db` is normally
started with `docker compose up -d db` so that is the common case.

`app` is different: it is normally started with `docker compose run`,
and `docker compose logs` does not show anything for containers started
that way, live or after they exit, with or without `--rm`. For `app`,
use one of these instead:

- Watch the terminal you ran `docker compose run --rm -it app` in
  directly, that already is the live output.
- `docker logs <container name>` (plain docker, not compose), find the
  name with `docker ps -a`, it will look like
  `cli-login-app-run-xxxxxxxxxxxx`. Works whether the container is still
  running or already exited, as long as it has not been removed.
- Start that particular session with `docker compose up app` instead of
  `run`, then `docker compose logs app` will work for it like it does
  for `db`.

What to expect in each service's logs:

- `app`: on a clean start you will see a line for each migration it
  applies (only on first run against a fresh database, later runs skip
  already-applied ones silently), then the CLI's own startup banner. If
  it cannot reach Postgres yet it prints a retry line for each attempt
  before giving up, that is expected during the first few seconds of a
  cold start, not a problem by itself. An actual failure looks different:
  a line prefixed with a timestamp like `2026/08/26 22:04:33 failed to
  connect to database: ...`, that timestamp prefix only appears on a
  fatal error, normal output does not have it.
- `db`: normal Postgres startup and shutdown messages, plus periodic
  `checkpoint starting` / `checkpoint complete` lines in the background,
  those are routine and not something to worry about. Connection and
  query activity shows up here too if you want to see what the app is
  actually doing to the database.

There is no application logging beyond this. Errors are not written
anywhere with more detail than what the CLI already shows you, whatever
is printed to the terminal (or, for fatal startup errors, to stderr) is
the entire log, viewable through whichever of the methods above matches
how you started that container.

## Known limitations

Things left out on purpose, either because they were out of scope for
this project or because a small single admin system does not need them:

- No password reset flow. If you forget your password there is no "email
  me a reset link," you would need to reset the row directly in the
  database.
- No rate limiting beyond the account lockout. There is nothing stopping
  someone from hammering the login prompt with different usernames, only
  repeated attempts against the same account get slowed down.
- No roles or permissions. Every account is equal, there is no concept of
  an admin user versus a regular user.
- No password change command from inside the CLI. Changing a password
  also means updating the database directly.
- No multi factor methods beyond TOTP, no SMS, no hardware keys, no
  email codes.
