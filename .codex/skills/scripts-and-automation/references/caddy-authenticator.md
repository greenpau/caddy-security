# Standalone caddy-authenticator

Use this reference when implementing or maintaining `cmd/caddy-authenticator`.
The user-facing command contract and examples live in
[`cmd/caddy-authenticator/README.md`](../../../../cmd/caddy-authenticator/README.md),
as explicitly requested for this utility. Keep that guide and Cobra help in sync
with changes; do not move the guide into skills or duplicate it here.

## Ownership

This is a standalone `package main`, installed as
`github.com/greenpau/caddy-security/cmd/caddy-authenticator`. Keep it independent
of Caddy server registration and the root security package. Reuse the selected
`github.com/greenpau/go-authcrunch/pkg/authclient` for `Client.Authenticate`,
`PromptFunc`, `Config`, `Credentials`, `Credentials.Authorization` and
`FileTokenStore`. Reuse its parser for profile authentication settings. Do not
copy login exchanges, challenge routing, TOTP generation or token serialization
into this command. Inspect the version selected by `go list -m -json`; the
sibling source is a read-only reference and can differ from that version.

`main.go` initializes `*versioned.PackageManager` using the authdbctl pattern:
`appVersion`, `gitBranch`, `gitCommit`, `buildUser` and `buildDate` are optional
linker values; `version` prints `app.Banner()` through Cobra's output writer.
Version reporting must work without a home directory, profile, credentials or
network access. Keep it outside the state/lock/input wrapper.
`make build` produces both binaries and injects `VERSION` into
`main.appVersion` for `bin/caddy-authenticator`. Plain `go install` uses the
checked source fallback. `make version-check` rejects fallback drift and
`make version-sync` updates it after a VERSION edit; the patch release target
also synchronizes it. See [version authority](../../release-and-versioning/SKILL.md#version-authority).
`.goreleaser.yaml` also builds independent archives for Linux/macOS/Windows on
amd64/arm64, with the executable, this command's README and LICENSE. Maintain
the [download guide](../../../../cmd/caddy-authenticator/README.md#download-a-release)
alongside the build/archive selectors and release linker metadata. Follow the
[packaging checks](../../release-and-versioning/references/ci-and-packaging.md#toolchain-and-packaging-checks)
when changing these artifacts; ordinary `go build` alone does not exercise
archive contents, names, Windows ZIP output or checksums.

`config.go` owns a bounded, strict INI dialect and its adapter to the public
parser. Preserve secret bytes through both boundaries: INI uses Go double-quoted
strings, while shared directives use CSV quoting with doubled embedded quotes.
Do not use the generic directive encoder in a way that strips trailing secret
whitespace. Do not echo raw syntax, secret values or server bodies in errors.

`storage.go` selects the private state directory, profiles, lock and logs.
Defaults are `<UserHomeDir>/.caddy-authenticator/credentials` and
`profiles/<name>/token.jwt`; the latter remains authclient's JSON format, not a
bare JWT. `--home`/`--profile` override `CADDY_AUTHENTICATOR_HOME` and
`CADDY_AUTHENTICATOR_PROFILE`, then platform home and profile `default`.
Names are lowercase, path-safe and portable across supported filesystems.
Reject an explicitly empty `--home` before opening state; an empty environment
variable still selects the default.

Preserve private permissions, symlink rejection, bounded reads and atomic
replacement. Serialize commands with the state-directory lock; never infer a
stale lock solely from age. Configure clears only its selected token before
committing new settings. Login failures retain existing tokens. `clear` is
local deletion, not remote logout; it also clears `refresh.pending`. Manual edits
require a fresh login because
the upstream token file has no portal/identity binding.

Logs use fixed event/outcome fields, UTC timestamps, and one rotated backup at
1 MiB. No secret, identity, URL, HTTP body or upstream error text belongs in a
log record. Log the operation's start before modifying credentials/tokens or
contacting a portal, then its success/failure. A known unusable log must fail
before these actions. If completion logging fails after success, explicitly
report that the operation completed; do not imply rollback.
Token output is explicit through `token`; `--header` delegates to
`Credentials.Authorization`, preserving custom access token names.

`login.go` owns HTTPS enforcement, optional additional CA roots and a fresh
HTTP transport. Allow cleartext only on literal loopback addresses/localhost.
Keep redirect refusal and cancellation. Anchor relative CA paths without
lexically cleaning unresolved symlinks and `..`: `filepath.Abs` and
`filepath.Join` can select a different file. Configure anchors to the working
directory; manually stored relative CA paths anchor to the state directory.
Reject ambiguous Windows drive-relative paths when anchoring.

`terminal.go` owns hidden input and restoration on timeout/signals. Keep one
line editor per command so pasted answers survive across prompts, and use its
password API to bypass echo and history for passwords/TOTP. Never let a blocked
input goroutine own terminal restoration; reject invalid UTF-8 before the line
editor can discard bytes. Secrets use private files/stdin or terminal prompts,
not argument values. Reject multiple stdin secret flags before reading input.
Commands default to non-interactive mode, including when stdin is a terminal;
only `--interactive` enables setup/password/MFA prompts. Missing-input
errors should identify that opt-in. The default total command timeout is 45s,
overridable with `--timeout`, and includes network requests and input.

`login` reuses a valid cached token without network requests when at least three
minutes remain. Inside that window it attempts one native refresh if a refresh
credential exists; otherwise reuse the token and report refresh unavailability.
Missing/expired tokens and `login --force` trigger fresh authentication through
authclient. Unknown expiration or unreadable credentials require explicit force;
do not silently treat them as expired. Password-file input must not be consumed
when reusing/refreshing. `token` remains an explicit local extraction operation.

`refresh.go` reads expiration as an unverified scheduling hint, taking the
earlier native metadata/JWT exp value when both exist. Payload decoding must not
depend on signing-algorithm registration (including the Ed25519 alias). Resource
authorization still validates signatures, expiry and other claims.

The selected authclient has no renewal method. Keep fresh password/MFA/API-key
login delegated to it; use its Credentials/FileTokenStore and the shared
apiauth.AuthResponse for the single native refresh POST. Reuse the verified TLS,
CA, redirect refusal and context deadline setup. Require explicit body transport,
send no browser or access-token credentials, preserve session/absolute-expiry
binding and lower-case the returned access token name. Bound response reads and
redact errors. Never retry a rotation, follow redirects, or silently fall back
to fresh login after a failed refresh.

Persist `refresh.pending` under the state lock before sending a refresh request.
Retain it after network/response/save failure to prevent replay across commands.
Remove it only after saving rotated/fresh credentials or clearing the token;
configure also clears it when invalidating the selected cache. An expired token
or explicit force may authenticate again without replaying the refresh token.
No browser flow, admin API or session lookup belongs in this recovery path.
Refer to [native interoperability](../../authentication-portal-api/references/native-client.md)
for protocol ownership and single-use rotation boundaries.

## Validation

Run this repository's tests, never the sibling suite:

```sh
go test -mod=readonly -race -count=1 ./cmd/caddy-authenticator
go test -mod=readonly -race -count=1 -run '^TestCaddyAuthenticator(Version)?E2E$' .
```

Command-package tests cover strict parsing, byte preservation, selection
precedence, credential updates, failed-login preservation, private files,
symlinks, locking, log rotation, TLS trust, redirect refusal and deadlines.
Regression cases cover explicit empty home overrides, CA traversal through
`link/..` (including manually entered relative paths), rejected mutations with
unusable logs, late completion-log failures, conflicting stdin flags and
buffered terminal input without secret echo/history. Check the actual command
context's default/overridden deadline without waiting for 45s to elapse.
Verify version output and stdout error propagation without profile storage.
`refresh_test.go` covers offline cache reuse, near-expiry access-only tokens,
expiry/forced login, native wire/metadata behavior, redirects, response failures,
failed persistence and replay prevention across commands.
`caddy_authenticator_e2e_test.go` builds the actual CLI and runs real Caddy TLS
with root/nested mounts, admin/profile APIs disabled, password/configured and
prompted MFA/API keys, native metadata, independent resource authorization,
profile isolation and local clear. Its Unix PTY broker under
`testdata/caddy_authenticator/terminal.py` requires Python 3 and checks pasted
setup answers, hidden/password paste input, EOF and keyboard/signal interruption,
and terminal restoration at password and TOTP prompts; Windows skips the PTY
portion. PTY cases must verify default commands do not prompt even with a real
terminal, and explicitly opt in for interactive scenarios. Successful password,
configured MFA and API-key cases exercise the default mode without redundant
flags; missing MFA input must fail. Real-Caddy regressions also verify
symlink-sensitive CA selection and credential/token preservation after rejected
configure/clear commands.
The CLI E2E verifies actual near-expiry rotation with retained SID, forced fresh
families, real expired-token login, and recovery from a lost committed refresh
response through the existing Caddy fault probe. No test-issued token replaces
the portal's authentication or resource authorization in these scenarios.
`TestCaddyAuthenticatorVersionE2E` installs the actual executable to an isolated
GOBIN, checks its basename and source fallback, then builds with linker overrides
and checks the PackageManager banner. Both paths must leave user state untouched.
Run `make test-automation` and `make build` for build/version workflow changes;
automation fixtures cover both outputs, build failures and version drift.

Validate installability with `GOBIN` set to a generated directory inside this
checkout and `go install -mod=readonly ./cmd/caddy-authenticator`. Keep build
outputs in `bin/` or `tmp/`. There is no separate go.mod or dependency replacement
for this tool, so version-suffixed `go install` uses normal published module
resolution. Run the package tests and E2E whenever changing the CLI or updating
the selected authclient dependency. Update test names here when their ownership
changes.
