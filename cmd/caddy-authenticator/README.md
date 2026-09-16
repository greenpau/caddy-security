# caddy-authenticator

A standalone command for logging in to a Caddy security authentication portal.
It uses `go-authcrunch/pkg/authclient` for password, TOTP/MFA and API-key login.
No Caddy binary, admin API or profile API is required on the client.

## Install

### Download a release

Releases containing this command provide standalone archives on the
[GitHub releases page](https://github.com/greenpau/caddy-security/releases).
Choose the archive for your operating system and CPU; a Go installation is
not required.

| Operating system | Intel/AMD 64-bit (`amd64`) | ARM 64-bit (`arm64`) |
| --- | --- | --- |
| Linux | `caddy-authenticator_<version>_linux_amd64.tar.gz` | `caddy-authenticator_<version>_linux_arm64.tar.gz` |
| macOS | `caddy-authenticator_<version>_darwin_amd64.tar.gz` | `caddy-authenticator_<version>_darwin_arm64.tar.gz` |
| Windows | `caddy-authenticator_<version>_windows_amd64.zip` | `caddy-authenticator_<version>_windows_arm64.zip` |

Use `darwin_arm64` for Apple silicon Macs and `darwin_amd64` for Intel Macs.
The archive version omits the Git tag's leading `v`. Compare the archive's SHA-256
with its entry in the release's `authcrunch_<version>_SHA256SUMS` file.

Extract the archive and put `caddy-authenticator` (`caddy-authenticator.exe` on
Windows) in a directory on your `PATH`. Each archive also includes this usage
guide as `README.md` and the license. Check the installation with
`caddy-authenticator version`.

### Install with Go

Once a version containing this command is published, you can also run:

```sh
go install github.com/greenpau/caddy-security/cmd/caddy-authenticator@latest
```

Use `@<version>` to pin a release. The module requires Go 1.26 or newer. Go
installs the executable in `GOBIN`, or `$(go env GOPATH)/bin` when `GOBIN` is unset;
add that directory to `PATH`. The binary is named `caddy-authenticator`
(`caddy-authenticator.exe` on Windows). From a checkout containing the command:

```sh
go install ./cmd/caddy-authenticator
```

`make build` builds both `bin/authcrunch` and `bin/caddy-authenticator`.
Display the authenticator's version without opening a profile:

```sh
caddy-authenticator version
```

The output starts with `caddy-authenticator <version>`. It uses
`versioned.PackageManager`, including any supplied build metadata. Go installs
use the release version embedded in the source; Make builds explicitly set it
from the repository's `VERSION` file. Release archives include the release
version, commit and build date supplied by GoReleaser.

## First login

Commands are non-interactive by default. Supply the required profile settings
and credentials; missing input fails without prompting, even in a terminal.

```sh
caddy-authenticator configure --profile work \
  --url https://auth.example.com/auth --realm local --username alice
caddy-authenticator login --profile work \
  --password-file /private/secrets/portal-password
```

Use the portal's base URL, for example `https://auth.example.com/auth`, not its
`/login` endpoint.
`configure` stores these settings without storing a password. A login password
file is used only for that login. For interactive setup and password/MFA prompts,
enable interactive mode:

```sh
caddy-authenticator configure --profile work --interactive
caddy-authenticator login --profile work --interactive
```

Interactive `configure` asks for missing URL, realm and username settings.
Interactive `login` prompts for any required password and authenticator code
with terminal echo disabled. Combined MFA challenges select TOTP. Prompts go
to stderr; results go to stdout.
Setup accepts all three answers pasted as separate lines. Secret prompts keep
passwords and codes out of both terminal echo and input history.

Configure additional profiles independently:

```sh
caddy-authenticator configure --profile personal \
  --url https://login.example.net --realm local --username alice
caddy-authenticator profiles
caddy-authenticator login --profile personal --interactive
```

Failed logins preserve an existing token. Passwords, TOTP codes and bearer tokens
are not printed by login or written
to logs. OAuth redirects, browser SSO and WebAuthn/security-key assertions are
not supported by this direct JSON client.

## Login, cached tokens and refresh

Each `login` checks the selected profile's saved credentials first:

| Saved token | Behavior |
| --- | --- |
| Valid, at least 3 minutes remaining | Reuse it without contacting the portal |
| Valid, less than 3 minutes remaining, with a native refresh credential | Attempt one refresh and save the rotated credentials |
| Valid, less than 3 minutes remaining, without a refresh credential | Reuse it and report that refresh is unavailable |
| Expired or absent | Authenticate again using configured credentials or supplied input |
| Unreadable, or expiration cannot be determined | Fail with guidance to use `--force` |

Expiration comes from saved native metadata or the JWT's `exp` claim; the earlier
value wins when both exist. This is a local scheduling check, not signature or
revocation verification. The resource server remains responsible for validating
the token. A revoked but unexpired token may require an explicit fresh login.

Use `--force` to authenticate again even when a token is present:

```sh
caddy-authenticator login --profile work --force \
  --password-file /private/secrets/portal-password
caddy-authenticator login --profile work --force --interactive
```

Password input is read only when authentication is needed or forced. Refresh
uses the saved refresh credential and does not prompt for a password or MFA.
It requires `refresh_transport = body` and the portal's native transport opt-in.
An unsuccessful refresh keeps the old token and returns an error without falling
back to a fresh login. The `token` command can still extract that saved token.

A refresh response can be lost after the server consumes the old refresh
credential. The tool writes a private `refresh.pending` marker before sending
the request and removes it only after saving the replacement credentials.
If the exchange or save fails, later commands will not replay that credential.
Use `login --force` to recover; an expired access token also permits fresh login.
Successful fresh authentication or `clear` removes the marker. `clear` deletes
local state only and does not revoke the server's session.

## Files and profiles

The default directory is `~/.caddy-authenticator` on Linux/macOS and
`%USERPROFILE%\.caddy-authenticator` on Windows. The extensionless credentials
file uses named sections, following the
[AWS shared credentials file convention](https://docs.aws.amazon.com/sdk-for-net/v3/developer-guide/creds-file.html).
It is separate from `~/.config/authdbctl/config.yaml` and does not import that file.

```text
.caddy-authenticator/
├── credentials
└── profiles/
    ├── work/
    │   ├── token.jwt
    │   ├── refresh.pending  # only during an incomplete refresh
    │   ├── auth.log
    │   └── auth.log.1     # previous log, after rotation
    └── personal/
        ├── token.jwt
        └── auth.log
```

Example `credentials`:

```ini
[default]
base_url = https://auth.example.com/auth
realm = local
username = alice

[work]
base_url = https://sso.example.net
realm = employees
username = alice@example.net
ca_file = /path/to/company-ca.pem
```

Profile selection is `--profile`, then `CADDY_AUTHENTICATOR_PROFILE`, then
`default`. State directory selection is `--home`, then
`CADDY_AUTHENTICATOR_HOME`, then the platform's user home plus
`.caddy-authenticator`. Flags work before or after the command. The override
selects the entire state directory, including credentials, profiles and logs.
An explicitly empty `--home` is rejected; an unset or empty environment variable
uses the default:

```sh
export CADDY_AUTHENTICATOR_PROFILE=work
caddy-authenticator login --password-file /private/secrets/portal-password
caddy-authenticator --home /private/project-auth login --profile work \
  --password-file /private/secrets/portal-password
```

Profile names contain 1–64 lowercase ASCII letters, digits, hyphens or
underscores, starting with a letter or digit. Windows device names such as
`con`, `nul`, `com1` and `lpt1` are reserved on all platforms. This prevents
directory traversal and case aliases on case-insensitive filesystems.

Settings and sections must be unique. Unknown settings are rejected. Blank
lines and full-line `#`/`;` comments are accepted. There are no inline comments,
variable expansion, inheritance or multiline values. Unquoted values lose
surrounding whitespace; double-quoted values use Go string escapes, preserving
spaces, tabs, quotes and backslashes. Quote passwords with significant whitespace.
Quoted Windows paths need escaped backslashes; unquoted paths do not.

| Setting | Meaning |
| --- | --- |
| `base_url` | Required portal base URL, including its mount path |
| `realm` | Required identity store realm |
| `username` | Required for password login; omit for API-key login |
| `password` | Optional plaintext password; otherwise prompt during login |
| `api_key` | Independent API-key login; cannot be combined with username/password/TOTP |
| `totp_secret` | Optional raw secret bytes, **not base32 text**; otherwise prompt for the current code |
| `totp_code_length` | TOTP digits, 4–8; default 6 |
| `totp_code_lifetime` | TOTP period in seconds; default 30 |
| `access_token_name` | Fallback token name; default `authp_access_token`; the portal response takes precedence |
| `refresh_transport` | `cookie` (default, compatible with access-only portals) or explicit native `body` |
| `ca_file` | Additional PEM CA certificates; system roots remain trusted |

`configure` updates only the selected profile and preserves other profiles. It
rewrites the file in sorted, quoted form, removing comments. Existing values are
retained unless replaced. Every successful reconfiguration clears that profile's
cached token, requiring a fresh login. `--clear-secrets` removes stored password,
API key and TOTP secret before applying new flags. Supplying `--api-key-file`
switches to API-key login and clears the previous password identity, unless
conflicting identity/secret flags were also explicitly supplied (then it fails).
It also resets a previous body transport to cookie unless explicitly overridden.
`configure --ca-file` resolves relative paths from the working directory and
stores an absolute path. A manually entered relative `ca_file` is resolved from
the state directory; `login --ca-file` resolves from the working directory.
Path resolution preserves filesystem traversal through symlinks and `..`.
On Windows, use a fully qualified path such as `C:\certs\ca.pem` or a relative
path such as `certs\ca.pem`; drive-relative paths such as `C:ca.pem` cannot be
stored through `configure` or used as a profile's relative `ca_file`.

## Automation and private credentials

For unattended password login without persisting the password:

```sh
caddy-authenticator login --profile work \
  --password-file /private/secrets/portal-password
```

Use `--password-file -` to read one password from stdin until EOF. One final LF
or CRLF is removed; other whitespace is retained. Multiline, NUL and invalid
UTF-8 inputs are rejected. Missing MFA input fails in noninteractive mode.
Secret values have no command-line flags, avoiding plaintext secrets in shell
history and process argument lists.

To explicitly persist a password or raw TOTP secret in the credentials file:

```sh
caddy-authenticator configure --profile work \
  --password-file /private/secrets/portal-password \
  --totp-secret-file /private/secrets/portal-totp
caddy-authenticator login --profile work
```

API keys use their own profile:

```sh
caddy-authenticator configure --profile automation \
  --url https://auth.example.com/auth --realm local \
  --api-key-file /private/secrets/portal-api-key
caddy-authenticator login --profile automation
```

All three configure secret-file flags accept `-`, but only one may consume
stdin per command; conflicting stdin flags fail before any input is consumed.
Files containing stored secrets are plaintext, not encrypted.
On Unix, directories must be owner-only (0700) and credential/log/secret files
owner-only (0600); the tool creates new state with those modes and rejects
existing shared files. On Windows, restrict access with filesystem ACLs. State
directories and credential/log files cannot themselves be symlinks.

## Using a saved token

`token.jwt` is the private **JSON credential object** used by authclient and
authdbctl, despite its filename. It retains `access_token`, its name, creation
time, and any native refresh/session metadata. Use the command to extract it:

```sh
caddy-authenticator token --profile work           # bare access token
caddy-authenticator token --profile work --header  # Authorization: name=token
caddy-authenticator token --profile work --path    # absolute token.jwt path

curl -H "$(caddy-authenticator token --profile work --header)" \
  https://service.example.com/protected
```

Token output is sensitive. Send it only to the intended trusted service. `token`
does not contact the portal, verify signatures or check expiration; the resource
server must validate it. Run `login` again when it expires. The token file has
no portal/identity binding: after manually editing a profile to point at another
identity or portal, run `clear` and then `login` before using it.

```sh
caddy-authenticator clear --profile work
```

`clear` removes the selected profile's local token and any `refresh.pending`
marker, retaining settings and logs. It does not revoke an access token or a
server-side refresh family.

## TLS, native transport and diagnostics

HTTPS certificate validation is always enabled. HTTP is accepted only for
`localhost` or literal loopback addresses. Redirects are not followed. Use a
profile's `ca_file`, or `login --ca-file /path/to/ca.pem` for a one-time override,
for a private CA. There is no insecure TLS bypass.

For password login in a participating refresh-enabled realm, configure
`refresh_transport = body` (or `configure --refresh-transport body`), and have
the portal administrator explicitly enable native body transport for that realm.
The default cookie mode works with access-only realms and older portals. Browser
session responses explain the need for native transport and are not retried.
Body mode retains refresh credentials in `token.jwt`, sends no browser cookies,
and requires the portal's opt-in. API-key login is always access-only and cannot
use body transport. `login` rotates native credentials when the saved access
token is within the three-minute refresh window. It does not revoke server
sessions; `clear` is local deletion only.

`--timeout 45s` is the default total deadline, including network requests, stdin
and any explicitly enabled password/MFA prompts. Override it when needed, for
example `--timeout 90s`. Ctrl-C, SIGTERM and timeout restore terminal state.
Errors exit with status 1; success/help use 0. `--help` and `<command> --help`
list available flags.

Each profile's `auth.log` contains UTC JSON events for configure, login, refresh
and clear, recording each operation's start and success/failure or a cached-token
reuse event, with no credential values,
identity information, URLs or raw server errors. At 1 MiB it rotates to
`auth.log.1`; only one previous log is retained. If the starting event cannot be
written, the command fails before changing credentials/tokens or sending login
requests. If completion logging fails after an operation succeeds, the command
reports that the operation completed but could not be logged. Failures before
profile storage can be opened appear on stderr.

Commands serialize access to the state directory with an exclusive `.lock`
directory and fail promptly if another command owns it. After an uncatchable
termination or machine crash, confirm no command is running before removing the
empty `.caddy-authenticator/.lock` directory. The tool never removes locks based
on age. Different `--home` directories are independent.
