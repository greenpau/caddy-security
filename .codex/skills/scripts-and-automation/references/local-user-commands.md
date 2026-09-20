# Local User Administration

`bin/authcrunch security local` brings the user-store operations from
`go-authcrunch/cmd/authdbctl` into Caddy's registered `security` CLI. Use the
same paths with a custom Caddy binary containing this module.

## Operating Model

Remote commands manage **local identity stores through a running portal**.
Enable `admin api` on that portal and authenticate as an administrator, normally
with `authp/admin`. `connect` uses JSON `/login` and works independently of the
admin API flag. Login delegates to the pinned `go-authcrunch/pkg/authclient`.

Offline `generate` commands need neither a server nor client config. They
print credentials for local-user Caddyfile blocks; they do not add users or
modify database files. System messaging/encryption utilities from authdbctl
are outside this local-user command group.

Use [Configuration Users](../../configuration-users/SKILL.md) for static user
blocks and [Authentication Portal API](../../authentication-portal-api/SKILL.md)
for the HTTP API. Keep implementation, tests, and documentation here;
upstream source is a read-only reference.

## Client Configuration and Login

Create a private directory and an owner-only YAML file (0600):

```yaml
base_url: https://auth.example.com/auth
realm: local
username: webadmin
# Optional: omit password for a hidden terminal prompt.
# password: ...
```

`base_url` is the full portal mount, which can use a custom path. For a portal
served at `/xauth`, set `base_url: https://auth.example.com/xauth`; login uses
`/xauth/login` and admin commands use `/xauth/api/server/...`. Use HTTPS
for remote credentials; HTTP remains available for local deployments. TLS
verification is always enabled. `--ca-file /path/to/ca.pem` adds trusted CA
certificates for a private PKI. The CLI uses its own transport so a custom
Caddy module's process-wide transport settings cannot disable this verification.

```sh
bin/authcrunch security local connect --config private/client.yaml
bin/authcrunch security local list realms --config private/client.yaml
bin/authcrunch security local list users --config private/client.yaml --realm local
```

Each remote command accepts `--config`, `--token-path`, `--ca-file`, and
`--timeout` (30 seconds by default). Flags belong to the leaf command. The
config is client YAML, **not** a server Caddyfile or OAuth provisioning input.

YAML accepts authclient fields: `base_url`, `username`, `realm`, `password`,
`api_key`, `totp_secret`, `totp_code_length`, `totp_code_lifetime`,
`access_token_name`, and `refresh_transport`. Unknown fields, duplicate keys,
multiple documents, invalid URLs, and invalid authentication settings fail
before login. Decoded strings must be valid UTF-8, including YAML binary values;
credentials are never silently converted when sent as JSON. No imports,
environment expansion, or `~` expansion occur.

Authentication fields are encoded and passed to the dedicated
`pkg/authclient/parser.NewAuthenticationClientConfigFromDirectives`; its typed
config owns defaults and semantic validation. Nonempty whitespace-only and
multiline authentication values fail with redacted errors. Empty optional YAML
scalars and zero TOTP integers retain defaults. Nonempty string values are always
CSV-quoted at the shared parser boundary to preserve trailing tabs and Unicode
whitespace; the host must neither corrupt raw secrets nor repair invalid options
by trimming them. CLI filesystem fields stay
separate. See [JSON/native interoperability](../../authentication-portal-api/references/native-client.md)
for cookie-mode wire compatibility, native opt-in, response metadata and explicit
renewal; this is separate from an OAuth public relying party.

For API-key login, use `base_url`, `realm`, and `api_key`; omit username,
password, and TOTP settings. Missing password/TOTP input uses a hidden terminal
prompt; automation supplies it in the private config. Prompts and HTTP
requests share the command's overall timeout; there is no separate ten-second
HTTP limit. Terminal settings are restored on success, timeout, SIGINT, and
SIGTERM. Interactive prompts reject malformed UTF-8 and the replacement
character (U+FFFD) before the terminal editor can discard them. For a valid
password containing U+FFFD, use the private client config or `--password-file`
to preserve it exactly. WebAuthn assertions remain unsupported by the
shared client. Native refresh realms require `refresh_transport: body` and
the portal's opt-in; refresh credentials are retained but not renewed.

Login atomically saves a 0600 JSON token file; new token directories use 0700.
Default caches are `.security-tokens/<digest>.json` beside the config, isolated
by portal and login identity. Commands reuse cached credentials and authenticate
when the cache is missing. `connect` explicitly replaces stale or malformed
credentials. Its JSON output contains `status` and `token_path`, never tokens.

For authdbctl interoperability, YAML `token_path` or `--token-path` selects an
existing JSON token file. The flag wins. Relative YAML token paths resolve
beside the resolved config file; relative flag paths resolve from the working
directory. Directory symlinks are followed before `..` is evaluated. Token
output cannot replace the config or CA input, including through hard-link aliases.
Explicit token files are not bound to a portal or identity: use a distinct
path per target. Legacy `cookie_name` is accepted but does not override the
login response's token name. Credential files must be regular files with
owner-only permissions; Windows uses filesystem ACLs. Keep parent directories
private and trusted.

## Commands

Prefix these paths with `bin/authcrunch security local`. All remote commands
require `--config`. The YAML realm identifies the **administrator's login**;
`--realm` explicitly selects the **target database**, preventing a config
change from silently retargeting a mutation.

| Command | Additional flags |
| --- | --- |
| `connect` | None |
| `metadata` | None |
| `list realms` | Optional `--format json`, `table`, or `csv` |
| `list users` | `--realm`; optional `--format` |
| `info realm` | `--realm` |
| `reload` | `--realm` |
| `info user` | `--realm`, `--username`, `--email` |
| `add user` | `--realm`, `--username`, `--email`, `--name`, `--roles` |
| `delete user` | `--realm`, `--username`, `--email` |
| `update user` | `--realm`, `--username`, `--email`, exactly one update below |

Update operations are `--enable`, `--disable`, `--reset-password`,
`--overwrite-roles`, `--add-roles`, and `--overwrite-auth-challenges`.
List flags accept comma-separated values or repeated flags. Empty lists,
empty members, conflicting updates, false update switches, positional
arguments, and irrelevant flags fail before any remote action.

```sh
bin/authcrunch security local add user --config private/client.yaml \
  --realm local --username alice --email alice@example.com \
  --name 'Alice Example' --roles authp/user,reader

bin/authcrunch security local update user --config private/client.yaml \
  --realm local --username alice --email alice@example.com --reset-password

bin/authcrunch security local update user --config private/client.yaml \
  --realm local --username alice --email alice@example.com \
  --overwrite-auth-challenges "password totp"
```

Each `--overwrite-auth-challenges` item is a complete ordered rule body.
`"password totp"` requires both methods; `password,totp` supplies two separate
rules, so an available password selects the first rule. Quote spaces within
a rule and use commas or repeated flags between rules. The server API requires
a nonempty replacement; it does not implement the profile API
[empty-array reset](../../authentication-portal-api/references/authentication-flows.md#profile-api).

Creation and password reset return a **server-generated plaintext password**
in JSON; they do not accept a caller-selected password. Protect stdout,
including automation logs. `info user` can return sensitive credential hashes.
JSON preserves server fields; table/CSV are available for listings. Prompts go
to stderr.

Requests are not automatically retried and redirects are not followed. HTTP
errors, malformed responses, HTTP-200 operation failures, and unconfirmed
mutations exit nonzero. Transport errors, negative HTTP/API responses, and
output failures may occur after a change has taken effect. Errors after an
attempted mutation include recovery guidance: inspect the account/realm before
repeating. Malformed UTF-8 and unpaired Unicode escapes in API responses are
rejected before decoding can alter returned credentials. Rejected or expired
tokens require `connect`. `reload` reloads the selected identity
database; it is separate from Caddy configuration reload.

## Offline Generators

```sh
bin/authcrunch security local generate password hash
bin/authcrunch security local generate password hash \
  --password-file private/password.txt --cost 10
bin/authcrunch security local generate password hash \
  --password-file - --db-path private/users.json
bin/authcrunch security local generate api key --cost 10
```

`--password-file -` reads stdin through EOF. A final LF or CRLF is removed;
surrounding whitespace, embedded newlines, NUL, invalid UTF-8, and passwords
over bcrypt's 72-byte limit are rejected. Plaintext passwords are never
accepted as command arguments. A plaintext `bcrypt:` prefix is hashed
literally rather than interpreted as a precomputed hash.

Password hashing prints only `password "bcrypt:<cost>:<hash>"`. Default
minimum length comes from authcrunch (8 bytes). `--db-path` reads an existing
database's length and character-class policy without creating, normalizing,
locking, or saving that database. Missing length limits inherit upstream
defaults. This check does not validate history or authorize a password change;
account mutations remain the server's responsibility.

API-key generation prints `secret: <72-character alphanumeric secret>` and an
`api key <24-character prefix> "bcrypt:<cost>:<hash>"` directive. The full
secret authenticates the client; the prefix and hash go in its user block.
The generator uses cryptographic randomness. Both generators accept bcrypt
cost 8-31, default 10; higher costs grow exponentially. Neither contacts a
server, and password generation never prints the plaintext input.

## Implementation and Validation

- `command_local.go`: command registration, validation, and dispatch.
- `command_local_client.go`: YAML, authclient/cache wiring, TLS, admin requests.
- `command_local_output.go`: JSON/table/CSV.
- `command_credentials.go`: hashes, policy reads, and terminal input.
- `command_local_test.go` and `command_credentials_test.go`: wire contracts,
  failures, cache isolation, database immutability, bcrypt compatibility,
  secret-safe errors, and actual Caddy command dispatch.
- `command_local_safety_test.go`: unit and Caddy CLI regressions for decoded
  UTF-8, independent TLS verification, configured request/login timeouts, and
  mutation failures after the backend may have committed, including malformed
  Unicode in generated-password responses.
- `command_local_paths_test.go`: unit and Caddy CLI checks for symlink traversal,
  cache placement, input-file preservation, hard-link aliases, and leaf symlinks.
- `TestCaddySecurityLocalE2E`: TLS Caddy portals at root, `/auth`, and `/xauth`,
  persisted users, login, CRUD, enable/disable, resets, roles/challenges, realm reload,
  admin denial, authentication with generated password hashes and API keys,
  configured administrator MFA, a full three-prompt MFA login (password, method,
  and authenticator code), and cache preservation on failed MFA login.
- `TestSecurityTerminalE2E`: real Unix terminal input, secret echo suppression,
  Unicode, CRLF and bracketed paste, Ctrl-C/Ctrl-D keystrokes, and terminal
  restoration after success, SIGINT, SIGTERM, and timeout (Python 3). It also
  verifies that malformed encoding cannot produce a hash of an altered password,
  and that interruption at later MFA prompts preserves cached credentials.
- `TestSecurityTerminalEncoding` and `FuzzSecurityTerminalEncoding`: byte
  preservation and rejection of corrupt input, including split UTF-8 sequences.

Run focused tests, then the repository suite:

```sh
go test -mod=readonly -run 'TestSecurity(Local|Credential|Terminal)|TestCaddySecurityLocal' .
make test
make build
```
