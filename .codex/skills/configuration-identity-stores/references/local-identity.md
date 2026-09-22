# Local Identity Compatibility

This contract is qualified against the go-authcrunch revision selected in
`go.mod`, currently published v1.3.4.
Check `go list -m -json github.com/greenpau/go-authcrunch` before attributing
behavior to a sibling checkout. The upstream `local-password-authentication`
skill and `pkg/identity/password_verifier.go`, `user.go`, `database.go`,
`refresh.go`, and `pkg/ids/local/{store,authenticator}.go` are read-only
references. Keep implementation and tests here; report upstream fixes separately.

## Password Authentication and Mutations

Keep form and JSON password authentication delegated through the local store's
`AuthenticateUser` to `identity.Database.AuthenticateUser`. The database builds
its bcrypt comparison schedule across enabled accounts and active passwords,
using costs encoded in hashes, including mixed costs and multiple active hashes.
Missing, disabled, and present users receive that schedule. A match does not
short-circuit it. Do not replace this with `User.VerifyPassword` in a Caddy
handler or copy authdbctl management/terminal code into the server.

The Caddy tests assert outcomes, persistence, and credential invalidation; they
do not measure timing or prove constant time. If investigating timing/CPU,
isolate synthetic homogeneous and mixed-cost data, warm the verifier, interleave
samples, report distributions, and keep exact timing assertions out of CI.

Creation/import trims surrounding password whitespace; authentication compares
the supplied plaintext. The `bcrypt:<cost>:<hash>` import format describes a
stored credential, not an alternative plaintext login. Duplicate updates reuse
the active hash and creation timestamp but still advance the database credential
version. Reset creates a fresh password record even for the same plaintext or
import. The admin HTTP reset endpoint generates a password: do not invent a
caller-supplied reset field to test the lower-level same-password contract.

Static Caddyfile `password ... overwrite` calls the database update operation.
Without `overwrite`, provisioning preserves an existing password. Neither mode
bulk-migrates legacy records lacking `credential_version`; missing means zero,
and successful security mutations persist a later version for the affected user.

Profile password update uses `kind: update_user_password`, `old_password`, and
`new_password`. In v1.3.4, profile updates accept plaintext only and reject
reserved `bcrypt:` and `argon2:` import prefixes with HTTP 400, including valid
hashes and imports matching the current password. Rejection preserves password
records, credential versions and existing renewable sessions. Trusted database
and static-user provisioning imports remain supported.
Management uses the existing `/api/server/user` operations,
including `reset_password`, `disable`, `enable`, `delete`, `add`, and
`overwrite_auth_challenges`. Inspect both HTTP status and the operation's JSON
status: existing management endpoints can return HTTP 200 with a failure object.
`POST /api/server/info` with an unknown realm returns HTTP 404.

## Canonical Identity and Renewable Credentials

Password login captures backend identity independently of transformed access
claims. A transform that sets Alice's subject to Bob cannot make Bob's password
authenticate Alice. Legacy access JWTs retain configured subject/email transforms;
participating refresh access JWTs use the canonical subject and transformed email.
Refresh preserves the canonical identity and SID. OIDC UserInfo uses the backend
email and a subject derived from immutable backend identity. Deleting and
recreating a username changes its OIDC subject.

Password changes (including identical updates), role changes, MFA enrollment/deletion or rule
changes, disablement, deletion, and local database reload invalidate captured
refresh/OIDC evidence. Verify refresh rejection, pending authorization-code
rejection, UserInfo rejection, and loss of silent OIDC login. Reload invalidates
old evidence even when an old file and credential version are restored. Ordinary
stateless access JWTs remain usable until normal expiry; this is not global
immediate access-token revocation.

Real required checkpoints must finish before renewable credentials or an OIDC
browser session exist. Authentication challenge rules resolve against available
factors. A `password totp` rule with no enrolled factor fails identification
closed (HTTP 400); deleting a factor does not remove that rule. Administrative
recovery can explicitly replace it with `password`, while an existing additive
`require mfa` transform still requires enrollment. The server API rejects an
empty rule list; the profile API supports an explicit empty-array reset.
Profile enrollment titles accept 3–50 alphanumeric characters, not spaces.
Do not infer completed MFA from a bearer/API key. The local-identity suite focuses on password/TOTP; the separate
`TestCaddyAuthenticationChallengesE2E` now qualifies signed WebAuthn assertions
through Caddy. The public authclient still implements password/TOTP.

**Canonical profile identity:** go-authcrunch revision
`3e28980b0f5a78463953b674241f154bb77c6679`, included in v1.3.3, fixed backend identity selection when
transformed claims collide with another account. The default Caddy
[profile regression](../../authentication-portal-api/references/profile-public-keys.md#canonical-profile-identity-regression)
verifies isolation through actual profile operations. Identity selection remains
library-owned; Caddy does not rewrite tokens or intercept profile operations.

## Caddy Validation

`TestLocalIdentityProvisioning` verifies static overwrite mapping, preserved
hashes/timestamps, credential versions, and unchanged legacy records through
`App.Provision`. `TestLocalIdentitySamePasswordReset` is a public database
consumer covering the same-password reset case the management HTTP API does
not expose.

`TestCaddyLocalIdentityE2E` launches an isolated Caddy process with verified TLS,
private temporary identity files, management/profile APIs, and separate resource
authorization. It explicitly configures and checks temporary Caddy storage;
`DefaultStorage` captures its path at package initialization, so changing XDG
environment variables inside a test alone does not isolate it.
`local_identity_e2e_test.go` covers form/JSON login, case/email
aliases, transformed subject/email, password/TOTP, root/nested mounts, absent
features, refresh-only, OIDC-only, both, neither selected, and independently
selected realms. Both form and JSON paths independently reject the transformed
account's password. OIDC exchange uses the existing independent RP verifier.

`local_identity_mutation_e2e_test.go` performs profile password changes, identical
plaintext updates, rejected new/current hash imports, admin reset, MFA changes,
account disable/enable, delete/recreate, realm reload, and old-file restoration
through actual routes.
It checks complete password-record preservation after rejected updates,
fresh authentication afterward, stale
refresh/code/UserInfo/browser evidence, and continued stateless access. It also
resets the password between password and TOTP checkpoints in both login flows,
checking both rejected JSON credentials and browser cookies/evidence.
Native requests use public authclient for fresh login and explicit refresh
requests, with no automatic retry. Runtime and access logs are checked for
synthetic secret/token disclosure. The fixture removes access-log response
`Location` values because OIDC redirects contain authorization codes.

Run from this repository:

```sh
go test -mod=readonly -race -count=1 -timeout=10m \
  -run '^Test(LocalIdentity|ProfilePublicKeyParserCompatibility|CaddyLocalIdentityE2E)' .
```

The canonical profile-isolation regression linked above is also enabled by
default and runs under `TestCaddyProfileCanonicalIdentityRegression`.
