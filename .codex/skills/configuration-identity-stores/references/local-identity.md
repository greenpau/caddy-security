# Local Identity Compatibility

This contract is qualified against the selected go-authcrunch v1.2.5 module.
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
`new_password`. Management uses the existing `/api/server/user` operations,
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

Password changes (including identical updates), MFA enrollment/deletion or rule
changes, disablement, deletion, and local database reload invalidate captured
refresh/OIDC evidence. Verify refresh rejection, pending authorization-code
rejection, UserInfo rejection, and loss of silent OIDC login. Reload invalidates
old evidence even when an old file and credential version are restored. Ordinary
stateless access JWTs remain usable until normal expiry; this is not global
immediate access-token revocation.

Real required checkpoints must finish before renewable credentials or an OIDC
browser session exist. Authentication challenge rules resolve against available
factors; a `password totp` rule alone does not force enrollment when no factor
exists. Use an existing `require mfa` transform when enrollment is required.
Profile enrollment titles accept 3–50 alphanumeric characters, not spaces.
Do not infer completed MFA from a bearer/API key. Hardware-backed/WebAuthn
assertions are outside this qualification; authclient implements password/TOTP.

**Profile limitation:** v1.2.5 profile handlers still select backend identity
from transformed session claims. A legacy login whose subject and email both
collide with another account can read and mutate that account's profile. This
does not qualify as canonical profile isolation. See the strict failing
[profile regression](../../authentication-portal-api/references/profile-public-keys.md#known-upstream-profile-identity-gap).
Fixing it belongs to go-authcrunch; Caddy must not rewrite tokens or intercept
profile operations to mask the library defect.

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
updates/imports, new imports, admin reset, MFA changes, account disable/enable,
delete/recreate, realm reload, and old-file restoration through actual routes.
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

This default suite covers supported behavior. The separate, deliberately failing
profile-isolation qualification is linked above; a green default suite does not
resolve that upstream gap.
