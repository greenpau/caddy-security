# SQLite password identities

## Declaration and selection

The bundled `security.identity_stores.sqlite` module supplies password accounts
to the ordinary AuthCrunch root. Inside the global `security` block, declare:

```caddyfile
identity store sqlite accounts {
    realm staff
    path /var/lib/caddy/private/identities.db
    timeout 1s
}
authentication portal myportal {
    enable identity store accounts
    crypto key sign-verify {env.PORTAL_SIGNING_KEY}
}
```

The header supplies the instance name. The public SQLite parser requires one
realm and absolute database path; optional timeout defaults to one second and
accepts one millisecond through thirty seconds. Duplicate fields, unknown
options and nested bodies fail adaptation. Fields are literal; Caddy runtime
placeholders and secret lookups are not expanded in this module. Keep database
paths separate from the SQLite secrets, API-key, messaging and registration
categories. The database must already exist: ordinary app construction never
creates an empty account database or an administrator.

Native Caddy JSON uses `apps.security.identity_stores`, an array of objects with
`driver: sqlite`, `name`, `realm`, `path` and optional `timeout`. The app derives
`Config.ExternalIdentityStores` descriptors from normalized module configuration
before validation. Do not supply those derived descriptors inside the native
AuthCrunch config. They bind exact name/kind/realm plus a configuration digest
for persistence; runtime handles remain outside serialized configuration.

`caddyfile_identity_backend.go` dispatches modules, `plugins/identity-stores-sqlite/plugin.go`
delegates the parser, and `app_identity_stores.go` constructs handles before
`NewServerWithOptions`. Built-in local/LDAP declarations keep their existing
syntax and factory. The SQLite API-key authenticator remains a separate backend;
it does not provide these portal accounts.

## Trusted offline administration

Use `security identity create|set-password|roles|disable|enable|delete` on the
built Caddy command. Every action requires `--config` naming a private JSON file:

```json
{
  "config": {
    "name": "accounts",
    "realm": "staff",
    "path": "/var/lib/caddy/private/identities.db",
    "timeout": "1s"
  },
  "username": "alice",
  "email": "alice@example.test",
  "name": "Alice Example",
  "roles": ["authp/user"]
}
```

This is a create input. `roles` requires a complete replacement role list and
rejects `name`; password, enable, disable and delete actions accept only config,
username and email. Both selectors are required for mutations. Unknown fields,
duplicate JSON keys and malformed inputs are rejected before storage opens.

Create and set-password accept `--password-file`; omission prompts on a terminal
with echo disabled and confirmation. Passwords never belong in argv or JSON.
A password file loses one trailing LF or CRLF, preserving every other byte.
Passwords require 12–72 UTF-8 bytes and must not be blank. Private input files
must be regular files with mode 0600 under private 0700 directories and trusted
ancestors. These commands print only an action confirmation; they never print
account attributes or credentials. Commands other than create require an
existing database. They use trusted library methods, not public HTTP endpoints.

The database stores ordinary account fields in plaintext and bcrypt password
hashes. Names/emails are normalized by the backend. No bootstrap administrator,
public hash import or anonymous management endpoint is provided. Enrollment IDs
have a lifetime capacity of 10,000, including tombstones; account deletion does
not reclaim them or revive old identity evidence. An uncertain mutation must
be reconciled before retry; a successful mutation followed by output/Close
failure is also reported without replaying the operation.

## Authentication and lifecycle

Browser form, native JSON and direct Basic login use the same password backend.
Authentication captures immutable account ID, credential version and a fresh
per-instance epoch. `WithRefreshIdentity` holds the current account, roles,
policy checks and signing callback in one transaction. Callbacks must not
reenter storage; publish credentials only after success. Disablement, deletion
and password replacement invalidate captured evidence. Current roles govern
new credentials. Already signed access JWTs retain their bounded expiry.
Account quarantine must also reject requests already waiting for identity
transaction admission before their callbacks execute. In particular, a pending
Documents operation must not commit its independent write after an earlier
account COMMIT failure. The upstream helper and real TLS regression cover this
boundary. Drain pending consumers before closing and reconciling through a fresh
handle; reopening also requires fresh login evidence. An operation rejected
before its callback returns `storage_unavailable`, while a completed independent
mutation followed by outer failure retains `commit_uncertain`.

The app shares each configured handle across selected portals in that app,
closes candidate resources on failure, and drains consumers before closing
successful runtimes. Modules validate configuration without opening storage;
persistent roots defer construction to Start. A failed reload leaves the active
root usable. Persistent roots still require stop/start deployment and exclusive
root-state ownership. The normalized descriptor participates in persistent
configuration binding, and every new SQLite handle creates a fresh proof epoch.
Persisted refresh families cannot reuse identity evidence from an old instance;
users authenticate again after replacement. Account persistence alone does not
provide shared portal sessions or multi-host availability.

The backend remains kind `sqlite` with password authentication. In the upstream
capability implementation qualified by the SQLite handoff tests, its concrete
handle also preserves `ids.IdentityRequestStore` and `StoreCapabilityProvider`.
The upstream discovery endpoint checks for the actual bound-operation interface
before advertising Profile support; forwarding metadata alone is insufficient.
Profile information, diagnostics, partial dashboard and password changes work;
all sixteen Documents operations use the same immutable account proof. MFA,
profile API/public keys, stored login rules, connected accounts, recovery and OP
remain unsupported. Stronger factor requirements still deny issuance. Realm
labels such as `local` do not change backend kind. Registration workflows retain
their own adapter and prerequisites. Identity verification does not select
SQLite refresh-token storage.

These capabilities are available through the published go-authcrunch dependency
selected in `go.mod`. Before release, verify `go list -m -json` resolves that
version without a local replacement, rerun the Caddy journeys, and inspect
`security version` plus `go version -m` on the built executable. A sibling
checkout or an overriding Go workspace cannot establish published-module
compatibility. Never fabricate a version or ship a filesystem replacement.
The root and companions share one module pin.

Administration uses safe structured roles/email/name plus an explicit SQLite
record discriminator, capabilities and password count. Unsupported counts are
absent, never fabricated zeroes or verifier arrays. Additive roles merge
atomically and an identical retry does not revoke credentials. Stored challenge
replacement returns 501. Empty account listings are arrays; the complete-list
limit is 10,000 and unsupported queries fail. New HTTP support uses the existing
account schema, preserving UUIDs, enrollment tombstones and vault ownership.
The authored UI still needs capability/count/error integration; backend support
does not establish full UI parity.
The complete resulting roles array is bounded at 8 KiB of encoded JSON, including
escaping. Creation, enrollment, replacement and additions must reject oversized
records before persistence. Keep the upstream HTTP-200 mutation failure envelope
and existing login evidence on rejection; do not retry it as a transport failure.

## Validation

`plugins/identity-stores-sqlite/consumer_test.go` and `ownership_test.go` cover
public parsing, descriptors, real account authentication and independent handles.
The factory consumer also checks structured public administration data,
password-only counts and capability metadata, with no credential collections.
Root `TestSQLiteIdentity*` and `TestAppIdentity*` cover native binding,
normalization, isolation and resource ownership; the adaptation fixture is
`testcase_identity_sqlite`. `TestCaddySQLiteIdentityE2E` builds the production
command without cgo and exercises verified TLS browser/native/Basic login,
independent JWT checks, current roles, account mutations, storage failure,
failed/successful reload, profile/password success and revocation, unsupported
credential/OP rejection, stronger factor requirements and
persistent restart. Its Chrome helper uses rendered forms and private TLS trust. Successful-reload
checks discard the old listener’s idle client connections before the next
single-attempt authentication POST; they never replay a mutation on EOF.
`TestSecuritySQLiteIdentity*` and `TestCaddySQLiteIdentityCommandsE2E` cover
trusted provisioning, private inputs, terminal behavior and actual CLI processes.
Keep mutation-before-signing and cleanup/drain regressions alongside the factory
coverage. Standalone library fixtures complement these host tests.

`TestCaddySQLiteDocumentsE2E` runs real SQLite account, refresh and document
storage through the optional companion at root, ordinary and nested mounts,
including a realm named `staff`. It covers all
operations, transformed claims, admin isolation, sharing/revocation, stable IDs
and fresh login after stop/start, plus the verified-TLS Web Crypto journey.
Its mounted admin/profile checks also reject oversized escaped-role updates
without making the account unreadable or revoking its current profile login.
They also inject a malformed verifier into an isolated SQLite fixture and require
the upstream HTTP 503 `storage_unavailable` response without password/version
mutation, followed by restored real login. This must not become a 400 blaming the
submitted old password or a successful mutation in the host adapter.
Mounted tests also hold a real competing SQLite writer until the configured
transaction budget expires. Preserve Profile HTTP 503 and the admin HTTP-200
failure envelope, both with `storage_unavailable`; verify unchanged persistent
credentials/generation and restored profile access and login after lock release.
The `admin_lifecycle` journey creates an account through the mounted API and
uses its generated password for real browser-protocol login. It verifies duplicate
and wrong-selector failures, grant replacement and idempotent additions, health
reload, disable/re-enable, reset and delete/recreate. Require stale bound proofs to
fail, a health reload to preserve current proof, and stop/start to preserve the
managed account and vault while requiring fresh login. Reusing a username must
never inherit the deleted account's UUID or files. Inspect mutation envelopes and
persistent outcomes in addition to HTTP status.

Keep `TestCaddyDocumentsE2E` for the legacy local fixture. A candidate run uses
`GOWORK=off make test TEST_DIR='. ./plugins/identity-stores-sqlite' TEST='^TestCaddySQLiteIdentity|^TestCaddySQLiteDocumentsE2E|^TestSQLiteIdentity'`.
Record the source replacement and effective binary linkage alongside results.
