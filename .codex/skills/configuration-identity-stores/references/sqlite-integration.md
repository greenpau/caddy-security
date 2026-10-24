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

`caddyfile_identity_backend.go` dispatches modules, `identity_store_sqlite.go`
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

The backend remains kind `sqlite` and password-only. MFA, API-key login,
recovery and profile credential mutations are unsupported. A stronger portal
factor requirement must deny issuance. Recognized authenticated profile requests
return 501: the profile API admits only local authentication, and the SQLite
plugin also lacks `ids.IdentityRequestStore`. Portal OP
realms and external-identity attachment targets retain their local-store
restrictions. Registration workflows have their own adapter and prerequisites.
Transactional identity verification supports the existing portal refresh engine;
it does not select SQLite refresh-token storage.

## Validation

`TestSQLiteIdentity*` and `TestAppIdentity*` cover parsing, native binding,
normalization, isolation and resource ownership; the adaptation fixture is
`testcase_identity_sqlite`. `TestCaddySQLiteIdentityE2E` builds the production
command without cgo and exercises verified TLS browser/native/Basic login,
independent JWT checks, current roles, account mutations, storage failure,
failed/successful reload, profile/OP rejection, stronger factor requirements and
persistent restart. Its Chrome helper uses rendered forms and private TLS trust.
`TestSecuritySQLiteIdentity*` and `TestCaddySQLiteIdentityCommandsE2E` cover
trusted provisioning, private inputs, terminal behavior and actual CLI processes.
Keep mutation-before-signing and cleanup/drain regressions alongside the factory
coverage. Standalone library fixtures complement these host tests.
