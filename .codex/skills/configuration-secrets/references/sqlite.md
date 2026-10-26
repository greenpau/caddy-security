# SQLite secrets

## Ownership and configuration

The bundled `security.secrets.sqlite` module consumes the public AuthCrunch
SQLite secrets backend. It does not add a root `Config.Secrets` loader or an
HTTP mutation API. Configure a manager in the global security block:

```caddyfile
{
 security {
  secrets sqlite signing {
   path /var/lib/caddy/private/secrets.db
   record access
   timeout 1s
  }
  authentication portal myportal {
   crypto key sign-verify secrets:signing:secret.key
  }
 }
}
```

Add the portal's identity store/provider and HTTP mount separately. An
authorization policy can consume the same record with
`crypto key verify secrets:signing:secret.key`.

The header supplies the upstream `name`. `path` and `record` are required once;
`timeout` is optional, defaults to one second, and accepts one millisecond
through thirty seconds. Reject duplicate/unknown statements, nested blocks,
missing closing braces, or a second `name` in the body. A quoted brace is data.
Adaptation uses the public backend parser and performs no database I/O. Native
module JSON uses `driver: "sqlite"`, `name`, `path`, `record`, and `timeout`.

Backend fields are literal: runtime `{env.*}` and `secrets:*:*` expansion is not
supported there. Caddy's earlier `{$ENV}` adaptation applies normally. Names
cannot contain a colon because lookups require exactly three segments. Dotted
keys are literal top-level keys, not traversal. Payload strings retain their
exact bytes. Missing keys, empty strings, numbers, null, arrays and objects
cannot become string credentials; no numeric coercion is permitted. Whole
record copies preserve `json.Number` and distinguish null from missing.

## Storage and trusted provisioning

Use an absolute path on a local POSIX filesystem with reliable SQLite locks.
Create the parent as 0700 and keep it under trusted ancestors. Database and
sidecars must be regular 0600 files; symlinks at the database/parent boundary,
replacement, foreign schemas and unsupported versions fail closed. The database
is plaintext. This contract does not cover Windows, network filesystems,
encryption at rest, or protection from the owning account. The pure Go driver
supports builds with `CGO_ENABLED=0`.

Ordinary Caddy provisioning requires an existing database and record. Only the
explicit offline command creates a missing database. Prepare an owner-only 0600
JSON file in a 0700 directory with trusted ancestors and no symlink components:

```json
{
  "config": {
    "name": "signing",
    "path": "/var/lib/caddy/private/secrets.db",
    "record": "access",
    "timeout": "1s"
  },
  "values": {
    "secret.key": "replace-with-a-privately-generated-signing-secret",
    "revision": 9007199254740993
  }
}
```

```sh
bin/authcrunch security secrets put --config /var/lib/caddy/private/input.json
```

The sample value is instructional, not a deployment key. Values are accepted
only from the private file, never flags or ordinary Caddy configuration. Use a
private editor or trusted provisioning tool; do not put credentials in shell
history. Success prints only the operation outcome. Protect and remove input
files according to the deployment's credential-handling policy.

`put` atomically replaces the whole bound record. `delete` takes the same JSON
`config` but rejects a `values` field; deleting an absent record is idempotent:

```sh
bin/authcrunch security secrets delete --config /var/lib/caddy/private/delete.json
```

Input is bounded to 128 KiB and must be one JSON object with exact schema keys.
Duplicate keys at every level, unknown/case-folded config fields, malformed
UTF-8, lone surrogate escapes, and trailing documents fail before mutation.
Numbers remain `json.Number`, including integers larger than float64 can retain.
The backend enforces a nonempty object, at most 128 top-level keys, 16 container
levels, 4096 nodes, 128-byte numeric tokens, 64 KiB aggregate text/encoded
payload, and 1024 records. The trusted Go API also rejects custom marshalers,
implicit byte/struct serialization and malformed UTF-8. An invalid replacement
preserves the previous record, including for a freshly provisioned consumer.

Each command owns and closes its database handle. Errors omit payloads and
backend details. A commit-uncertain result requires reconciliation through a
fresh handle before deciding whether to retry; no blind retry or success claim
is made. A successful mutation followed by close/output failure is reported as
completed with a follow-up failure, rather than as a rolled-back transaction.

## Publication, rotation and cleanup

Each Caddy candidate loads one complete record exactly once, then closes its
database handle. All references to that manager resolve from the same immutable
private snapshot, including portal signing and policy verification. Consumers
are constructed from a copied app config. GetConfig exposes only name, kind,
record and the host-required id alias. Payloads and database paths are absent
from module metadata; declarative module JSON necessarily retains the configured
path, record and lookup references, never resolved values.

No watcher, request-time database lookup, implicit refresh or automatic key
rotation is installed. To adopt a replacement:

1. Provision the complete record using the offline command.
2. Explicitly reload Caddy; use `reload --force` if declarative JSON is unchanged.
3. Verify a newly issued token and protected request with the new key.

Existing consumers keep their old values until successful replacement. An
invalid write preserves storage; an invalid consumer candidate preserves the
serving configuration. Deleting a record therefore prevents the next candidate
from starting, but does not revoke the active runtime. Plan rotation and
revocation around that explicit publication boundary. Persistence of this
secret record does not imply persistence of portal sessions or refresh state.

Module cleanup waits for snapshot readers and discards the private data.
Resolved consumers own their copied values and never borrow a database handle;
retiring one candidate cannot close storage under active HTTP requests. A
process restart reads the current durable record again. App-level resolution,
validation and constructor failures with secret managers suppress upstream
error details that may contain resolved instructions. Do not weaken this rule
for debug logging or expose the private runtime config through introspection.

## Verification

The sources are `plugins/secrets-sqlite/plugin.go`, `command_secrets.go`, `app.go`, and the
runtime resolver. `plugins/secrets-sqlite/consumer_test.go` and `caddyfile_test.go`
cover parsing, metadata, exact types, snapshot detachment, cleanup, invalid storage,
no runtime database dependency and reprovision rejection. Root
`secrets_sqlite_test.go` retains global dispatch, native loading, resolver type
rejection, duplicate manager IDs and private app failures.
`command_secrets_test.go` covers private input, strict JSON,
invalid replacement and trusted mutation. The registered
`testcase_secrets_sqlite` adaptation fixture verifies module and consumer shape.

`TestCaddySQLiteSecretsE2E` builds Caddy with explicit companion imports without CGO and
uses a trusted TLS listener, password login and independent JWT verification.
It exercises exact signing-key bytes, explicit reload, failed replacement then
fresh consumer rebuild, invalid/missing keys and storage, rejected candidates,
restart, cleanup, native introspection, autosave and debug-log redaction. It
uses synthetic credentials and a disposable private database, with bounded
commands and no machine trust changes. Backend transaction fault injection and
schema internals remain owned by AuthCrunch; host tests consume the public API.
