# Consul secrets manager

Use `security.secrets.consul` to resolve a separately provisioned encrypted record
through the existing `secrets:MANAGER:KEY` contract. The module borrows the ready
client, prefix and AES key from Caddy's configured `pteich/caddy-tlsconsul` storage.
It supplies a coherent provisioning snapshot, not live replacement of running
consumers. Keep related keys under one manager ID to share that exact snapshot.

## Configuration

Inside the global `security` block:

```caddyfile
secrets consul signing {
    record access
    prefix security/secrets
    timeout 3s
}
authentication portal myportal {
    enable identity store localdb
    crypto key sign-verify secrets:signing:key
}
```

This is a fragment requiring the named identity store, ordinary portal routing,
and global `storage consul` configuration. Use the existing storage address,
ACL/TLS settings and a private AES key shared by participating clients. Bootstrap
storage credentials independently; a manager cannot resolve the key needed to
read its own storage. Caddy lexical `{$ENV}` expansion remains available.

`record` is required once; `prefix` and `timeout` are optional single-value
settings. Defaults are `security/secrets` and `3s`; timeout is 1ms..30s. Manager
IDs cannot contain colons and must be unique in the app. Record names are exact,
nonempty text up to 256 bytes. Prefixes are canonical relative paths, without
traversal, controls or backslashes. Backend fields receive no runtime secret or
`{env.*}` replacement. Native app JSON uses `secrets_managers` entries:

```json
{"driver":"consul","name":"signing","record":"access","prefix":"security/secrets","timeout":"3s"}
```

The storage key hashes the record name under the configured global/adapter
prefixes and the secrets category. Different manager IDs may intentionally select
the same record. Their snapshots are independent reads; use one manager for
related references that must agree. Other categories retain separate key domains.

## Trusted provisioning

Import `plugins/secrets-consul` and call `New(ctx, *Config, storage)`, supplying
the borrowed Caddy `*storageconsul.ConsulStorage`. The returned `Client` supports
`Put`, `GetSecrets`, exact-key `GetSecret`, `Delete` and `Close`. Constructor
validation/readiness never creates a record. Only an authorized application may
call the mutation APIs. There is no Consul provisioning HTTP endpoint or CLI;
existing `security secrets` commands remain SQLite-specific.

`Put` accepts a nonempty `map[string]any` containing JSON-compatible values.
It atomically replaces the record after validating the complete graph. The
maximum is 128 top-level keys, 16 nesting levels, 4096 visited nodes and 64 KiB
of encoded JSON. Keys are bounded nonempty text; strings retain exact valid
UTF-8 bytes, including credential whitespace. JSON numbers read as `json.Number`,
including integers above JavaScript's exact-number range. Nil, booleans, finite
numeric scalars, `[]any` and nested `map[string]any` are supported. Invalid UTF-8,
cycles, non-finite numbers, invalid `json.Number`, arbitrary Go objects and
implicit encodings such as `json.RawMessage` or typed slices are rejected.

Rejected writes retain the previous record. `Delete` removes its value atomically
and is idempotent; it retains an encrypted schema marker. Client Close discards
only its logical handle, never stored peer data or the global Caddy client.
Payloads are encrypted with AES-GCM and fresh nonces using the complete storage
key as authenticated data. The module's JSON/config metadata exposes only
identifiers and backend settings, never secret values or encryption material.
Global storage's own configuration retains its existing Caddy visibility rules.

## Snapshot, rotation and failure semantics

Provision reads one coherent object, closes its short-lived logical client and
keeps an immutable snapshot for all of this manager's references. Numbers and
nested values preserve their types; callers receive detached copies. Dots in a
key are literal rather than JSON traversal. A present null differs from a missing
key. Empty string credentials fail; core secret consumers require final strings
and reject non-string results instead of coercing them.

Backend writes and deletion do not alter a serving runtime. A successful reload
loads a fresh snapshot; process restart requires the record to remain available.
Missing/deleted records, unavailable storage, incompatible documents, missing
lookup keys and non-string consumer values reject the candidate. Existing
serving consumers retain their resolved values when a candidate fails. A retired
module discards its snapshot after readers finish and cannot be reprovisioned.

Consistent reads and conditional transactions fence reads and replacements.
Only definite CAS conflicts retry, at most eight times within the deadline.
Transport errors or lost committed responses return unavailable without an
automatic retry. An uncertain Put may have replaced the record; reconcile before
retrying. It never changes an already serving snapshot or publishes one from a
failed candidate. Key rotation, rollback and schema migration require a drained
plan or fresh prefix; no adapter silently adopts incompatible ciphertext.

`TestConsulSecretsSnapshots` and `TestConsulSecretsUncertainWrites` cover aliases,
exact strings/numbers, detached nested values, snapshot isolation, malformed
input, bounds, deletion, cancellation and ambiguous writes. The production-command
journey `TestCaddyConsulCredentialsSecretsE2E/secret_snapshot_rotation_and_failed_reload`
checks verified TLS, exact secret-backed JWT signing, explicit reload rotation,
non-string/deleted/unavailable candidate rejection, restart and redacted output.
