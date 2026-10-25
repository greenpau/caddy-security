# Static claims for authorization

Use `claims enrichment static` inside one authorization policy to supply literal
values to its ACL decisions. The backend gives the same values to every accepted
identity, including different subjects and tenants. It is not a directory lookup
or a way to issue roles. Omission preserves the policy's ordinary behavior.

## Configuration and binding

One flat block is allowed per policy. The following is grammar notation; use the
[complete adaptation fixture](../../../../testdata/caddyfile_adapt/testcase_authorize_static_claims.Caddyfile)
for a concrete example of the backend's source and contract fields.

```caddyfile
claims enrichment static {
 source static
 version <static-backend-contract>
 issuer <exact-token-issuer>
 realm <exact-token-origin>
 subject claim <immutable-account-claim>
 tenant claim <tenant-claim>
 audience <required-token-audience>
 timeout 1s
 max age 1m
 attribute enrichment.department string
 claim enrichment.department engineering
 attribute permissions string list
 claim permissions json `["read","write"]`
 attribute settings json
 claim settings json `{"enabled":true,"quota":9007199254740993,"optional":null}`
}
```

`source` and `version` must equal the static backend's exported `Source` and
`Version` contract constants. Each scalar occurs once. `timeout` defaults to one
second and accepts positive durations up to 30 seconds. `max age` defaults to one
minute; static results expire one minute after observation, so the binding must
allow at least one minute, up to 24 hours. It is a freshness bound, not a cache TTL.

All identity settings are required. The authenticated issuer and origin must
exactly match `issuer` and `realm`; the token audience list must contain
`audience`. The named subject and tenant claims must be distinct, nonempty string
claims. The host must establish that the subject is an immutable account ID
within issuer, realm and tenant. Do not substitute a username, display name or
email without an identity-source guarantee. The binding chooses claim names; it
does not filter for a particular subject or tenant value.

Repeat `attribute <name> string`, `attribute <name> string list`, or
`attribute <name> json` for each requested output. Each requested claim must be
configured and satisfy its declared type. Additional configured claims are
allowed but are not requested or exposed. Names are literal top-level keys;
dots do not traverse nested objects. Register a typed ACL field alias for any
custom claim used by a rule; see [typed ACL fields](typed-acl-fields.md). The
ACL grammar consumes strings and string lists; it does not coerce or compare
numbers, booleans, nulls or nested objects. Those JSON values remain available
in the detached claim map, and a referenced ACL field with the wrong type denies.

`claim <name> <value>` supplies a literal string. `claim <name> json <value>`
decodes a complete JSON value in one Caddy token. Backtick quoting is useful for
objects, arrays and JSON strings. Keep each declaration on one line; encode
control characters with JSON escapes. JSON supports null, booleans, exact numbers,
strings, arrays and objects. Use a JSON string for an empty value or whitespace;
plain empty Caddy tokens are rejected. String/string-list declarations have
stricter whitespace rules than JSON-typed strings. Duplicate claim or attribute
statements, protected names, invalid types and malformed blocks are rejected.

There are 1–32 claims/attributes. Individual strings are limited to 4096 UTF-8
bytes, string lists to 128 entries, and JSON values to 16 container levels,
4096 nodes and 64 KiB of encoded JSON per attribute. Shared AuthCrunch validators
own these bounds; the host checks static binding compatibility before publication.

## Native Caddy JSON and literal transport

The app's `claims_enrichment` list contains `policy`, `config` and `backend`.
`config` uses the public enrichment fields: `source`, `version`, `issuer`, `realm`,
`subject_claim`, `tenant_claim`, `audience`, `timeout`, `max_age`, and `attributes`
objects with `name` and `type`. List attributes use type `string_list` in JSON.
The backend object is:

```json
{
  "driver": "static",
  "claims_json": "{\"enrichment.department\":\"engineering\",\"quota\":9007199254740993,\"optional\":null}"
}
```

`claims_json` is required and contains one JSON object encoded as a string. The
Caddyfile adapter emits this representation automatically. Bare `claims` objects
are unsupported: Caddy converts both its configuration tree and inline module
objects through floating-point values before the app/module can decode them.
The string boundary followed by `json.Decoder.UseNumber` preserves exact values
through adaptation, load, reload and configuration storage. Use a JSON encoder
for the outer string; do not manually substitute unescaped data into it.

Binding fields and claim values do not receive Caddy runtime replacement,
secret-manager lookup or claim-template expansion. Caddy's ordinary `{$ENV}`
lexical substitution still occurs before adaptation. Strings such as
`{env.NAME}` remain literal data. Configured claims are visible in Caddy's
configuration and should not contain secrets merely because a backend error is
redacted. Changing values requires a new configuration/backend.

## Request behavior and lifecycle

The app attaches one fresh static backend to the private gatekeeper before it
serves requests. Construction and parsing perform no IO; the backend owns no
workers, resources or cleanup method. Every lookup returns an independent,
bounded snapshot. The app's existing request-drain and failed-candidate lifecycle
continues to apply.

Enrichment runs after authentication and before ACL evaluation, including token
cache hits. It is required: binding mismatch, backend error, expired result,
invalid output or deadline failure denies the protected request. An early ACL
allow cannot bypass required enrichment. Explicit configured bypasses still work,
and a policy without an enrichment binding is unaffected. Backends must honor
request cancellation; the effective deadline is the earliest of the request
deadline, binding timeout and authenticated expiration. An uncooperative
in-process implementation cannot be forcibly interrupted.

Only a detached ACL view receives the values. The signed token, cached identity,
roles, authentication evidence and injected claim headers retain authenticated
values. Enrichment does not create headers for newly supplied claims. Plain
custom names cannot collide with any authenticated claim. The selected backend
owns the `enrichment.` namespace in the detached view, removing previous values
there before adding its current snapshot; this does not change the signed or
header-visible values. Standard identity/security claims and protected provider
prefixes cannot be declared as outputs.

## Maintenance and acceptance

Trace `caddyfile_authz_enrichment.go` through both shared parsers,
`plugins/claims-enrichment-static/plugin.go`, the app factory boundary and the gatekeeper's
required enricher. Keep backend-specific validation separate from shared grammar.
Do not implement another authorization engine in the HTTP handler.

`plugins/claims-enrichment-static/consumer_test.go` covers native string transport, exact numbers,
independent snapshots and malformed configuration. `caddyfile_authz_enrichment_test.go`
covers shared defaults, quoting, bindings, rejection and no partial publication.
The registered positive/negative adaptation fixtures cover the emitted app JSON.
`claims_enrichment_static_e2e_test.go` exercises a real local login and trusted TLS
Caddy routes, custom ACLs, collision rejection, unchanged tokens/headers, required
failures, repeated-token reevaluation, bypass and failed/successful reloads. Its
fault decorator is test-only and wraps the actual static backend before serving.
Keep exact-number assertions on the real Caddy load path, not only on a directly
constructed Go module.
