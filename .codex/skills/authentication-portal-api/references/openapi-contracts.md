# OpenAPI contracts through Caddy

AuthCrunch owns the authored HTTP contract in
`assets/openapi/content/openapi.yaml` and its relative YAML references. Select
the source that matches the module used by this checkout: inspect
`go list -m -json github.com/greenpau/go-authcrunch`, including `Replace.Dir` when
present. The published module contains these files. A local replacement can
contain unreleased amendments even when the specification's nominal version
is unchanged; record its revision and schema identity with validation evidence.
Do not silently fetch a moving specification when selected contract data is
missing.

The specification describes unversioned paths relative to the configured portal
origin and mount. `/auth` is an example mount, not a fixed API prefix. Preserve
the complete URL when mounting `authenticate`; root and nested mounts must reach
the same handler contracts. Deployment-defined application resources, Caddy's
management API and earlier app lifecycle admission errors are outside this
portal specification.

AuthCrunch's separate OpenAPI tooling can bundle or display the specification.
Neither its presence in the module nor a successful adaptation creates a Caddy
documentation endpoint, enables an optional API, or installs a Scalar server.
Use immutable source references for a shared contract; generated workspaces and
expiring build artifacts are not durable release identifiers.

## Wire-format distinctions

Match operation, status and media type before decoding a payload. Keep the HTTP
status authoritative: portal errors use a boolean `error` property, while OAuth
errors use a different envelope. Schema validation complements authentication,
cache, cookie and ownership assertions; it cannot prove those behaviors alone.
Claims and profile envelopes allow extensibility, so also check the expected
identity fields and the concrete profile entry. Validate timestamp semantics
explicitly; a schema format annotation alone need not enforce them.

| Operation | Wire contract |
| --- | --- |
| `GET /beacon`, 200 | Exactly the raw bytes `OK` under `application/json`; do not JSON-decode success. Missing/invalid credentials in JSON mode return 401. |
| `GET /whoami`, 200 JSON | Claims retain custom fields and numeric Unix-second time claims. `probe=true` adds boolean `authenticated` and duration `expires_in`. |
| `GET /whoami`, HTML | Browser identity rendering can use formatted display times. It is a separate representation. |
| `GET /api/server/metadata`, 200 | JSON-encoded object under `text/plain`, with RFC3339 timestamp and linked identity-library metadata. |
| Profile API | Requires stored portal-session evidence associated with the exact token; successful access-only JSON login is insufficient. |
| Public JWKS | `application/jwk-set+json`, public keys only. HEAD preserves the discovery headers and has no response body. |

For ordinary portal JSON routing, the Accept value must be exactly
`application/json`; a list, quality parameter or charset does not qualify.
The `format=json` query signal also selects JSON. Dedicated API, discovery,
provider and refresh routes retain their own dispatch/credential rules. In
particular, beacon has no HTML handler and returns HTML 404 without JSON routing.
Do not replace these observed contracts with conventional HTTP negotiation in
the thin Caddy middleware.

Access tokens, profile-session evidence, refresh credentials and OIDC provider
sessions are distinct authorities. Administrative access requires an admitted
admin token, not a profile session. Public JWKS requires none of them. Keep
feature flags and provider-specific proof requirements explicit even when the
schema documents an operation.

## Host qualification

`openapi_contract_test.go` reads only the selected module's authored contract and
uses a local-only JSON Schema loader. It rejects missing operations, undocumented
statuses/media, unsafe references and invalid payloads without dumping response
bodies or credentials. Its unit tests must prove rejection as well as acceptance
and retain exact JSON numbers. Known beacon/metadata decoding exceptions are
scoped to their exact operations and statuses.

`TestCaddyOpenAPIContractE2E` qualifies a bounded matrix through real Caddy TLS
at root and nested mounts: negotiation, probes, metadata, profile authority,
public discovery and isolation outside the nested mount. A root catch-all has
no sibling path outside its mount. Login/refresh assertions can
reuse existing client journeys; retain their semantic transport and cookie
checks. This sampling does not certify every documented API operation or any
official OIDC conformance plan. Extend the matrix when a changed consumer
depends on another operation instead of copying the upstream contract suite.
