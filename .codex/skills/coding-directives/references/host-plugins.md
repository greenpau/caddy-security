# Host plugin contracts

Read this when adding a backend adapter, native configuration, policy binding,
or runtime resource ownership. `app_plugins.go` owns the claims enrichment
boundary and `app_external_authorization.go` owns external authorization;
`app.go` owns construction and retirement of the single AuthCrunch root.
HTTP integrations borrow that root. Do not replace root
assembly with a second host implementation of portals, gatekeepers or persistence.

## Source authority and naming

Inspect the module directory selected by `go list -m -json
github.com/greenpau/go-authcrunch`. Its public APIs and consumer fixtures are the
runtime authority. Read its plugin-development and category guidance when
available; a sibling checkout and temporary handoffs may describe different
code. Keep those inputs read-only and perform host validation in this repository.

Backend libraries export ordinary Go constructors. Importing a backend neither
registers a Caddy module nor changes AuthCrunch dispatch. A Caddy companion owns
module registration, native decoding, text parsing, binding and resource lifetime.
Use a category-specific `security.<category>.<driver>` ID and `driver` as the
inline module selector. The selector, configured instance name, target policy,
realm and database path are distinct values; never use a path as implicit identity.

| Category | Host module naming | Status |
| --- | --- | --- |
| Claims enrichment | `security.claims_enrichment.<driver>` | Native app binding below; bundled `static` adapter also has policy Caddyfile syntax |
| Secrets | `security.secrets.<driver>` | Existing `SecretsManager` integration; external static/AWS module IDs remain unchanged |
| External authorization | `security.external_authorization.<driver>` | Native app binding and bundled `httpjson` adapter with policy Caddyfile syntax |
| Credential authenticators | `security.credential_authenticators.<driver>` | Proposed; bind validated runtime proxy config before root construction |
| Identity stores/providers | `security.identity_stores.<driver>`, `security.identity_providers.<driver>` | Proposed; root injection unavailable |
| Messaging | `security.messaging.<driver>` | Proposed; runtime injection is possible but no host adapter/worker exists |
| Registration workflows | `security.registration_workflows.<driver>` | Proposed; identity-store/root composition gap |
| Signing/refresh storage | `security.cryptographic_signing.<driver>`, `security.session_and_refresh_storage.<driver>` | Proposed; standalone engine APIs do not select portal backends |
| OAuth login storage | `security.oauth_login_stores.<driver>` | Proposed; public root option exists, host loader does not |

These proposed namespaces are design conventions, not registered modules or
accepted Caddyfile syntax. Add loaders only with a supported consumer and its
acceptance tests. Do not add a universal map-based plugin executor or a second
process-global runtime registry.

## Native claims enrichment binding

`App.ClaimsEnrichment` is JSON `claims_enrichment`, an optional list of
`ClaimsEnrichmentBinding` objects. Each object has:

| Field | Meaning |
| --- | --- |
| `policy` | Exact existing authorization policy name; one binding per policy |
| `config` | Typed `enrichment.Config`: source/revision, issuer, realm, immutable subject claim, tenant claim, audience, timing and requested attributes |
| `backend` | Raw module object containing `driver` and the companion's typed configuration |

Omission or an empty list preserves ordinary policy behavior. Null list entries,
missing/duplicate/unknown policy references, missing config/backend, invalid
identity bindings, unknown drivers and modules with the wrong interface fail
provisioning. AuthCrunch validates identity binding values and duration defaults.
Each backend must also validate its own source, revision and freshness constraints.
The same driver can be used by distinct policies; each binding gets a fresh
backend owned by that app. There is no named shared-backend pool.

Binding validation operates on deep copies. Caddy's `LoadModule` clears the raw
field it loads, so pass a copied binding to it. Preserve original JSON through
provisioning and round trips. Decode backend values into public typed structs;
where arbitrary JSON numbers are permitted, the companion must use
`json.Decoder.UseNumber`. Caddy decodes its configuration tree and inline module
objects through `map[string]any`, so raw module bytes alone cannot preserve bare JSON numbers.
The static adapter transports its entire object in a `claims_json` string and
uses `UseNumber` only after that boundary. Do not insert decoded numeric values
into the outer Caddy JSON tree.

The bundled static adapter has a
[policy Caddyfile block](../../configuration-authorization/references/static-claims.md).
Backend fields and identity binding fields receive literal values without Caddy
runtime replacement. Add any supported replacement centrally with its feature's
parser, redaction and resolution tests. Raw module configuration is visible to ordinary
Caddy configuration introspection; never put runtime credentials/results in it.

## Factory and resource ownership

External authorization follows the same ownership rules through
`App.ExternalAuthorization`, JSON `external_authorization`, and
`ExternalAuthorizationBackendModule.NewExternalAuthorizationBackend(context.Context,
external.Config)`. Each binding selects an existing local `policy`, typed
external `config`, and raw `backend` module. The remote `config.policy` is a
different name. The app clones attribute selections and module bytes, validates
unique policy references, and attaches `external.New` through
`Gatekeeper.SetExternalAuthorizer` before root publication. Omitted bindings
preserve ordinary behavior. The
[external authorization reference](../../configuration-authorization/references/external-authorization.md)
owns text/native fields, TLS and decision behavior.

Claims backends are constructed before external backends. If a later factory
or attachment fails, close the root, then all acquired backends in reverse
order across both categories. The HTTP JSON wrapper implements `io.Closer`
around the library's errorless Close and owns its injected TLS transport.

Claims companions implement `ClaimsEnrichmentBackendModule` alongside `caddy.Module`.
`NewClaimsEnrichmentBackend(context.Context, enrichment.Config)` returns an
`enrichment.Backend` and error. Return an actual nil interface on nil results;
typed nils violate the module contract. Include compile-time interface guards.

Caddy `Provision`/`Validate` prepare and validate configuration only. They must
not open runtime databases, create transports/workers, or resolve the parent
security app recursively. Construction happens while the parent is provisioning
under its mutex, so requesting that app again can deadlock. The factory receives
an independent normalized binding copy at runtime construction and must check
backend-specific constraints before returning a ready backend.

The constructor context bounds setup only. Runtime lookups use their request
context; workers need separately owned cancellation and joining. Do not retain
the Caddy context as a runtime shutdown signal: Caddy can cancel it before HTTP
requests finish. Module `Cleanup` must never dispose returned backends.

The returned backend may implement `io.Closer`. Each successful factory call
transfers a distinct resource ownership to the app; do not return a shared
closable singleton across bindings or configurations. A factory that fails after
acquisition must either return the closable partial backend with its error or
unwind everything before returning nil. Non-closable backends own no resources
that need disposal. Construction errors and Close errors must not leak supplied
values through logs; the host reports binding/resource positions instead.

The app constructs its root first, obtains each named gatekeeper, creates the
backend and `enrichment.Enricher`, and calls `SetClaimsEnricher`. Only after every
attachment succeeds does it publish the server for request admission. Failure
closes the private root before all acquired backends, in reverse order, without
touching the active configuration. A later Caddy provisioning/validation/start
failure reaches the same app cleanup path. Runtime objects never enter JSON.

For a persistent root, `Provision` prepares factories and validates bindings;
`Start` constructs the root and backends. Validation must not open persistent
runtime storage. Backend checks requiring construction happen at `Start` in
that mode. Preserve the existing rejection of overlapping persistent reloads.

At retirement, the app closes admission, waits for admitted calls, closes the
root, and then closes backends. Root Close owns built-in components only.
Module cleanup order and HTTP grace-period expiry do not replace request drain.
The [runtime lifecycle contract](runtime-lifecycle.md) owns errors, reservations
and concurrent cleanup. Future category adapters must preserve these invariants
and define any worker shutdown ordering before sharing this resource mechanism.

## Public injection audit

Recheck these boundaries against the selected module before each adapter change.
An interface satisfied by a backend does not establish a usable root attachment.

| Category | Public consumer and host consequence |
| --- | --- |
| Claims enrichment | `Server.GetGatekeeperByName` → `Gatekeeper.SetClaimsEnricher`; supported before publication through this host boundary |
| External authorization | `Gatekeeper.SetExternalAuthorizer`; attached to the private root through the host binding and bundled HTTP JSON factory |
| Secrets | Host `SecretsManager` resolves values before root construction; separate adapter must preserve exact types and redact `GetConfig` metadata |
| Messaging | `messaging.Config.AddProvider` preserves runtime injections through validation, excludes them from JSON, and is consumed by registry `SetMessaging`; bind after config restoration and before validation/construction; host still needs a bounded delivery worker |
| OAuth login storage | `NewServerWithOptions` and `ServerOptions.OAuthLoginStores`; supply named runtime bindings on each construction, close only after consumers drain; current app uses `NewServer` without these bindings |
| API-key authenticators | Validate `PolicyConfig`, then call its `AuthProxyConfig.AddAuthenticator` before `NewServer` on that same private graph. The root retains these runtime bindings and checks `HasAuthProxies`. Waiting to call `Gatekeeper.AddAuthenticators` after root construction fails for an injected-only realm |
| Identity stores | `PortalParameters.IdentityStores` supports direct portal composition; root factories dispatch built-in kinds and expose no injected store option. Do not disguise SQLite as a local snapshot store |
| Ticket identity providers | `PortalParameters.IdentityProviders` and optional HTTP-login interface support direct composition; root provider dispatch has no injected-provider option |
| Registration workflows | `Portal.AddUserRegistry` is public, but the SQLite workflow also requires its injected SQLite identity store; root dispatch constructs local registries and cannot assemble that dependency graph |
| PS256 signing | `token_refresh.NewManager` accepts a signer; root portal/OP signing does not expose that selection |
| Refresh storage | The same standalone manager accepts a store; it does not select portal/OP persistence or provide complete distributed session state |

For API-key adapters, parse/validate the complete policy first, keep its raw
declarations intact, then bind into the resulting runtime proxy config before
constructing the root. Check backend name and realm explicitly, reject collisions
with root-owned portal names and existing bindings, and check all proxies before
publication. Runtime bindings disappear on JSON serialization: restore them on
each new graph after decoding. The backend remains caller-owned on constructor
failure and root Close. Add regression coverage for this ordering; do not assume
reparsing raw declarations preserves an injected handle. No Caddy adapter for
this path is implemented yet.

Do not remove auth-proxy declarations during construction and patch them afterward,
create placeholder portals, or replace root-owned authenticators. For identity
and registry gaps, do not reconstruct a parallel root.
Upstream work must define typed injection, duplicate-name handling, consumer
validation, caller ownership on constructor failure and disposal, and persistent
binding behavior. Keep unavailable backend selectors out of operator examples.

SQLite references require distinct private local POSIX database files and a
pure-Go production build. They do not imply network-filesystem support, encrypted
storage, schema migration or multi-host availability. Keep trusted issuance,
enrollment and delivery-worker controls in their own adapters.

## Validation surfaces

`app_plugins_test.go` checks native binding validation, immutable JSON/config,
module type checks, constructor failure, reverse cleanup, error redaction,
concurrent drain and deferred persistent construction. `app_plugins_e2e_test.go`
uses a test-only module through actual Caddy TLS routes and reloads: repeated
authenticated requests, rejected candidates, validation-only cleanup, a blocked
lookup across replacement, and final stop. It verifies transport trust.

These tests establish the host factory/lifecycle seam. Static adapter coverage
lives in `claims_enrichment_static_test.go`, `caddyfile_authz_enrichment_test.go`
and `claims_enrichment_static_e2e_test.go`, plus adaptation fixtures. Each other
companion needs its own native/text round trips, real authentication/authorization
E2E, backend failures and resource assertions. `app_external_authorization_test.go`
checks the external binding and mixed-category cleanup; the HTTP JSON adapter's
unit and TLS E2E tests qualify its service transport and protected requests.
These tests do not qualify SQLite storage.
