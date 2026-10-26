# Host plugin contracts

Read this when adding a backend adapter, native configuration, policy binding,
or runtime resource ownership. `app_plugins.go` owns the claims enrichment
boundary and `app_external_authorization.go` owns external authorization;
`app_credential_authenticators.go` owns fresh API-key bindings;
`app_identity_stores.go` owns named identity-store bindings;
`app_identity_providers.go` owns external login-provider bindings;
`app_messaging.go` owns notification backends and their delivery workers;
`app_registration_workflows.go` owns enrollment bindings and dependency ordering;
`app_refresh_stores.go` owns immutable managed refresh factories;
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
| Credential authenticators | `security.credential_authenticators.<driver>` | Native app declarations and bundled SQLite/Consul factories with global Caddyfile syntax; bind validated runtime proxy config before root construction |
| Identity stores | `security.identity_stores.<driver>` | Native/global declarations and bundled SQLite factory; derived descriptors and runtime handles enter ordinary root assembly |
| Identity providers | `security.identity_providers.<driver>` | Native/global declarations and bundled SQLite tickets; normalized descriptors and exact caller-owned providers enter ordinary root assembly |
| Messaging | `security.messaging.<driver>` | Native/global declarations and SQLite outboxes; optional named email delivery uses an app-owned bounded worker |
| Registration workflows | `security.registration_workflows.<driver>` | Native/global declarations and bundled SQLite enrollment; exact borrowed dependencies and explicit portal registry selection |
| Access signing | `security.access_signers.<driver>` | Immutable factory and borrowed root/portal signer; bundled `rsapss` |
| Refresh storage | `security.refresh_stores.<driver>` | Native/global named declarations and bundled SQLite; immutable factories and borrowed generation views consumed by selected persistent portals |
| OAuth login storage | `security.oauth_login_stores.<driver>` | Native/global named declarations and bundled SQLite storage; immutable factories supply exact borrowed runtime handles through root options |

The categories retain their typed public consumers. Do not add a universal
map-based plugin executor or a second process-global runtime registry.

## Bundled companion packages

Implement each companion in `plugins/<category>-<backend>/plugin.go`, flattening
the AuthCrunch category/backend boundary. These packages share this repository's
Go module and dependency pins; they are not nested modules. Each imports its
corresponding AuthCrunch backend and registers its own Caddy module exactly once.

| AuthCrunch backend under `plugins/` | Caddy companion under `plugins/` | Caddy module ID |
| --- | --- | --- |
| `claims-enrichment/static` | `claims-enrichment-static` | `security.claims_enrichment.static` |
| `authproxy.ContextAuthenticator` (host Consul implementation) | `credential-authenticators-consul` | `security.credential_authenticators.consul` |
| `credential-authenticators/sqlite` | `credential-authenticators-sqlite` | `security.credential_authenticators.sqlite` |
| `cryptographic-signing/rsapss` | `cryptographic-signing-rsapss` | `security.access_signers.rsapss` |
| `external-authorization/httpjson` | `external-authorization-httpjson` | `security.external_authorization.httpjson` |
| `idp.HTTPLoginProvider` (host Consul ticket implementation) | `identity-providers-consul` | `security.identity_providers.consul` |
| `identity-providers/sqlite` | `identity-providers-sqlite` | `security.identity_providers.sqlite` |
| `ids.IdentityStore` (host Consul implementation) | `identity-stores-consul` | `security.identity_stores.consul` |
| `identity-stores/sqlite` | `identity-stores-sqlite` | `security.identity_stores.sqlite` |
| `messaging/sqlite` | `messaging-sqlite` | `security.messaging.sqlite` |
| `oauth.LoginStore` (host Consul implementation) | `oauth-login-storage-consul` | `security.oauth_login_stores.consul` |
| `oauth-login-storage/sqlite` | `oauth-login-storage-sqlite` | `security.oauth_login_stores.sqlite` |
| `registration-workflows/sqlite` | `registration-workflows-sqlite` | `security.registration_workflows.sqlite` |
| Host `SecretsManager` (Consul snapshot implementation) | `secrets-consul` | `security.secrets.consul` |
| `secrets/sqlite` | `secrets-sqlite` | `security.secrets.sqlite` |
| `tokenrefresh.ManagedStore` (host Consul implementation) | `session-and-refresh-storage-consul` | `security.refresh_stores.consul` |
| `session-and-refresh-storage/sqlite` | `session-and-refresh-storage-sqlite` | `security.refresh_stores.sqlite` |

`pkg/plugin` owns the public category contracts and OAuth storage metadata, with
one Go file per category (for example `claims_enrichment.go`,
`identity_stores.go` and `oauth_login_storage.go`). Keep related factories,
runtime interfaces and metadata validation together in their category file;
`doc.go` contains only the package description.
Companions depend on those contracts, AuthCrunch and shared lexical helpers in
`internal/caddyfileutil`; they do not import the parent `security` package.
Keep lifecycle, root assembly, route integration, worker management and
cross-backend storage admission in the app. Delegate backend grammar to the
existing public AuthCrunch parser packages. The host-owned Consul OAuth backend
uses its own small parser because AuthCrunch supplies the runtime interface
rather than a Consul backend/parser. It borrows the configured
`pteich/caddy-tlsconsul` client and uses conditional Consul transactions; generic
CertMagic locking does not establish OAuth single-use semantics. The global
client remains owned by Caddy when the app retires a transaction handle.

The original root adapter filenames retain type aliases and import the companion
packages. Root factory interfaces alias `pkg/plugin` as well, preserving method
signatures for existing consumers. Importing the root still bundles the
companions listed above in the normal `cmd/authcrunch` build; existing Caddyfiles,
JSON selectors and module IDs retain their meanings. Importing a companion alone
registers its backend module without registering the parent app. Do not add a
second registration hook to an alias file or make companions depend on the root.

Host admission inspects detached `BackendConfig` snapshots and immutable
`Factory.SQLiteConfig`/`Factory.SigningConfig` snapshots. These expose declarative
opening paths for existing alias checks; they never transfer a runtime handle or
permit mutation of prepared configuration. The SQLite secrets module uses a
pointer `CaddyModule` receiver to avoid copying its runtime mutex.

`plugins/consumer_test.go` loads every companion through Caddy without importing
the parent app. It checks typed contracts, strict native decoding, unchanged
configuration, secret resolution and the absence of premature storage creation.
Each companion also owns category-local external-package parser, factory,
failure and real-backend tests. Its `caddyfile_adapt_test.go` explicitly imports
the app for full Caddy adaptation of its dedicated `testdata/` fixtures; this
test-only dependency does not change production package boundaries or the
standalone loading inventory. Keep private state tests beside their own
category. Root dispatch/adaptation, alias, storage-preflight, lifecycle and
TLS/browser E2E tests remain with the app. Run both surfaces when changing a
companion; directory registration alone does not prove consumer integration.
The [test inventory](../../testing-and-ci/references/test-surfaces.md#bundled-companion-packages)
maps local cases to assembled consumers and explains package coverage.

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

Credential, identity, messaging, registration, signing and selected-storage
backends are constructed before the root, followed by claims and external
backends after root construction. A
registration workflow borrows its selected account and notification handles.
If a later factory
or attachment fails, close the root, then all acquired backends in reverse
order across all categories. The HTTP JSON wrapper implements `io.Closer`
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

Qualify setup failures with dependencies supplied to one private invocation,
including errors after successful reads and acquisition. Do not replace global
constructors, encoders or file operations: one candidate's fault must not alter
another binding or an already serving runtime. Keep public factories and typed
category contracts unchanged, and assert disposal plus withheld publication.

For claims enrichment, the app constructs its root, obtains each named
gatekeeper, creates the backend and `enrichment.Enricher`, and calls
`SetClaimsEnricher`. Only after every
attachment succeeds does it publish the server for request admission. Failure
closes the private root before all acquired backends, in reverse order, without
touching the active configuration. A later Caddy provisioning/validation/start
failure reaches the same app cleanup path. Runtime objects never enter JSON.

For a persistent root, `Provision` prepares factories and validates bindings;
`Start` constructs the root and backends. Validation must not open persistent
runtime storage. Backend checks requiring construction happen at `Start` in
that mode. Preserve the existing rejection of overlapping persistent reloads.

At retirement, the app closes admission, waits for admitted calls, stops and joins
delivery workers, closes the root, and then closes backends. Root Close owns built-in components only.
Module cleanup order and HTTP grace-period expiry do not replace request drain.
The [runtime lifecycle contract](runtime-lifecycle.md) owns errors, reservations
and concurrent cleanup. Future category adapters must preserve these invariants
and define any worker shutdown ordering before sharing this resource mechanism.

## OAuth pending-login factories

`OAuthLoginStoreBackendModule.PrepareOAuthLoginStore` returns an immutable
`OAuthLoginStoreFactory`. Its `OAuthLoginStoreConfig` returns copied name, driver
and config-hash metadata; `NewOAuthLoginStore` consumes the frozen prepared
configuration. It must not reread mutable exported module fields at deferred
Start. The bundled SQLite factory normalizes public defaults and duration spelling.
Its descriptor hash establishes host factory agreement, not the provider namespace.

The returned `OAuthLoginStore` embeds the public transaction interface and
attests the same metadata plus initialized/not-closed readiness through
`OAuthLoginStoreConfig`. The host contains metadata panics, including invalid
typed nils, and collects optional closers before inspecting a constructor error.
Do not probe readiness by creating a sentinel login or wrap transaction errors
with retries. The runtime delegates operations unchanged. A custom companion
owns truthful metadata, storage separation and the public transactional contract.

Reference preflight runs even without any backend declaration, for every retained
OAuth provider. The new selector check is pure: full OAuth validation can read
pinned JWKS files and remains with existing provider validation. Reject malformed
native selector bytes before JSON encoding can repair them. Runtime handles do
not enter Params or JSON; each root receives a fresh map of exact instances.

SQLite storage may share a canonical file only with matching capacity. Known
cross-category database/sidecar aliases and managed-directory containment fail
before factories, including candidate/active comparisons in both directions.
Keep the immutable opening path alongside physical ownership; re-resolve opening
paths before deferred construction while retaining the old app's physical graph
through drain. No raw database open is needed for these checks. External path
replacement after admission remains outside the guarantee.
See [shared login storage](../../configuration-oauth-providers/references/shared-login-storage.md).

## Managed refresh factories

`RefreshStoreBackendModule.PrepareRefreshStore` returns an immutable
`RefreshStoreFactory`; copied `ExternalStoreConfig` metadata comes from
`RefreshStoreConfig`, and `NewRefreshStore` returns the exact public
`tokenrefresh.ManagedStore`. The bundled SQLite factory delegates pure parsing
and normalization, including equivalent timeout spelling, without opening the
database. Runtime module fields are never reread at deferred Start. Reject
invalid native selector bytes before JSON copying and raw module bytes before
module decoding; retain original declarations for round trips.

Derive root descriptors from prepared modules, never accept caller-supplied
native root descriptors as substitutes for module preparation. Validate selected
names and equal session/rotation limits before acquisition. Selected portals
require enabled refresh and root state. An unused declaration is still prepared
and constructed, so its storage belongs in preflight too. Empty selection keeps
the existing owned memory store; an invalid selected backend must never trigger
that fallback.

The host collects an optional closer before inspecting a factory's error or
runtime metadata. Metadata/cleanup boundary failures are sanitized and narrowly
contained, including typed nils. The root then checks copied metadata and bounded
read-only readiness without a probe write. It activates an immutable namespace
and generation only after the complete normalized configuration and actual
loaded public trust enter durable epoch admission. Selected portals remain
pending until their single manager is ready. Root and portals borrow both the
backend and activated views, never close them, and never snapshot selected
families through the legacy memory-store persistence path.

Each backend operation must verify the view's generation in its transaction
before inspecting replay state, removing expired records or mutating families.
SQLite IDs, spent digests and capacity are file-wide. All users of the same file
must agree on both limits; namespace retirement reclaims only that namespace.
Startup across multiple stores is not a cross-database transaction: a completed
retirement remains committed if a later store fails. Discard the unpublished
root, close app-owned handles after root disposal, and recover through fresh
construction without restoring retired authority.

Storage admission inventories every actual portal/policy KMS file read, including
ordinary consumers without strict profiles. A candidate that removes refresh
storage can still read the active app's database as a key; compare both retained
physical graphs before any reader opens it. Keep opening paths for deferred
rechecks, include sidecars and physical aliases, and never open/close a raw
SQLite file to inspect it while another handle serves requests. Custom backends
remain responsible for truthful metadata and undeclared storage separation.
See [named refresh storage](../../configuration-authentication/references/refresh-storage.md)
for grammar, migration, limits and operator recovery.

## Public injection audit

Recheck these boundaries against the selected module before each adapter change.
An interface satisfied by a backend does not establish a usable root attachment.

| Category | Public consumer and host consequence |
| --- | --- |
| Claims enrichment | `Server.GetGatekeeperByName` → `Gatekeeper.SetClaimsEnricher`; supported before publication through this host boundary |
| External authorization | `Gatekeeper.SetExternalAuthorizer`; attached to the private root through the host binding and bundled HTTP JSON factory |
| Secrets | Host `SecretsManager` resolves values before root construction; separate adapter must preserve exact types and redact `GetConfig` metadata |
| Messaging | `messaging.Config.AddProvider` preserves runtime injections through validation, excludes them from JSON, and is consumed by registry `SetMessaging`; bind after config restoration and before validation/construction; SQLite delivery uses the app-owned bounded worker |
| OAuth login storage | `NewServerWithOptions` and `ServerOptions.OAuthLoginStores`; the host validates every retained provider reference, supplies fresh named handles on each construction and closes them only after consumers drain and the root closes |
| API-key authenticators | Validate `PolicyConfig`, then call its `AuthProxyConfig.AddAuthenticator` before `NewServer` on that same private graph. The root retains these runtime bindings and checks `HasAuthProxies`. Waiting to call `Gatekeeper.AddAuthenticators` after root construction fails for an injected-only realm |
| Identity stores | Derive `Config.ExternalIdentityStores` through `ids.NewExternalIdentityStoreConfig` before validation and supply `ServerOptions.IdentityStores` before root construction. Exact names/kinds/realms, configured handles and persistence digests are validated; injected handles remain caller-owned. See [SQLite identities](../../configuration-identity-stores/references/sqlite-integration.md) |
| Ticket identity providers | Derive `Config.ExternalIdentityProviders` and supply `ServerOptions.IdentityProviders`. Root checks exact configured metadata and borrows the same dynamic instance, including its attachment interface; it never reconfigures or closes caller-owned providers |
| Registration workflows | Derive `Config.ExternalUserRegistries` before validation and supply `ServerOptions.UserRegistries` at construction. Root validates exact metadata/readiness and attaches only selected names; providers remain caller-owned. SQLite factories receive the already-open selected account/outbox handles |
| PS256 access signing | Derive `Config.ExternalAccessSigners` and supply `ServerOptions.AccessSigners`; `PortalConfig.AccessSigner` selects one borrowed handle with a matching strict profile. App factories freeze normalized configuration; root validates metadata and public-key equality before publication. OP ID signing is separate |
| Refresh storage | Derive `Config.ExternalRefreshStores` and supply `ServerOptions.RefreshStores`; selected portals receive prepared `PortalParameters.RefreshStore` bindings. Root state activates immutable generation views after complete configuration admission. Omission preserves the owned memory store; selected stores/views stay caller-owned |

The [refresh storage contract](../../configuration-authentication/references/refresh-storage.md)
owns the selected portal integration and its acceptance requirements. A
standalone engine interface alone does not establish another host consumer.

For API-key adapters, parse/validate the complete policy first, keep its raw
declarations intact, then bind into the resulting runtime proxy config before
constructing the root. Check backend name and realm explicitly, reject collisions
with root-owned portal names and existing bindings, and check all proxies before
publication. Runtime bindings disappear on JSON serialization: restore them on
each new graph after decoding. The backend remains caller-owned on constructor
failure and root Close. Add regression coverage for this ordering; do not assume
reparsing raw declarations preserves an injected handle. The bundled SQLite
adapter uses `CredentialAuthenticatorBackendModule`: `CredentialIdentity` supplies
the exact name/realm and `NewCredentialAuthenticator` transfers a distinct
context-aware, fresh, closable backend. The host verifies runtime identity and
freshness, and shares that handle only across matching policies in the same app.
The [SQLite API-key contract](../../configuration-authorization/references/sqlite-api-keys.md)
owns declarations, private issuance/revocation and operator recovery.

Do not remove auth-proxy declarations during construction and patch them afterward,
create placeholder portals, or replace root-owned authenticators. For remaining
provider gaps, do not reconstruct a parallel root.
Upstream work must define typed injection, duplicate-name handling, consumer
validation, caller ownership on constructor failure and disposal, and persistent
binding behavior. Keep unavailable backend selectors out of operator examples.

SQLite references require distinct private local POSIX database files and a
pure-Go production build. They do not imply network-filesystem support, encrypted
storage or multi-host availability. Schema migration is backend-specific; the
refresh backend validates and migrates only its recognized older layout. Keep
trusted issuance, enrollment and delivery-worker controls in their own adapters.

## Validation surfaces

`app_plugins_test.go` checks native binding validation, immutable JSON/config,
module type checks, constructor failure, reverse cleanup, error redaction,
concurrent drain and deferred persistent construction. `app_plugins_e2e_test.go`
uses a test-only module through actual Caddy TLS routes and reloads: repeated
authenticated requests, rejected candidates, validation-only cleanup, a blocked
lookup across replacement, and final stop. It verifies transport trust.

These tests establish the host factory/lifecycle seam. Static adapter coverage
lives in `plugins/claims-enrichment-static/consumer_test.go`, `caddyfile_authz_enrichment_test.go`
and `claims_enrichment_static_e2e_test.go`, plus adaptation fixtures. Each other
companion needs its own native/text round trips, real authentication/authorization
E2E, backend failures and resource assertions. `app_external_authorization_test.go`
checks the external binding and mixed-category cleanup; the HTTP JSON adapter's
unit and TLS E2E tests qualify its service transport and protected requests.
SQLite credential coverage lives in `plugins/credential-authenticators-sqlite/`,
`app_credential_authenticators_test.go`, `command_api_key_test.go` and
`credential_authenticator_sqlite_e2e_test.go`; its production TLS journey also
checks CLI revocation, storage failure, reload and restart.

## Messaging ownership

`MessagingProviderBackendModule` supplies a validated name and a fresh
`messaging.Provider`. Bind it into the app-private resolved messaging config
before constructing the root. Runtime handles are excluded from native JSON.
SQLite delivery is an explicit bundled capability, not an assumed method of
arbitrary providers. Its queue factory has no module-level Cleanup ownership.
The app starts workers only at Start, drains producers before cancellation,
joins every worker, disposes the root, then closes queues in reverse acquisition
order. See [messaging configuration](../../configuration-messaging/SKILL.md) for
lease budgets, persistence, transport limits and actual Caddy acceptance tests.

## Registration ownership

`RegistrationWorkflowBackendModule` returns a normalized descriptor and constructs
a fresh provider from only its selected identity and messaging dependencies.
Restore descriptors before root validation; restore handles after opening those
dependencies and before root construction. A descriptor supplied directly in
native root config is rejected because the host must derive it from its module.
Module validation stays free of storage I/O. Runtime checks reject aliased SQLite
account/pending/outbox files before acquisition without reserving them as exclusive
local-file stores. The root never activates, rebinds or closes an injected registry.
See [SQLite enrollment](../../configuration-registrations/references/sqlite-workflows.md)
for explicit selection, policy, deployed origin/mount responsibility and recovery.

## Access-signer ownership

`AccessSignerBackendModule.PrepareAccessSigner` freezes normalized configuration
without reading key material. Its `AccessSignerFactory` returns a detached core
descriptor and constructs a fresh app-owned runtime on each call. Keep module
validation and cleanup independent of those handles. Collect an optional closer
before inspecting a constructor error, and close all acquired handles in reverse
order after root disposal or construction failure. Core validates declaration
metadata, captures immutable public-key evidence, and borrows the exact signer.
Contain only metadata/preparation/accessor and cleanup panics; never recover
around signing or root construction.

The bundled RSA-PSS factory's private-key path and every explicit selected
portal/policy KMS key read enter the common storage inventory before any backend
opens. Check physical paths, existing-file identities and SQLite sidecars, then
recollect environment/directory-derived key reads during deferred startup before
opening the candidate. Preserve each active runtime's original opening and
physical paths. This preflight checks aliases; it does not make arbitrary
filesystem or environment mutations safe during construction. See
[access signing](../../configuration-crypto/references/access-signing.md) for the
consumer, verification and rotation contracts.

## External identity-provider ownership

`IdentityProviderBackendModule` derives a normalized descriptor and returns a
fresh configured `idp.IdentityProvider`. Keep original module JSON unchanged,
reject native root descriptors, and restore runtime maps on each construction.
The root checks exact map keys and name/kind/driver/realm metadata before resource
acquisition. A borrowed attachment consumer must return a nonnil attachment;
by default an explicitly named store must already be caller-bound. Unnamed
lazy memory attachments are not initialized by this check. Preserve dynamic optional interfaces,
especially HTTP login and identity attachment; a wrapper that loses the provider's attachment cannot
validate its proof through a newly created fallback.

The bundled SQLite ticket module alone opts into
`ServerOptions.IdentityProviderAttachmentStores` when its copied typed attachment
has a nonempty target. Prepare the exact target name on the immutable app snapshot;
require one configured built-in local declaration before factories run and pass
a fresh provider-name → store-name map on construction. The root captures the
original attachment once under sanitized preflight, requires it to be fresh and
unbound, then binds its actual root-owned local store after epoch setup. Do not
reconstruct providers, root stores or attachment objects; do not opt in arbitrary
third-party consumers based on interface satisfaction. Empty native attachments
normalize to omission only in detached ticket descriptor/runtime configuration.

The root finishes owned attachment setup once, then tells portals that assembly
is complete. Already-ready borrowed providers retain their caller wiring and
private state. Standalone portal callers retain the default attachment setup
unless they explicitly declare it complete. The host never duplicates the root
or configures a second identity attachment for a ticket backend. A failure after
explicit binding may leave that borrowed candidate bound to a retired root store:
discard and close it, then construct a fresh instance. There is no unbind/reuse
rollback contract. The root still never closes borrowed providers.

Read-only host checks compare ticket database and sidecar paths with known
bundled backend and local/dropbox files before live factories run. SQLite secret
snapshots were already read and closed during configuration resolution. Compatible
ticket handles may share one canonical file, without exclusive local-snapshot
reservations; different hardlink names and cross-category aliases are rejected.
See [ticket configuration](../../configuration-ticket-providers/SKILL.md) for
trusted issuance, private identity lifetime, browser cookies and recovery.

## Consul identity, ticket and refresh companions

The host-owned Consul companions implement the public typed backend contracts
using `internal/consulstate`. One encrypted bounded document per category/name
atomically owns each backend's records. Factories retain a borrowed Caddy client;
logical cleanup never closes it. Read
[Consul companions](../../configuration-state/references/consul-companions.md)
before changing config defaults, schema, optimistic identity fences, replay
history, generation retirement or deployment guarantees. Root state and local
attachment ownership remain core concerns; do not implement a parallel portal
session manager or bypass persistent refresh generation admission.

## Consul credential and secrets companions

`credential-authenticators-consul` implements fresh realm-bound API-key lookup
through the existing app factory contract. `secrets-consul` snapshots one record
during provisioning through the common secrets manager contract. Both reuse
`internal/consulstate` and the configured Caddy Consul client; trusted public Go
constructors supply issuance/revocation and secret mutation without public HTTP
or CLI endpoints. Logical handles never own the global client. Read the
[Consul API-key contract](../../configuration-authorization/references/consul-api-keys.md)
and [Consul secrets contract](../../configuration-secrets/references/consul.md)
before changing record identity, fresh lookup, snapshot/reload semantics or
uncertain-write behavior. Secret module receivers must remain pointers because
of their snapshot mutex; never copy their runtime state into native config.
