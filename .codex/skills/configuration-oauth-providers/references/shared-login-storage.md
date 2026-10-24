# Shared pending OAuth login storage

Use this for upstream OAuth login callbacks that may reach another local Caddy
process. The app supplies named public `oauth.LoginStore` handles through
`ServerOptions.OAuthLoginStores`; providers retain ownership of authentication,
PKCE, nonce, browser binding, exact callback and destination validation.

## Declaration and selection

```caddyfile
security {
	oauth login store sqlite shared {
		path /private/auth/oauth-logins.db
		timeout 1s
		capacity 10000
	}

	oauth identity provider upstream {
		realm upstream
		driver generic
		client_id {env.OAUTH_CLIENT_ID}
		client_secret {env.OAUTH_CLIENT_SECRET}
		base_auth_url https://issuer.example.test
		login store shared namespace deployment-a
	}
}
```

This is a fragment; configure the provider's actual issuer/discovery trust and
portal routes under the [shared parser contract](shared-parser.md). Header form
is exactly `oauth login store DRIVER NAME`. The SQLite flat block requires
`path VALUE` and accepts optional `timeout VALUE` and `capacity COUNT`, each once.
The complete encoded body delegates to the public SQLite parser. Empty/unknown
settings, nested blocks, duplicate fields and surplus arguments fail adaptation.
Names are exact, nonempty identifiers; duplicate backend names fail provisioning.

The native app field is `apps.security.oauth_login_stores`, an array of entries:

```json
{"driver":"sqlite","name":"shared","path":"/private/auth/oauth-logins.db","timeout":"1s","capacity":10000}
```

The provider retains its existing `params.login_store` object with `name` and
`namespace`. Omission selects private memory. Present null, empty, partial,
unknown or malformed references fail; no fallback replaces an explicit selection.
Preflight inspects every retained OAuth provider, including an unselected one,
before any backend factory. A Caddyfile `disabled` declaration is omitted by its
existing parser. Declared unused backends are still validated and constructed.

Backend fields are literal, apart from Caddy's lexical `{$ENV}` expansion.
Provider selector arguments support their existing runtime replacements and
secret lookups. Resolve them once, preserve exact values, and reject invalid
UTF-8 before JSON encoding can repair it. Do not rewrite a supplied namespace.

## Namespace and lifecycle

The provider derives the effective namespace from the configured deployment
namespace and its complete normalized configuration. Peers need identical
provider names, credentials, trust/compatibility settings, attachment selection
and configured path/array values. Equivalent key bytes at different configured
paths may still isolate transactions. Discovery does not replace this binding.
The host does not derive, expose or shorten the provider's namespace digest.

Each app construction owns a fresh client. Pure adaptation/preparation opens no
database; persistent apps defer factories to `Start`. Factories capture immutable
normalized configuration rather than rereading exported module fields. Runtime
metadata must match the prepared binding and attest readiness before publication.
Failure unwinds partial handles; retirement drains requests, closes the root,
then closes borrowed clients once in reverse acquisition order. Closing one
client does not purge shared pending work or close another client's connection.

Pending evidence survives closing/reopening clients only until its own deadline;
offline time counts. Wrong browser/callback bindings do not consume a legitimate
transaction. Claim is atomic, and successful completion is single-use. An
acknowledged cancellation can remove claimed work, preventing final credential
issuance. Backend errors do not confirm a transaction outcome: do not retry an
uncertain operation automatically or publish tentative results. Start a fresh
login when the previous attempt cannot safely complete.

## SQLite deployment boundaries

Use a dedicated private absolute database path under an existing private parent
directory on a local POSIX filesystem. The database holds private nonce, PKCE and
destination evidence in plaintext; protect it and backups. Timeout defaults to
1s and accepts 1ms through 30s. Capacity defaults to 10000, accepts 1 through
100000, and applies to the whole database across all namespaces. All clients of
one file must agree. Capacity refusal preserves existing pending transactions;
completion or expiry restores room. Namespaces do not reserve separate quotas.

The same canonical file can be shared by independent clients with matching
capacity, including old/candidate apps. Distinct hardlink names are rejected
because their SQLite journal names differ. Known identity, ticket, messaging,
registration, API-key, secrets, Documents, local-account and dropbox files cannot
alias this database or its `-journal`, `-wal` or `-shm` sidecars. The database must
also be outside managed root-state and OAuth-registration directories. These
checks apply with no ticket/Documents consumer and across candidate/active
configurations in both directions. Custom companion modules own their storage
separation contract.

The app retains immutable opening paths and resolved physical ownership. Before
constructors it re-resolves the opening paths, catching ancestor symlink changes
that introduce a known collision. It retains an active app's physical inventory
through drain. Checks use filesystem metadata, not raw database opens. Keep
storage paths stable while serving; this is not protection against arbitrary
external filesystem replacement after admission or discovery of unknown files.

This backend distributes only upstream pending-login evidence. Completed portal
sessions, refresh families, OP sessions and profile caches have separate owners.
Implicit attached-account IDs remain private to each runtime. Stateless JWT
authorization on both peers additionally needs compatible signing/verification
keys and policy. Direct-policy OAuth has an independent local pending map; this
adapter does not distribute that map. Root-state exclusive ownership and its
overlapping-reload restriction remain unchanged. SQLite is not multi-host portal
availability or network-filesystem support.

## Validation owners

The [test surfaces](../../testing-and-ci/references/test-surfaces.md#shared-upstream-oauth-transactions)
map module/parser/reference, storage/lifecycle and real two-process Caddy tests.
The real-process fixture verifies both TLS hops, nested/root portal mounts,
independent JWT verification and peer authorization, wrong/duplicate callbacks,
single-use concurrency, graceful close/restart, failed candidates, isolation,
capacity and cancellation. Public backend/root tests own detailed expiry,
record-growth, context and transaction-error matrices. Neither lower-level tests
nor a host callback alone establish full portal high availability.
