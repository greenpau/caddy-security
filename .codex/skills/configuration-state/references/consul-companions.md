# Consul identity, ticket and refresh companions

Read this when selecting shared Consul account, ticket or refresh storage. The
companions reuse the ready client, prefix and AES key from the configured
`github.com/pteich/caddy-tlsconsul` global storage module. Other Consul storage
implementations are rejected. They create no second connection configuration.

## Configuration

These declarations belong inside one global `security` block:

```caddyfile
identity store consul accounts {
    realm staff
}
identity provider consul tickets {
    realm application
    public_origin https://login.example.test
    issuer_url https://issuer.example.test/signin
}
token refresh store consul sessions
```

The global options must also select `storage consul`, with the deployment's
address, ACL/TLS configuration and a private `aes_key` shared by peers. Portal
consumers explicitly select `enable identity store accounts`, `enable identity
provider tickets` or `token refresh { store sessions ... }`. Merely selecting
Caddy storage does not replace any omitted backend selection.

| Declaration | Module ID | Required body settings | Optional body settings and defaults |
| --- | --- | --- | --- |
| `identity store consul NAME` | `security.identity_stores.consul` | `realm REALM` | `prefix security/identities`, `timeout 3s`, `capacity 1000` |
| `identity provider consul NAME` | `security.identity_providers.consul` | `realm REALM`, `public_origin HTTPS_ORIGIN`, `issuer_url HTTPS_ISSUER_PATH` | `prefix security/tickets`, `timeout 3s`, `capacity 1024`, `base_path /auth`, `cookie_name AUTHP_PROVIDER_SESSION_ID`, `attach to local identity store NAME` |
| `token refresh store consul NAME` | `security.refresh_stores.consul` | None | `prefix security/refresh`, `timeout 3s`, `max sessions 1000`, `max rotations 128` |

Settings occur once in a flat block. Backend values are literal apart from
Caddy's lexical `{$ENV}` substitution. Prefixes are canonical relative paths,
without traversal, controls or backslashes. Timeouts span 1ms through 30s;
capacities and refresh limits span 1 through 10000. Explicit zero text limits
fail; omitted/native zero limits receive defaults. An empty block and a bare
refresh declaration are equivalent. Identity declarations require their bodies.

Native app lists are `identity_stores`, `identity_providers` and `refresh_stores`,
with `driver: consul`, `name` and the snake_case versions of these fields.
Refresh portals must explicitly match `max sessions` and `max rotations` to the
selected backend; core portal defaults differ from these backend defaults.

## Account and ticket authority

The identity store provides password accounts with stable random user IDs and a
persisted backend epoch. Password changes, disable/enable and role mutations
advance credential versions. Current policy is read from Consul for refresh;
a concurrent account mutation invalidates a staged refresh result. The callback
runs once and its result may be published only after the final version fence
succeeds. No local MFA, API-key, recovery or challenge-rule backend is supplied.

Trusted Go administration uses `identity-stores-consul.New(ctx, config, storage)`
and the returned `Store.Create`, `SetPassword` and identity administration methods.
The supplied `storage` is the borrowed Caddy `*storageconsul.ConsulStorage`.
Create requires username, email, name, roles and a plaintext password of 8..72
bytes; bcrypt hashes stay encrypted in Consul. There is no default administrator
or Consul administration CLI. Protect trusted administration access separately.

The provider implements trusted-application tickets, not an external OAuth IdP.
Use `identity-providers-consul.New(ctx, config, storage)` and call `Provider.Issue`
only after independently authenticating and authorizing the application's user.
It installs no issuer endpoint. Browser requests last 300s; tickets last at most
120s and require the original Secure/HttpOnly/SameSite=Lax browser-binding cookie.
Origin, mount, issuer and cookie restrictions match the existing ticket protocol.
A wrong browser leaves the legitimate ticket usable; one successful callback
atomically consumes it. Peer restart retains pending requests and tickets.

## Transaction and storage guarantees

Each category/name owns one encrypted, versioned document under the global and
adapter prefixes. Categories and hashed names isolate documents even when
operators reuse an adapter prefix. Peers need identical configuration, capacity,
AES key and effective KV domain. Different semantics at the same key fail closed.

Consistent reads and conditional Consul transactions fence every operation. A
single compare-and-set commits all account changes, ticket consumption, or refresh
family/replay/generation changes. Encryption uses AES-GCM with fresh nonces and
the complete key as authenticated data. The payload uses a versioned Go gob
schema so server-only authentication fields excluded from JSON are retained.

Each complete plaintext document is capped at 384 KiB as well as its entry
limits. Capacity can therefore be reached before the configured entry count;
refresh rotation fails without discarding a live family's spent history. This
bounded document model serializes writes within a backend and is intended for
modest deployments. Provisioning and readiness do not create a sentinel record.

Only definite conditional conflicts retry, at most eight times within the
operation deadline. An uncertain/network write never retries automatically or
publishes tentative credentials. A spent refresh credential with the correct
binding atomically revokes its whole family, including usable descendants. Wrong
bindings leave other families untouched. Changed generations retire their
namespace's families before another view can operate. Host clocks must agree.

App cleanup drains callers and retires logical handles. It never closes Caddy's
client or deletes peer state. Storage deletion, rollback, encryption-key rotation,
capacity changes and schema migrations require a separately drained deployment
or a fresh prefix; there is no automatic adoption of incompatible data.

## Remaining upstream boundaries

These companions do not make the entire portal interchangeable between hosts.
In go-authcrunch v1.4.1:

- Managed refresh requires exclusive root `state`. Namespace and generation
  identities come from that root's private durable records. Independently running
  roots have different identities, even when they select the same Consul backend.
  Consul refresh supports durable storage and same-root restart; cross-root
  refresh needs an upstream distributed epoch/namespace and ownership contract.
- Portal session/sandbox checkpoints, cross-device state, downstream OP grants
  and direct-policy sessions have separate owners without a selected Consul
  backend here. Keep affinity for flows requiring those states.
- Explicit provider account attachments accept root-owned local identity stores.
  They cannot select this external Consul password store. Omission still creates
  provider-private memory; sharing tickets does not share attached identities.
  Generalizing attachment targets and local-factor authority requires upstream work.

The existing Consul OAuth login companion separately shares pending OAuth/OIDC
handshakes. Its deployment namespace is independent of managed refresh epochs.
Never remove root state requirements or synthesize deterministic refresh epochs
in the Caddy adapter to bypass these core guarantees.

## Focused validation

`TestConsulIdentityStore`, `TestConsulTicketProvider`, `TestConsulRefreshStore`
and `TestConsulStateTransactions` exercise real disposable Consul clients,
concurrency, credential changes, replay, generation fencing, cancellation,
encryption tampering, payload limits and a lost response after a committed write.
`TestCaddyConsulCompanionsE2E` exercises the assembled Caddy command, TLS routes,
password login, protected access, refresh restart/replay and ticket callbacks
on a peer process. Each companion owns adaptation fixtures; the root fixture is
`testcase_consul_companions`. Missing Consul skips external-service cases; a skip
is not deployment acceptance. Multi-host routing and Consul cluster failover
remain deployment checks.
