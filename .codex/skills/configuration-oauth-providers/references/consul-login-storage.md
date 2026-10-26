# Pending OAuth transactions in Caddy's Consul storage

The optional `security.oauth_login_stores.consul` module borrows the client from
Caddy's configured `github.com/pteich/caddy-tlsconsul` storage module. It supports
an upstream OAuth/OIDC login starting on one Caddy host and its callback reaching
another host. AuthCrunch retains nonce, PKCE, browser/callback binding and
identity validation; the adapter supplies shared, single-use pending evidence.

## Configuration

Inside the global options block:

```caddyfile
{
    storage consul {
        address "127.0.0.1:8500"
        prefix "caddy"
    }
    security {
        oauth login store consul shared {
            prefix security/oauth-logins
            timeout 3s
            capacity 1000
        }
        oauth identity provider keycloak {
            driver generic
            realm keycloak
            client_id {env.OAUTH_CLIENT_ID}
            client_secret {env.OAUTH_CLIENT_SECRET}
            base_auth_url https://keycloak.example.com/realms/example
            metadata_url https://keycloak.example.com/realms/example/.well-known/openid-configuration
            scopes openid email profile
            login store shared namespace production
        }
        authentication portal myportal {
            enable identity provider keycloak
        }
    }
}
```

Add the site's normal `authenticate with myportal` route. Existing global
Consul address, ACL token, TLS and encryption settings are reused; there is no
second Consul connection configuration. Build with explicit `--with` selections
for `github.com/greenpau/caddy-security` and
`github.com/greenpau/caddy-security/plugins/oauth-login-storage-consul`, plus
`github.com/pteich/caddy-tlsconsul`. The root and regular local command include
no companions by default. Other modules registering the same `caddy.storage.consul` ID
cannot be linked alongside it.

A bare `oauth login store consul shared` declaration or an empty block uses the
defaults. In a nonempty block, each setting occurs once:

| Setting | Meaning and bounds | Default |
| --- | --- | --- |
| `prefix` | Relative canonical key prefix, up to 512 UTF-8 bytes; no traversal, backslashes or control characters | `security/oauth-logins` |
| `timeout` | Deadline for one complete store operation, 1ms through 30s, additionally bounded by the request context | `3s` |
| `capacity` | Pending and claimed transactions across this backend name's provider namespaces, 1 through 1000 | `1000` |

Backend fields are literal apart from Caddy's lexical `{$ENV}` expansion. Provider
store/namespace selectors retain their existing runtime resolution. The native
app entry is:

```json
{"driver":"consul","name":"shared","prefix":"security/oauth-logins","timeout":"3s","capacity":1000}
```

The effective key prefix combines Caddy's configured Consul prefix, the adapter
prefix and a hash of the backend name. Transaction keys hash the complete
AuthCrunch namespace and state. All participating replicas need the same store
name, key prefix, capacity and storage encryption key, the same Consul KV domain,
and matching normalized provider/trust configuration. AuthCrunch adds its
configuration digest to the deployment namespace; the adapter preserves it.
Compatible JWT verification keys and resource policy are also required.

## Atomicity, confidentiality and lifecycle

The adapter uses Consul conditional transactions and consistent reads directly,
without CertMagic locks. Admission and removal update an encrypted, bounded
capacity index in the same transaction as the record. Claim conditionally writes
the record's exact Consul modification index. Only one competing callback can
win; cancellation of a claimed transaction prevents completion.

Records and the capacity index use AES-GCM with the configured storage AES key,
fresh nonces and the complete Consul key as authenticated data. Protect that key,
Consul access and transport as authentication infrastructure. The configured ACL
token needs read/write access to this subtree. OAuth evidence uses
its own format and subtree, independently of the TLS storage record format.
No raw Consul error, OAuth proof or encryption key is returned in diagnostics.

Every operation checks transaction expiry. Host clocks must be synchronized;
Consul KV does not supply an application-level expiry predicate. Claim and
completion also recheck expiry after a successful write before publishing
success. Expired records release capacity opportunistically during admission;
cleanup is bounded within Consul's 64-operation transaction limit. Capacity is
an entry bound, and the index is limited to 1000 entries to bound payloads.

Only definite conditional conflicts can be retried, at most eight attempts
within the operation deadline. A transport error or uncertain write stops the
operation without tentative credentials or an automatic retry. Start a fresh
login after an unavailable exchange. Backend errors map to the existing upstream
unavailable response; capacity uses the existing authorization-state-limit path.

Factories capture the configured client, encryption material and normalized
configuration. They check index compatibility before publishing a handle. App
cleanup drains consumers and closes the logical handle; it never closes the
Caddy-owned client or purges pending work. Compatible peers/reloads can continue
pending transactions until their original expiry. Changing capacity or the
storage encryption key requires a drained migration or a fresh adapter prefix;
existing index formats/capacity must agree even when no live records remain.
Do not delete or restore this subtree while transactions may still be consumed.

## Deployment boundary and validation

Selecting global `storage consul` alone does not opt providers into this store.
Omitted provider selections retain private memory. Unsupported global storage
fails provisioning rather than falling back to memory. This companion requires
the configured `pteich/caddy-tlsconsul` implementation and a ready Consul client.

This distributes pending upstream OAuth transactions only. Completed portal
sessions, MFA/sandbox checkpoints, refresh families, downstream OP sessions and
direct-policy session maps retain their separate owners. Default attached
account identities remain private to each runtime. Keep affinity for operations
that require those identities/state, or implement the corresponding distributed
AuthCrunch capabilities before advertising full portal availability.

Focused validation commands:

```sh
make test TEST='^TestConsulOAuth|^TestCaddyfileAdapt' TEST_DIR='./plugins/oauth-login-storage-consul' COVERAGE_DIR='.coverage/consul-oauth-unit'
CADDY_SECURITY_TEST_CONSUL_BINARY=/absolute/path/to/consul make test TEST='^TestCaddyConsulOAuthLoginStoreE2E' TEST_DIR='.' COVERAGE_DIR='.coverage/consul-oauth-e2e'
```

The E2E parent starts disposable Consul development agents and two actual Caddy
processes with verified TLS. It exercises callback direction, concurrent replay,
peer restart, failed reload, namespace/provider isolation and capacity. Without
an explicit binary or `consul` on PATH, that external-service test skips; do not
report a skip as deployment acceptance. Unit tests cover cancellation, expiry,
capacity, tampering, read failures and ambiguous committed writes. Multi-host
routing and Consul cluster failover require separate deployment acceptance.
