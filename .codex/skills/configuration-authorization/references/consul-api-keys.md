# Consul API-key authentication

Use `security.credential_authenticators.consul` for fresh, realm-bound API keys
shared by Caddy replicas. It borrows the ready client, prefix and AES key from
Caddy's configured `github.com/pteich/caddy-tlsconsul` storage module. Other
Consul storage implementations fail provisioning. No second connection settings
or plaintext API keys belong in the backend declaration.

## Configuration

Inside the global `security` block:

```caddyfile
credential authenticator consul keys {
    realm staff
    prefix security/credentials
    timeout 3s
    capacity 1000
}
authorization policy api {
    crypto key verify {env.JWT_SHARED_KEY}
    with api key auth portal keys realm staff
    allow roles viewer
    disable auth redirect
    enable strip token
}
```

This is a fragment. The surrounding global options must configure `storage
consul`; use that module's existing address, ACL/TLS settings and a private
`aes_key` shared by peers. Mount `authorize with api` on the protected route.
Configure the mandatory `request>headers>X-Api-Key delete` filters on both the
global diagnostic and site access log encoders, as shown in
[the API-key request contract](sqlite-api-keys.md#request-behavior).
Include every custom key header in both filters. Stripping a credential before
downstream handling does not redact Caddy's original request copy in logs.

The header supplies the exact backend name. `realm` is required once. Optional
`prefix`, `timeout` and `capacity` occur once with one literal value. Defaults
are `security/credentials`, `3s` and 1000. Timeout is 1ms..30s, capacity 1..10000;
text zero is rejected, native omitted/zero capacity uses the default. Backend
values remain literal apart from Caddy's lexical `{$ENV}` substitution.

Native app JSON uses `credential_authenticators` entries:

```json
{"driver":"consul","name":"keys","realm":"staff","prefix":"security/credentials","timeout":"3s","capacity":1000}
```

The existing policy-binding rules apply: unique non-URL names distinct from
portals, one exact realm, at least one matching policy, and API-key-only bindings.
Basic/mixed bindings and unused factories fail before runtime publication.
Each app receives a fresh logical handle shared by its matching policies; it is
closed after admitted requests drain. Module cleanup never closes app handles.

## Trusted provisioning and request semantics

Use the public Go constructor from `plugins/credential-authenticators-consul`:
`New(ctx, config, storage)`, where config is `*ConsulCredentialAuthenticator` and
storage is the borrowed `*storageconsul.ConsulStorage`.
The returned `Authenticator` exposes `Issue(ctx, subject, email, roles, expires)`
and `Revoke(ctx, key)`. Call these only through trusted administration. There is
no Consul issuance HTTP endpoint or built-in CLI; existing `security api-key`
commands remain SQLite-specific.

Issue generates a 256-bit, 43-character unpadded base64url credential and returns
it only after a confirmed commit. It stores only its SHA-256 digest, with subject,
email, roles and expiry encrypted in Consul. Subjects are bounded to 256 bytes,
bare emails to 320 and roles to 1..32 entries of at most 128 bytes each. Expiry
must be strictly in the future and at most 30 days away. Deliver the result
privately to the intended client; never publish an error result as a credential.

Clients send `X-Api-Key` and the exact `X-Auth-Realm` over trusted TLS. Existing
custom header options and ACLs retain their behavior. Successful claims include
subject, email, roles, realm origin and `amr: ["api_key"]`; claim lifetime is at
most one minute and never exceeds credential expiry. Basic auth always rejects.
Every lookup reads consistent Consul state and fences its result against a
concurrent mutation. Result caching is disabled. Revocation therefore affects
the next lookup on every compatible peer without reload; already admitted
requests retain their result. Wrong realms, unknown/expired/revoked keys and
backend outages deny without reusing a previous successful response.

## Storage and failure boundaries

One encrypted versioned document per backend name stores the realm and entry
limit. All peers need the same name, prefix, realm, capacity, AES key and Consul
KV domain. Documents also have a 384 KiB plaintext ceiling; the byte limit can
be reached before the entry count. Issuance prunes expired entries. Changing a
persisted realm or capacity requires a drained migration or a fresh prefix/name.

The shared `internal/consulstate` helper supplies AES-GCM, category/name isolation,
consistent reads and conditional transactions. Only definite CAS conflicts retry,
at most eight times within the operation deadline. A lost response after commit
returns unavailable and no new credential; it never automatically reissues.
An unreturned committed key may remain until expiry. Reconcile uncertain writes
through trusted administration before retrying; an error does not prove rollback.
Logical Close retains shared records and Caddy's client. This backend distributes
API-key authority; it does not create portal sessions or replace other state stores.

`TestConsulCredentialAuthenticator` and `TestConsulCredentialUncertainWrites`
cover parsing, frozen factories, independent clients, fresh revocation, expiry,
capacity races, malformed input, cancellation and committed-response loss.
`TestCaddyConsulCredentialsSecretsE2E/fresh_credentials_across_replicas` uses the
production command, verified TLS, two Caddy processes and real Consul. It checks
ACLs, custom header stripping, backend outage/recovery, rejected reload survival,
revocation without reload, restart and credential-free config/log output.
