---
name: configuration-crypto
description: "Configure portal/policy JWT keys, token names and lifetimes, key loading and generation, public-key discovery, and System API encryption keys. Use for signing/verification compatibility and rotation."
---

# Configuration Crypto

## Purpose

Use this skill for `crypto` directives inside
`authentication portal <name>` and `authorization policy <name>` blocks.
Surrounding declarations belong to
[configuration-authentication](../configuration-authentication/SKILL.md) and
[configuration-authorization](../configuration-authorization/SKILL.md).
[runtime resolution](../configuration-runtime-resolution/SKILL.md) and
[secrets](../configuration-secrets/SKILL.md) own replacement semantics and manager
configuration; this skill owns how the resulting key material is used.

Read these files when details matter:

- `caddyfile_authn_crypto.go` and `caddyfile_authz_crypto.go` for the thin
  Caddyfile parser wrappers.
- `caddyfile_resolve.go` for env, file, and secrets substitution in raw crypto
  lines before authcrunch validation.
- `../go-authcrunch/pkg/kms/` for the real crypto
  grammar, key loading, defaults, signing, verification, and System API keys.
- `../go-authcrunch/pkg/authn/config.go` and
  `portal.go` for portal key-store construction, token signing, and the portal
  validator.
- `../go-authcrunch/pkg/authz/config.go`,
  `gatekeeper.go`, and `pkg/authz/validator/` for policy key-store
  construction, token discovery, and verification.
- `../go-authcrunch/pkg/authproxy/` and
  `pkg/system/` for remote Basic/API-key auth encrypted with `system` keys.

## Mental Model

The caddy-security parser only checks that a `crypto` line has at least three
arguments and begins with `key` or `default`. It then stores the full line as
raw encoded authcrunch KMS config. The deeper syntax is validated later by
`go-authcrunch/pkg/kms`.

During provisioning, caddy-security resolves placeholders and secrets inside
raw crypto lines, overwrites the raw entries, and calls authcrunch `Validate`.
That builds `CryptoKeyStoreConfig`; runtime then builds a `CryptoKeyStore` from
that config.

If no explicit `crypto key ...` lines exist, authcrunch auto-generates an ES512
`sign-verify` key by default; other algorithms are described below. This is
volatile by default. Explicit keys provide stable material across independent
instances; optional [persistent state](../configuration-state/SKILL.md) can retain
generated material across an exclusive owner's stop/start. Key persistence alone
does not share session state or authorize concurrent owners.

## Common Pairing

For a portal that issues JWTs and a policy that verifies them, configure the
portal with sign-capable material and the policy with matching verify-capable
material:

```caddyfile
{
	security {
		authentication portal myportal {
			crypto default token lifetime 3600
			crypto key sign-verify {env.JWT_SHARED_KEY}
			enable identity store localdb
		}

		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url /auth
			allow roles authp/admin authp/user
		}
	}
}
```

Use `sign-verify` on the portal for HMAC/shared secrets or private keys. Use
`verify` on the policy when only verification is needed. Do not configure a
portal with only `verify` unless it never issues tokens; portal provisioning can
succeed, but login token signing will fail later.

## Supported Forms

These raw forms are accepted by the authcrunch KMS parser after caddy-security
stores and resolves them:

```caddyfile
crypto default token name <TOKEN_NAME>
crypto default token lifetime <SECONDS>
crypto default autogenerate tag <TAG>
crypto default autogenerate algorithm <ES512|EdDSA|Ed25519>

crypto key token name <TOKEN_NAME>
crypto key token lifetime <SECONDS>
crypto key <KID> token name <TOKEN_NAME>
crypto key <KID> token lifetime <SECONDS>

crypto key <verify|sign|sign-verify|auto> <SHARED_SECRET>
crypto key <KID> <verify|sign|sign-verify|auto> <SHARED_SECRET>

crypto key <verify|sign|sign-verify|auto> from env <ENV_VAR>
crypto key <KID> <verify|sign|sign-verify|auto> from env <ENV_VAR>
crypto key <verify|sign|sign-verify|auto> from env <ENV_VAR> as <key|file|directory>
crypto key <KID> <verify|sign|sign-verify|auto> from env <ENV_VAR> as <key|file|directory>

crypto key <verify|sign|sign-verify|auto> from file <PATH>
crypto key <KID> <verify|sign|sign-verify|auto> from file <PATH>
crypto key <verify|sign|sign-verify|auto> from directory <PATH>
crypto key <KID> <verify|sign|sign-verify|auto> from directory <PATH>

crypto key <KID> system <HEX_32_BYTE_KEY>
```

Prefer explicit `sign-verify` or `verify` over `auto` in new examples. Current
KMS accepts `auto`; for shared secrets and private keys it behaves like both
signing and verification, while public-key files can only verify.

`crypto key token name ...` and `crypto key token lifetime ...` are
order-sensitive key attributes. Without `<KID>`, they target the default key
context. With multiple keys, prefer `crypto key <KID> token ...` so the intended
key is unambiguous.

## Defaults

The default key ID is `0`. A non-default key ID is injected into JWT headers
when that key signs a token. Token verification currently tries configured
verify-capable keys; it does not select a verification key solely from the JWT
`kid` header.

The default token name is `access_token`. The default lifetime is `900`
seconds. `crypto default token lifetime <SECONDS>` applies to explicit keys
unless a key-specific `crypto key ... token lifetime ...` overrides it. If only
defaults are present and no explicit key exists, the auto-generated key
uses those defaults.

Auto-generation defaults to tag `default` and algorithm `ES512`. It also
accepts `EdDSA` and `Ed25519`, which generate Ed25519 material and select the
respective JOSE signing label. Use a distinct tag when changing key families;
reuse with an incompatible algorithm is rejected. The auto-generation tag
identifies material shared within the runtime. With no state directory that
material is volatile; with explicit state the generated-key record survives
restart. `TestCaddyRuntimeStateE2E` verifies unchanged public JWKS and old JWT
verification after SIGKILL. Independent active instances still need deliberately
coordinated keys and cannot concurrently own the same state directory.

## Key Material

Use direct shared secrets for HMAC keys. They support `HS512`, `HS384`, and
`HS256`, with `HS512` preferred by default:

```caddyfile
crypto key sign-verify {env.JWT_SHARED_KEY}
crypto key verify {env.JWT_SHARED_KEY}
```

Use PEM files for RSA, ECDSA, and Ed25519 keys. Supported file extensions are
`.pem` and `.key`. RSA supports `RS512`, `RS384`, and `RS256`. ECDSA supports P-256,
P-384, and P-521 curves, mapped to `ES256`, `ES384`, and `ES512`. A private
key can sign and, unless usage is exactly `sign`, verify through its public
key. A public key can only verify.

```caddyfile
crypto key auth1 sign-verify from file /etc/caddy/jwt/sign_key.pem
crypto key auth1 verify from file /etc/caddy/jwt/verify_key.pem
crypto key verify from directory /etc/caddy/jwt/verify.d
```

When loading a directory, KMS reads `.pem` and `.key` files and derives each
key ID from the filename, normalized to lowercase letters, digits, `_`, and
`-`. The configured `<KID>` on the directory line is not retained for each file.

Ed25519 uses PKCS#8 `PRIVATE KEY` PEM for signing and SPKI `PUBLIC KEY` PEM
for verification. Both `EdDSA` and `Ed25519` JOSE labels are supported; imported
private keys prefer `EdDSA`. A public Ed25519 key with `sign` usage is rejected.
With `verify`, `sign-verify`, or `auto`, public PEM loads only a verifier and
does not enable signing or public discovery. An Ed25519 private key configured
with `verify` also contributes only a verifier. These KMS keys issue/verify
portal tokens; upstream OAuth `jwks key` pins use a separate loader with
different accepted key formats.

There is no crypto directive to relabel an imported key as `Ed25519`. PEM
persists material, not a JOSE preference: exporting a generated `Ed25519` key
and reimporting it uses `EdDSA` for new tokens. Both exact labels verify with
the same public key. Do not rewrite signed headers or extend OP ID-token
signing algorithms to configure portal access tokens.

Public signing-key discovery accepts `GET` or `HEAD` at
`<mount>/.well-known/jwks.json` without an enable directive or admin access.
See [public discovery](../authentication-portal-api/SKILL.md#public-signing-key-discovery)
for selection and response rules, and
[HTTP routing](../configuration-http-integrations/SKILL.md#public-jwks-routing)
for exact mount boundaries ahead of a protected catch-all.

Unsupported material includes certificates, malformed PEM, unsupported ECDSA
curves, and DSA. See selected upstream `pkg/kms/ed25519.go`,
`crypto_key.go`, and `ed25519_test.go` for Ed25519 material and label behavior.

## Env And Secrets

There are two different env patterns:

```caddyfile
crypto key verify {env.JWT_SHARED_KEY}
crypto key verify from env JWT_SHARED_KEY
```

The first is resolved by caddy-security before authcrunch parses the raw crypto
line. The second is parsed by authcrunch KMS and reads the environment variable
when the key store is built. Both must resolve during provisioning.

Use `from env <NAME> as file` when the env var holds a path to a PEM file, and
`as directory` when it holds a directory path. Use `as key` or omit `as ...`
when the env var holds a shared secret or PEM content.

Use secrets manager lookups as direct values, not as `from env`:

```caddyfile
{
	security {
		secrets static_secrets_manager access_token {
			shared_secret {env.JWT_SHARED_KEY}
		}

		authentication portal myportal {
			crypto key sign-verify "secrets:access_token:shared_secret"
		}

		authorization policy app_policy {
			crypto key verify "secrets:access_token:shared_secret"
			allow roles authp/user
		}
	}
}
```

Direct `crypto key ... <value>` selects HMAC (or System API hex material for
`system` usage). Do not substitute PEM content into that form: it is treated as
a shared secret. For PEM content use `from env <NAME> as key`; for a PEM path
use `from file <PATH>` or `from env <NAME> as file`. The resolved value must
match the selected source form.

## Token Discovery

Crypto token names and HTTP cookie names are related but distinct. A signed
user receives `usr.TokenName` from the signing key's token name, while portal
cookies use the portal cookie factory's access-token cookie name. The portal
config wires its own validator to the access-token cookie name.

For Caddy authorization policies, default cookie names are
`AUTHP_ACCESS_TOKEN`, `access_token`, and `jwt_access_token`; runtime resolution
pins this list. Default header and query names retain `access_token` and
`jwt_access_token`; configured access-token cookie names are additionally added
as lowercase header and query names.

When the portal sets a custom access-token cookie name, mirror it in separate
or cross-instance policy configs:

```caddyfile
authentication portal myportal {
	set access_token cookie name CONTOSO_ACCESS_TOKEN
	crypto key sign-verify {env.JWT_SHARED_KEY}
}

authorization policy app_policy {
	set access_token cookie name CONTOSO_ACCESS_TOKEN
	crypto key verify {env.JWT_SHARED_KEY}
	allow roles authp/user
}
```

Use `set token sources cookie header query` to control lookup order. Use
`validate bearer header` when clients send `Authorization: Bearer <token>`.

## System API Keys

Remote Basic/API-key authentication uses matching `system` key IDs and 32-byte
hex keys on the policy and portal. They encrypt PASETO assertions and do not
sign JWTs. Read [System API key configuration](references/system-api-keys.md)
for exact syntax, file-value handling, key selection and challenge-policy limits.

## Failure Patterns

If a policy rejects portal-issued tokens, verify that portal signing material
and policy verification material match, the policy searches the actual cookie,
header, or query name, and both sides agree on token lifetime expectations.

If login succeeds but protected routes redirect to auth, suspect token source
or access-token cookie name mismatch before suspecting ACLs.

If provisioning fails on crypto, inspect whether caddy-security rejected the
line as too short or unsupported `crypto` prefix, or whether authcrunch KMS
rejected the deeper key syntax, empty env var, unsupported file extension, bad
PEM, missing verify keys, or invalid System API key length.

If remote Basic/API-key auth fails, check that the policy has a `system` key,
the portal has the same key ID and value, the policy `with ... portal` URL is
HTTPS and points at the portal base path, and the client sends the expected
realm and API-key or Basic credentials headers.

## Fixtures

`caddyfile_crypto_test.go` checks exact raw adapter forwarding, runtime
algorithm replacement, legacy defaults/key attributes, and library-owned
validation. `testcase_authenticate_with_crypto` covers both portal and policy
adaptation. `TestCaddyJWKSE2E` in `jwks_e2e_test.go` runs real TLS Caddy login,
independent signature verification from public JWKS, file/directory/env PEM
loading, exact labels, public routing, gatekeeper trust, private export and
reimport, and live discovery changes. `TestCaddyJWKSPersistenceE2E` in
`jwks_persistence_e2e_test.go` checks restart, rotation, and retirement in fresh
OS processes, plus live verifier retirement after cached authorization.

Use these examples for orientation:

- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`
  for portal lifetime plus shared `sign-verify`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile` for
  portal `sign-verify` paired with policy `verify`.
- `testdata/caddyfile_adapt/testcase_security_with_secrets.Caddyfile` for
  secret-backed crypto values.
- `assets/config/home.Caddyfile` for multiple key IDs and `system` keys.
