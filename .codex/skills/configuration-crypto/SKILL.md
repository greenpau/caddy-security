---
name: configuration-crypto
description: "caddy-security crypto directive configuration for authentication portals and authorization policies. Use when creating, reviewing, or debugging crypto Caddyfile lines, JWT signing or verification keys, token names and lifetimes, key IDs, HMAC/RSA/ECDSA key loading, auto-generated keys, env or secrets-backed crypto values, System API crypto keys for remote Basic/API-key authentication, and authenticate/authorize key compatibility."
---

# Configuration Crypto

## Purpose

Use this skill for `crypto` directives inside
`authentication portal <name>` and `authorization policy <name>` blocks.
Use it together with `configuration-authentication` or
`configuration-authorization` for the surrounding portal or policy, and with
`configuration-runtime-resolution` or `configuration-secrets` when values come
from `{env.*}`, `{file.*}`, or `secrets:*:*`.

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
`sign-verify` key. That is useful for single-process local setups. Prefer
explicit keys for stable deployments, multiple Caddy instances, restarts where
old tokens should survive, or any portal and policy split across instances.

## Common Pairing

For a portal that issues JWTs and a policy that verifies them, configure the
portal with sign-capable material and the policy with matching verify-capable
material:

```caddyfile
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
crypto default autogenerate algorithm ES512

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
defaults are present and no explicit key exists, the auto-generated ES512 key
uses those defaults.

The auto-generation defaults are tag `default` and algorithm `ES512`. The
auto-generation tag is stored in authcrunch's shared in-memory key buffer, so
objects in the same process can share the generated key. Do not rely on it
across independent Caddy instances.

## Key Material

Use direct shared secrets for HMAC keys. They support `HS512`, `HS384`, and
`HS256`, with `HS512` preferred by default:

```caddyfile
crypto key sign-verify {env.JWT_SHARED_KEY}
crypto key verify {env.JWT_SHARED_KEY}
```

Use PEM files for RSA and ECDSA keys. Supported file extensions are `.pem` and
`.key`. RSA supports `RS512`, `RS384`, and `RS256`. ECDSA supports P-256,
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

Unsupported material includes certificates, malformed PEM, unsupported ECDSA
curves, DSA, and EdDSA keys.

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
```

The resolved value must be the exact string KMS expects: a shared secret, PEM
content, a PEM path only when using the `from file` form, or a System API hex
key for `system` usage.

## Token Discovery

Crypto token names and HTTP cookie names are related but distinct. A signed
user receives `usr.TokenName` from the signing key's token name, while portal
cookies use the portal cookie factory's access-token cookie name. The portal
config wires its own validator to the access-token cookie name.

For authorization policies, default cookie names are `access_token` and
`jwt_access_token`. Default header and query names are also `access_token` and
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

`system` keys are not JWT signing keys. They encrypt and decrypt PASETO
`v4.local` System API messages used by remote Basic/API-key authentication.
They require a non-empty key ID and a 32-byte key encoded as 64 hex characters.

Configure the same `system` key ID and value on the remote policy and the
receiving portal:

```caddyfile
authentication portal myportal {
	crypto key sys1 system {env.SYSTEM_API_SECRET}
	enable identity store localdb
}

authorization policy api_policy {
	crypto key jwt1 verify {env.JWT_SHARED_KEY}
	crypto key sys1 system {env.SYSTEM_API_SECRET}
	allow roles authp/user
	with api key auth portal https://auth.example.com/auth realm local
	with basic auth portal https://auth.example.com/auth realm local
}
```

For file-backed System API keys, use a Caddy replacer that resolves to the file
content, such as `crypto key sys1 system {file./etc/caddy/security_system.key}`.
Do not use `crypto key sys1 system from file ...`; KMS file loading is for PEM
JWT keys, not raw System API hex keys.

The portal chooses the `system` key from the encrypted message footer `kid`.
The authorize-side remote authenticator currently picks the first configured
`system` key in key-store order for remote calls, so keep rotation plans simple
and test them explicitly.

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

Use these examples for orientation:

- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`
  for portal lifetime plus shared `sign-verify`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile` for
  portal `sign-verify` paired with policy `verify`.
- `testdata/caddyfile_adapt/testcase_security_with_secrets.Caddyfile` for
  secret-backed crypto values.
- `assets/config/home.Caddyfile` for multiple key IDs and `system` keys.
