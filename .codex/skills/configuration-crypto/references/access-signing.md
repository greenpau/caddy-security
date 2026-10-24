# Selected PS256 access signing

The security app owns named signer factories and their runtime handles. A portal
selects one by name; its ordinary login, direct credential, connected-account,
cross-device and refresh paths keep their existing identity and commit checks.
The signer receives approved claims. A successful signature remains provisional
until its exact claims are verified and the owning login/session operation
completes.

This selection affects portal access JWTs. OP ID tokens retain their separate
signing keys and algorithms. System API encryption also retains its own keys.
Omitting the selector preserves ordinary KMS signing.

## Declarations and consumer profiles

This is a security-block fragment. It requires the surrounding identity-store,
portal, authorization and HTTP routing configuration, plus actual key files.

```caddyfile
access signer rsapss grants {
	key file /private/auth/access-private.pem
	key id current
	issuer https://auth.example.test/auth
	audience service-a
	max lifetime 15m
}

authentication portal login {
	access signer grants
	access token profile {
		issuer https://auth.example.test/auth
		audience service-a
		key ids current
		max lifetime 900
	}
	crypto key current verify from file /private/auth/access-public.pem
	transform user {
		match any
		action overwrite aud service-a
	}
}

authorization policy protected {
	access token profile {
		issuer https://auth.example.test/auth
		audience service-a
		key ids current
		max lifetime 900
	}
	crypto key current verify from file /private/auth/access-public.pem
	allow roles authp/user
}
```

The module is `security.access_signers.rsapss`; native app declarations use the
`access_signers` array, with `driver: "rsapss"`, `name`, and the public backend
fields `key_file`, `key_id`, `algorithm`, `issuer`, `audience`, `max_lifetime`.
Native portals use `access_signer`; portal and policy profiles use
`access_token_profile`, containing `issuer`, `audience`, `key_ids` and integer
`max_lifetime_seconds`. Policy-only profiles need no signer declaration.

The backend body delegates the public RSA-PSS parser. Every setting occurs once;
unknown settings, empty values and nested blocks fail. Algorithm defaults to
`PS256`, the only supported choice. Maximum lifetime is a whole-second duration
from `1s` through `24h`, default `15m`; equivalent spellings normalize before
configuration hashing. Key file, key ID, issuer and audience are required.
Relative key paths retain backend semantics; use absolute paths operationally.

The profile body delegates the core profile parser. All four settings are
required exactly once. `max lifetime` is integer seconds, from 1 through 86400.
`key ids` supplies one to sixteen distinct IDs in one statement; IDs are sorted
in the normalized profile. Profile algorithm and token purpose are fixed, with
no user-selectable alternatives. Issuer is an exact canonical HTTPS origin and
optional clean mount, without a trailing slash, credentials, query or fragment.
Audience is an exact nonempty grant.

Backend configuration is literal except for Caddy's lexical `{$ENV}` expansion.
Portal selection and consumer profiles support the usual runtime replacement
and secret lookup. Deferred profile bodies are retained complete, then resolved
once and parsed strictly. Only value positions resolve; replacement cannot turn
a keyword into syntax or split one value into several arguments. Native profile
lifetimes remain integers. A nonempty selection resolving to empty fails instead
of falling back to ordinary signing. Same-named portals and policies keep
separate deferred profiles.

## Issuance and verification

Each profile ID requires an explicit RSA public verification key of 2048–8192
bits. The current signer's public key must equal its corresponding verifier.
Signer and portal must agree on issuer, sole audience and maximum lifetime.
Selected portals reject ordinary non-system signing, sign-verify or auto keys;
keep explicit system encryption entries when required. A profile without a
signer is supported for an authorization policy, not a portal issuing ordinary
tokens. Direct OAuth policies reject these JWT profiles.

The private signer accepts one unencrypted PKCS#8 or PKCS#1 two-prime RSA key,
bounded to 16 KiB. It rejects symlinks and nonregular files. The app checks known
key-read paths against bundled SQLite databases and their journal/WAL/SHM names
using filesystem metadata before opening keys. Deferred Start checks opening
paths, current KMS environment paths and key-directory entries again. Serving
apps retain their physical ownership inventory until requests drain. Keep
trusted paths and process environment stable during construction and use; this
preflight is not a guarantee against concurrent external file replacement.

Current transforms must explicitly grant the sole configured audience. The
signer never supplies a missing audience or restores one removed on renewal.
After policy evaluation, selected issuance fixes the canonical issuer and sets
`nbf` to the trusted integral `iat`. Invalid/future reserved times fail before
user conversion; shorter approved expiry and proof deadlines remain shorter.
Exact custom JSON numbers survive normalization. Plugin input is detached and
its returned token must contain exactly the approved canonical claims.

Selected signing uses the positive `crypto default token lifetime`, otherwise
900 seconds, capped by the profile maximum. Negative explicit lifetimes fail;
verification-key lifetimes do not select the issuing lifetime. Refresh and
cross-device proof deadlines can shorten it further. Renewable portals require
the signer issuer to equal refresh `public origin` plus its mount. No issuer
override is inferred from the current request or provider.

Profile consumers require `alg=PS256`, `typ=authcrunch-access+jwt`, an allowed
`kid`, the exact issuer and sole audience, nonempty subject, and integral
positive `iat`, `nbf`, `exp`. They enforce `iat <= nbf <= now < exp` with zero
leeway and the configured maximum lifetime. Verification pins SHA-256 and a
32-byte PSS salt. Duplicate JSON members, extra JOSE headers, malformed or
oversized envelopes and other algorithms fail. An unrelated usable key cannot
rescue a rejected profile token, including through caches. This purpose profile
does not claim RFC 9068 conformance.

## Delivery, discovery and replacement

Logical signing token names and HTTP cookie names remain separate. Direct
Basic/API-key responses use the configured crypto token name, default
`access_token`; cookies and JSON `access_token_name` follow the resolved cookie
factory, including prefixes. Configure the policy to discover the actual cookie
name. A nonrenewable session cookie stays a session cookie, a shorter configured
lifetime stays shorter, and a longer lifetime is capped at signed expiry.
Renewable delivery continues using the committed access expiry.

Public `<mount>/.well-known/jwks.json` exposes the current key and explicitly
retained profile keys, sorted by ID and marked PS256. External private keys never
enter exportable KMS slots, even with private admin export enabled. Existing
GET/HEAD, no-store and mount-ownership rules still apply; OP discovery is separate.

For rotation, configure old and new public IDs in both consumers, switch the
selected signer to the new key/ID, then retire the old ID after its intended
overlap. Successful replacement builds fresh immutable signers and verifiers;
editing a PEM file does not change a live runtime. A failed candidate disposes
only its own resources and leaves the serving app usable. Persistent deployments
retain the existing exclusive stop/start boundary.

Persistent root state includes the actual loaded public trust and current signer
role. Re-encoding the same key does not change that identity; replacing key
material at the same path and ID does. Changing configuration away and back
receives a fresh durable epoch, so old persisted refresh/session authority is not
restored. This does not revoke stateless access tokens if their signing key is
explicitly trusted again.

Module/parser tests, storage-preflight tests and the actual Caddy signer suites
jointly own acceptance. Require independent signature verification, all issuance
categories, strict rejection with positive controls, credential withholding,
cookie/name contracts, rotation, failed candidates and real process persistence.
Legacy `rsa_pss_e2e_test.go` remains verification-only compatibility coverage.
