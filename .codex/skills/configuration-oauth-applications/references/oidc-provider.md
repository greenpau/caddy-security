# Portal OpenID Provider

Use `oidc provider` to let a portal issue OIDC tokens to selected named OAuth
applications. External login through an upstream OIDC service belongs to
`oauth identity provider`, a separate configuration surface.

## Collection and validation

`caddyfile.go` registers every named application before parsing portals,
independent of declaration order and Caddy file/snippet imports.
`caddyfile_authn_oidc.go` collects the flat provider body and preserves quoted
values with the shared directive codec. `caddyfile_authn.go` attaches it with
`Config.ConfigureOIDCProvider` after collecting the complete portal and before
`AddAuthenticationPortal` validates it. Do not add a second field parser or
validate the portal before attaching OIDC. The dependency selected in `go.mod`
provides `pkg/oidc/parser.NewOIDCProviderConfigFromDirectives` and
`PortalConfig.ConfigureOIDCProvider`.

Only one provider block is allowed per portal, including disabled blocks and
blocks expanded from repeated imports. An absent block remains nil. A present
block defaults enabled; an empty block fails enabled-provider validation.

Inside `authentication portal myportal`, each setting occurs at most once
except distinct `acr` mappings:

| Setting | Arguments |
| --- | --- |
| `enabled` / `disabled` | Standalone, mutually exclusive; no boolean value. |
| `issuer` | One canonical HTTPS URL including the portal mount, without a trailing slash. |
| `realms` | One line with one or more distinct local realm names. |
| `applications` | One line with one or more distinct registered nicknames, in selection order. |
| `signing key files` | One line with one or more distinct absolute paths to dedicated private RSA PEM files. |
| `session lifetime`, `token lifetime`, `refresh lifetime` | One decimal integer in seconds. |
| `max sessions`, `max pending requests`, `max grants`, `max refresh tokens` | One decimal integer count. |
| `acr` | One context value and one or more required authentication methods; repeat for distinct context values. |

Multiword keywords are separate tokens; `"signing key files"`,
`signing_key_files`, and `max "pending requests"` are invalid. Quote key paths
containing spaces. Nested blocks, extra scalar values, unknown fields, empty
arguments, and repeated settings fail. Zero numbers retain library defaults:
28,800 seconds for sessions, 300 seconds for tokens, 10,000 sessions, 1,024
pending requests, and 10,000 grants. Negative or excessive enabled values fail
the library's bounds checks.

OIDC refresh defaults to a fixed 28,800-second family lifetime and capacity of
10,000 refresh entries per provider, independent of portal refresh settings.
Lifetime is bounded to 86,400 seconds and capacity to 1,000,000. Capacity
exhaustion fails closed. Rotation never extends the original family deadline;
reuse revokes the family. Grants remain bound to client, identity and consent.

`acr urn:example:password pwd` advertises a context satisfied only by completed
password authentication. `acr urn:example:mfa pwd otp` additionally requires
completed OTP. Mappings describe verified methods; they never establish login
evidence or change challenge policy. Context values must be distinct, nonempty,
at most 256 bytes and contain no whitespace. Methods must be distinct and
come from the library's validated AMR vocabulary (`pwd`, `otp`, `hwk`, `swk`,
`mfa`, `sms`, `tel`, `email`, `fpt`, `face`, `pin`, `rba`, `sc`, `user`, `wia`).

Check the enclosing portal's closing boundary as well as the provider body.
Caddy's segment collection counts quoted brace-valued arguments as braces;
such a value must not make a truncated portal pass adaptation.

A standalone `disabled` requires no issuer, realms, keys, or applications.
Syntax and explicitly selected applications still validate: unknown or nil
registrations, repeated nicknames, and duplicate selected protocol client IDs
fail even when disabled. Other disabled values retain AuthCrunch's semantic
validation opt-out. Nicknames differ from client IDs; distinct registrations
may share an ID only if one provider does not select both.

## Realm and issuer boundaries

Every selected realm must identify exactly one local store attached to that
portal, with no conflicting upstream identity provider. LDAP and other upstream
realms are unsupported for OIDC participation. More than one local realm may
participate. `enable identity store` controls portal login availability; it does
not add those realms to OIDC. An attached but unselected realm can log in to the
portal without receiving an OIDC session or a silent authorization code.
Switching realms in one browser must revoke the preceding OIDC session, including
when the new realm is unselected. Assert this by replaying the saved session
cookie and presenting its access token to UserInfo, not just checking that the
browser received a deletion cookie. Verify
realm-specific UserInfo and stable, distinct subjects for users with the same
username in different realms.

Use a separate portal for each provider. `oidc_config.go` rejects identical or
nested issuer mounts on the same hostname, during both adaptation and runtime
restoration. Cookie scope ignores ports and equivalent host spellings: DNS
trailing dots, Unicode/punycode names, and IPv6 compression do not bypass this
check. This comparison leaves the configured issuer unchanged. Use standard
dotted-decimal IPv4 addresses; shortened, octal, and hexadecimal forms are
rejected because browsers and Go clients interpret them differently.
Disjoint paths such as `/auth` and `/other`, or distinct hostnames, provide
separate provider scopes. Match the Caddy `authenticate` routes to the issuer
mounts. Use separate portal cookie prefixes and paths when sharing a host:

```caddyfile
# Inside the first portal, serving /auth/*:
cookie prefix FIRST
cookie path /auth
oidc provider {
    issuer https://login.example.com/auth
    realms employees contractors
    signing key files "/var/lib/caddy/security-private/first key.pem"
    applications website
}

# Inside a second portal, serving /other/*:
cookie prefix SECOND
cookie path /other
oidc provider {
    issuer https://login.example.com/other
    realms employees
    signing key files /var/lib/caddy/security-private/second.pem
    applications second_website
}
```

Each referenced realm/store and application must also be declared and attached
in its proper scope. OIDC cookies are host-only, Secure, HttpOnly, SameSite=Lax,
and scoped to the issuer mount. Portal-owned reserved paths such as `/api`,
`/sandbox`, and `/oauth2` cannot be issuer mounts. Noncanonical URLs, query
strings, fragments, credentials, encoded paths, and trailing slashes fail.
Explicit ports must be nonempty decimal values within 0–65535.
Enabled issuers must already use the origin spelling browsers send: ASCII
punycode for internationalized DNS names, compressed hexadecimal IPv6,
standard IPv4 without a trailing dot, and ports without leading zeroes.
Omit the default HTTPS port `443`. A single DNS trailing dot is allowed;
empty or overlong DNS labels are rejected. AuthCrunch compares origins exactly,
so accepting spellings that browsers rewrite can replace a working provider
with one that rejects its own discovery and login requests. Reject these
configurations before construction; never silently rewrite an issuer.

When [portal token refresh](../../configuration-authentication/references/token-refresh.md)
is enabled by a `token refresh` block or native JSON `refresh_tokens`, its
canonical HTTPS public origin and base path must agree with the OIDC issuer
origin and mount. This does not enable OIDC refresh grants.

## Keys and saved JSON

The parser never generates client credentials or signing keys and does not read
key files. Runtime construction checks and loads existing keys. The first key
signs and all listed public keys appear in JWKS. Keys must be dedicated to OIDC,
not reused for portal access-token signing. Missing or invalid key material
fails candidate provisioning, leaving the active deployment usable.

Host key checks require clean absolute paths, private `0700` directories and
current-user-owned `0600` files, without symlinks or traversal. See
[private provisioning](private-provisioning.md#storage-and-command-contract)
for ancestor permissions and the optional explicit provisioning commands.
These checks apply even without an OAuth registration store. Use Caddyfile
`{$VARIABLE}` substitution or literal paths; the provider body does not expand
runtime `{env.*}` or `secrets:*` references.

Adapted JSON retains `apps.security.oidc_provider_directives`, keyed by portal
name, and omits copied provider client snapshots. During `App.Provision`,
`resolveOAuthRegistrationConfig` loads all stored applications and reattaches
the providers to a private config copy before root/runtime validation. Native
JSON may instead supply `authentication_portals[].oidc_provider`; do not supply
both forms for the same portal. Explicit client credentials remain sensitive
JSON. Disabled and absent states survive both restoration paths. Provider
sessions and grants are process-local and do not survive successful replacement.

## Validation surfaces

See the HTTP and RP contract below when changing request routing or protocol
coverage; parser tests cannot establish those behaviors.

- `caddyfile_authn_oidc_test.go`: all settings/defaults, quoted paths, malformed
  syntax, duplicates, forward references, imports, disabled references, JSON
  restoration, and adaptation with a failing randomness source.
- `testcase_authenticate_with_oidc_provider.Caddyfile` and `.json`, registered
  in `TestCaddyfileAdaptAuthenticationToJSON`: complete adapter fixture with two
  providers, selected/unselected realms, all settings, zero defaults, disabled,
  and absent providers. Key paths are synthetic; adaptation performs no key I/O.
- `testcase_authenticate_with_oidc_unterminated.Caddyfile` and `.json`: a
  negative adapter fixture for quoted braces concealing a missing portal close.
- `testcase_authenticate_with_oidc_noncanonical_issuer.Caddyfile` and `.json`:
  a negative adapter fixture for a port that browsers rewrite.
- `oidc_config_test.go`: issuer route and cookie-path conflicts, including
  different ports, hostname aliases, canonical origins, DNS label validity,
  root mounts, and declaration order.
- `TestCaddyOIDCProviderE2E`: real TLS Caddy provisioning and discovery, two
  participating local realms plus an unselected realm, signed token exchanges,
  realm-specific identities, switching realms in one browser with replay of
  revoked sessions, two independent issuers, native JSON, disabled/absent
  endpoints, refresh alignment, and rejection of invalid replacements while
  existing sessions work.
  It also replays foreign session cookies under the target issuer's cookie name,
  rejects cross-issuer access grants and code redemption, checks separate JWKS,
  and verifies that logging out one portal leaves the other's grant usable.
  With portal refresh enabled, viewing logout confirmation retains the OP grant;
  completing cookie-transport logout revokes it and the saved OP session.
  Rejection cases assert the expected error, so a duplicate block cannot mask
  the malformed setting a test intends to exercise.
- `TestAuthnOIDCDelegation` in `plugin_authn_test.go`: direct library versus
  middleware response comparisons and unchanged canonical request URLs, with
  HTML/JSON Accept headers, invalid portal tokens, method errors, and CORS.
- `TestOIDCRPVerification` in `oidc_rp_test.go`: independent RS256 verification
  rejects invalid signatures, unknown/duplicate keys, private JWKS material,
  incorrect key purposes/encodings, wrong issuer/audience/nonce/at_hash, and
  invalid token times (including nbf). JWT names are case-sensitive; signed
  fixtures also check duplicate decoded names, invalid claim types and
  unsupported critical JOSE extensions without using the OP's verifier.
- `TestOIDCRPResponse` in `oidc_rp_response_test.go`: verifies that the RP helpers
  reject ambiguous callbacks, changed destinations, malformed queries, broken
  POST forms and weakened CSP. Consent submits the returned form action and
  enabled controls. Query and form-post errors both preserve state and issuer.
- `TestCaddyOIDCRelyingPartyE2E`: `oidc_rp_e2e_test.go` provides real Caddy TLS,
  discovery-driven RP helpers, browser cookies and consent/form-post parsing.
  `oidc_flows_e2e_test.go` exercises root and nested mounts, all client methods,
  password/TOTP, prompts, stale checkpoints, max_age, query/form-post, replay,
  wrong client/redirect/PKCE, consent CSRF, revocation/logout, token purposes,
  CORS and unsigned request objects. `oidc_loopback_e2e_test.go` delivers real
  callbacks to IPv4/IPv6 ephemeral listeners and redeems the exact actual URI.
  `oidc_capabilities_e2e_test.go` extends the same default Caddy journeys with
  registered RS256 Request Objects, signature/downgrade rejection, essential
  individual claims, ACR, address/phone filtering, rotating refresh grants,
  wrong-client rejection and refresh replay family revocation at both mounts.
  `TestOAuthApplicationRequestObjectKeys` and
  `TestCaddyfileOIDCAuthenticationContexts` cover delegated registration/mapping
  grammar and malformed inputs; the provider adaptation fixture includes the
  new directives and explicit/zero refresh limits.
- `TestCaddyRegistrationE2E`: immutable client identity and signing keys across
  actual process restarts at the same issuer URL, explicit secret rotation and
  activation, and verification of an earlier ID token against retained rollover
  keys. Sessions/grants remain process-local. Its in-memory user fixture creates
  fresh user IDs on each load; this test does not assert user-subject persistence.

The older `TestResolveRuntimeAppConfig` extracts only `security.config`; it does
not restore host-owned provider statements. Use the full App/Caddy coverage
above when changing this integration.

## HTTP mount and protocol contract

The existing Caddy `AuthnMiddleware.ServeHTTP` acquires the app request reference
and delegates to `Portal.ServeHTTP` with the original URL. AuthCrunch's
`pkg/authn/serve_http.go` invokes its OP adapter before ordinary access-token
checks, API dispatch, or HTML/JSON negotiation. Route the canonical issuer mount
through that handler; do not strip the prefix with `handle_path` or rewrite the
path. Keep `authorize` on protected resource routes, after the portal route.
See [HTTP integrations](../../configuration-http-integrations/SKILL.md#portal-path-selection)
for exact path and descendant matchers and root-host wiring.

The mounted paths are `/.well-known/openid-configuration`, `/oidc/authorize`,
`/oidc/continue`, `/oidc/token`, `/oidc/userinfo`, `/oidc/jwks`, and `/oidc/revoke`.
`/oidc/continue` resumes login and consent. Preserve library status codes, method
and bearer challenges, redirects, CORS, no-store/no-cache and form-post CSP,
including the nonce on its submission script. Do not wrap OP responses in portal
HTML or duplicate login completion in Caddy. `pkg/authn/oidc_runtime.go` derives
authentication evidence only from completed password/MFA checkpoints and the
selected local identity store; Caddy must never call `CompleteLogin` or create
that evidence itself.

### Consent response policy for v1.2.6

The current published dependency, `v1.3.2`, supplies themed
consent/form-post/error pages and the correct consent headers in the provider.
Caddy preserves those headers. Both the official harness and normal RP E2E
now run without the compatibility snippet below. Consent CSP retains default,
frame and base restrictions, permits same-origin themed assets with a style
nonce, and binds form-action to self and the validated client's callback origin.
Form-post script and style nonces must match the actual response page.

The v1.2.6 consent HTML inherits `Referrer-Policy: no-referrer`. Chrome consequently
sends `Origin: null` on its form POST, and the provider rejects it with 403.
For this version, import the reusable Caddy snippet
[`assets/config/oidc-consent-headers.Caddyfile`](../../../../assets/config/oidc-consent-headers.Caddyfile)
before the site declaration, then apply it before `authenticate`:

```caddyfile
import /path/to/oidc-consent-headers.Caddyfile

login.example.com {
	@portal path /auth /auth/*
	route @portal {
		import oidc_consent_headers /auth/oidc/authorize /auth/oidc/continue https://rp.example.com
		authenticate with myportal
	}
}
```

This fragment assumes the named portal is already configured. Supply both exact
paths for its issuer mount; a root issuer uses `/oidc/authorize /oidc/continue`.
The third argument is the registered callback's HTTPS origin, including any
non-default port. For this static deployment all clients share that origin.
Do not supply `*`, a scheme-only source, or derive this value from request input.
Import paths are relative to the containing Caddyfile. The snippet must be
defined before it is used. Each import belongs to its own portal route.

The standard Caddy [header response matcher](https://caddyserver.com/docs/caddyfile/directives/header)
defers the change until it can match GET, HTTP 200, HTML, the original self-only
form CSP, and the original `no-referrer` policy. Only matching consent responses
get `same-origin`, which preserves the same-origin form POST Origin while
withholding referrers from other origins. Their CSP keeps `default-src 'none'`,
`frame-ancestors 'none'` and `base-uri 'none'`, and permits form submission to
`'self'` plus that registered callback origin. Chrome applies `form-action` to
the post-consent redirect too: `'self'` alone aborts a valid cross-origin code
callback. Exact redirect-URI registration and code binding remain enforced by
the provider. For deployments with other callback origins, configure an explicit
reviewed source list; this snippet does not discover or authorize new callbacks.
Discovery, errors, redirects and
cross-origin form-post responses retain their library headers. Keep Origin and
CSRF validation intact; do not accept `null`, alter request headers, or skip
consent. This is an explicit deployment policy, not an automatic change to
`authenticate` or a library patch. The snippet is retained for v1.2.6 deployments.

The selected upstream fix emits the referrer policy and a form-action policy
covering the validated request's callback directly from the provider. Reassess
the snippet when changing dependency versions;
its exact response matcher deliberately stops applying if the library contract
changes. Local adaptation and root/nested Caddy TLS relying-party E2E verify the
policy, null/cross-origin and forged-CSRF rejection, and unaffected callbacks.
The official Chrome evidence additionally verifies actual browser-generated
Origin headers and successful reauthentication.

Keep key and token purposes distinct:

- `<mount>/.well-known/jwks.json` contains portal access-token verification keys
  used by normal authorization policies.
- `<mount>/oidc/jwks` contains dedicated RSA OP keys for RS256 ID tokens. OP
  access tokens authorize UserInfo; ID tokens and portal access tokens do not.
  Neither OP token substitutes for a gatekeeper token or browser login.

The supported profile uses authorization code with S256, Basic/POST/public client
authentication, query/form-post responses, local password/MFA, consent,
prompt none/login/consent, fresh authentication/max_age, UserInfo and revocation.
Completing portal logout clears the OP session and invalidates its grants; it is
not RP-initiated OIDC logout. Without a refresh cookie, GET `/logout` completes
logout. With a portal refresh cookie, GET renders the confirmation page and
the portal session API completes logout. The selected library advertises OIDC refresh grants,
individual claims, optional address/phone scopes, and unsigned/RS256 Request
Objects. Dynamic registration, private_key_jwt, encrypted Request Objects and
end_session_endpoint remain unsupported. OIDC refresh credentials require
registered `offline_access`, `prompt=consent`, and explicit approval. Scope
requests outside the registration never grant additional permissions.

By-value `request` JWTs with `alg: none` encode authorization parameters. They
can neither authenticate a client nor assert an authenticated user. They still
require real login, registered client/redirect checks, consent, PKCE and the
registered token endpoint authentication method. RS256 signatures use registered
client public keys and require `iss` matching the client and `aud` containing
the issuer. Unknown keys, tampering, unsigned downgrade under an RS256 pin,
remote/embedded header keys and malformed JWT metadata fail. The inner callback
takes precedence over the outer callback, then undergoes registration validation.
Remote `request_uri` and encrypted Request Objects are unsupported.

Individual `claims` requests are limited by registered scope permissions and
consent for the requested `userinfo` or `id_token` location. Optional profile,
address and phone attributes come from explicit `identity.User.Profile` data;
missing attributes are not fabricated. Caddy's inline `user` grammar does not
expose this profile object. Use a prepared local identity database. The
conformance fixture adds synthetic attributes offline after Caddy provisions its
disposable account, before the serving process opens the database. It records
phone verification as false and does not assert verified email ownership.

Public native clients may vary only the authorization port for literal HTTP
`127.0.0.1` or `[::1]`; all other URI bytes, including path/query encoding, stay
exact. Redemption must repeat the actual callback URI, including its ephemeral
port. Do not extend this to localhost names, mapped/alternative IP spellings,
custom schemes, wildcards or arbitrary CORS origins. A native callback's varying
port does not grant a new browser token-endpoint origin. Caddy passes through
the library's CORS contract rather than adding a host-level allowlist or wildcard.

Run the complete local integration group with:

```sh
go test -mod=readonly -race -count=1 -run '^(TestAuthnOIDCDelegation|TestOIDCRPVerification|TestOIDCRPResponse|TestCaddyOIDCProviderE2E|TestCaddyOIDCRelyingPartyE2E|TestCaddyRegistrationE2E)$' .
```

The bounded child processes use verified test TLS, synthetic credentials and
private test-owned key paths. Both native address families are required by the
loopback test; an unavailable IPv6 listener fails explicitly. These are local
E2E tests, not OpenID Foundation conformance certification.
