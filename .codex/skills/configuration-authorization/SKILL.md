---
name: configuration-authorization
description: "Configure authorization policies, ACLs, bypasses, identity headers, JWT verification, remote Basic/API-key auth, and direct OAuth without a portal."
---

# Configuration Authorization

## Purpose

Use this skill to configure `authorization policy <name>` blocks and the
route-level `authorize [<matcher>] with <policy>` handler.

Use [configuration-http-integrations](../configuration-http-integrations/SKILL.md)
to place protected routes, select matchers, wire same-host or split-host
applications, and check directive ordering.

Use [configuration-crypto](../configuration-crypto/SKILL.md) to configure JWT
verification material, token names/lifetimes, generated or secret-backed keys,
and System API `system` keys for remote Basic or API-key authentication.

Read these files when details matter:

- `caddyfile_authz.go` for the policy block.
- `caddyfile_authz_acl.go` and `caddyfile_authz_acl_shortcuts.go` for ACLs.
- `caddyfile_authz_bypass.go` for bypass rules.
- `caddyfile_authz_crypto.go` for token verification keys.
- `caddyfile_authz_inject.go` for claim header injection.
- `caddyfile_authz_misc.go` for `enable`, `disable`, `validate`, `set`, and
  `with`.
- `plugin_authz.go` for route-level `authorize` syntax.
- `../go-authcrunch/pkg/authz/config.go` and
  `gatekeeper.go` for policy defaults and runtime wiring.
- `../go-authcrunch/pkg/authz/validator/` for token
  source, bearer, method/path, path-ACL, source-address, Basic, and API-key
  behavior.
- `../go-authcrunch/pkg/acl/` for ACL fields,
  aliases, match strategies, and action semantics.

## Shape

```caddyfile
{
	security {
		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url /auth
			allow roles authp/admin authp/user
		}
	}
}

example.com {
	route /app* {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

The policy name must match the `authorize with <policy>` reference.
The policy requires a block with unquoted opening and closing braces; quoted
brace tokens must not terminate or open a policy.
Put auth proxy settings inside the policy block, not inside a block under the
route-level `authorize` directive. The current route parser only reads the
directive arguments.

## Runtime Defaults

A JWT-mode authorization policy must have a name and at least one ACL rule. When no
`crypto key ...` entries are present, go-authcrunch auto-generates an ES512
`sign-verify` key with token name `access_token` and lifetime `900`; for real
portal-issued tokens, configure compatible verification material explicitly.
When explicit key entries are present, at least one key must be `verify` or
`sign-verify`.

These defaults apply to JWT policies; direct OAuth policies have their own
configuration and reject JWT crypto settings. Defaults applied by
`PolicyConfig.Validate()` and `Gatekeeper.configure()`:

- auth URL: `/auth`
- auth redirect query parameter: `redirect_url`
- auth redirect status: `302`
- token source priority: `cookie`, `header`, `query`
- session cookie: `AUTHP_SESSION_ID`
- access cookies: `AUTHP_ACCESS_TOKEN`, `access_token`, `jwt_access_token`
- named auth headers and query params retain the AuthCrunch defaults; explicit
  access cookie names also enter those lists in lowercase
- API key header: `X-Api-Key`
- auth realm header: `X-Auth-Realm`

Use `set token sources` only with `cookie`, `header`, and `query`; the order is
the lookup priority. `validate bearer header` enables `Authorization: Bearer
<token>` parsing but is not itself a token source name.

## ACLs

Read [typed custom ACL fields](references/typed-acl-fields.md) for `acl field`
declarations, literal claim keys, typed JSON, adapter ownership and Caddy TLS
qualification. It also records v1.3.10's failing default-action ordering boundary.

Prefer concise shortcuts for common role, origin, issuer, method, and path
matches:

```caddyfile
allow roles authp/admin authp/user
allow roles authp/guest with get to /public
deny iss untrusted
```

Shortcut behavior is not just syntax sugar:

- `allow <field> <values...>` becomes `allow log debug`; it does not stop later
  rules.
- `deny <field> <values...>` becomes `deny stop log warn`.
- `<field> any` or `<field> *` becomes `field <field> exists`.
- `with <method> to <path>` uppercases the method, adds a `partial match path`
  condition, and enables method/path validation.

Use explicit ACL rules when comments, actions, or multiple conditions matter:

```caddyfile
acl rule {
	comment allow users
	match role authp/user
	allow stop log info
}

acl default deny
```

Explicit rule conditions use go-authcrunch ACL grammar:

```caddyfile
match any
match roles authp/admin authp/user
partial match email @example.com
no regex match issuer ^https://untrusted
field origin exists
field picture not exists
```

Supported match strategies are `exact` (default), `partial`, `prefix`,
`suffix`, and `regex`; prefix with `no` for negative matches. Field aliases
include `role`, `group`, and `groups` for `roles`; `issuer` for `iss`;
`subject` for `sub`; `mail` for `email`; `scope` for `scopes`; `organization`
for `org`; `address`, `ip`, and `ipv4` for `addr`; `http_method` for `method`;
and `http_path` for `path`.

Explicit actions must start with `allow` or `deny`, and may include `any`,
`stop`, `log [debug|info|warn|error]`, `counter`, and `tag <value>`. With
multiple conditions, the default is match-all; add `any` to the action for
match-any. A matched deny denies immediately. A matched allow grants access only
if no later matching deny overrides it, unless `stop` is used. In v1.3.10,
`acl default`/`match any` rules are skipped on the validator's normalized user
data; do not rely on an explicit default deny to override a compact allow.
The typed-field reference owns the failing regression and required upstream fix.

Use `amr` to require verified methods, for example inside a policy:

```caddyfile
acl rule {
	match role authp/user
	match amr hwk
	allow stop
}
```

AMR is a list: `pwd` records password proof, `otp` records TOTP, and `hwk`
records WebAuthn/U2F. `allow amr otp` is also a valid shortcut. Credential
inventory and transform-added claims are not evidence that a factor was
completed. The library stamps authoritative evidence after login; the Caddy
challenge E2E verifies that forged transform AMR cannot satisfy a policy.
Direct Basic/API-key proxy authentication also observes current portal/user
challenge requirements.

## Policy Options

Use `set auth url` for the login redirect target and `set forbidden url` for
authorization failures:

```caddyfile
set auth url /auth
set forbidden url /forbidden
set redirect query parameter redirect_url
set redirect status 302
set user identity id
set token sources header query cookie
set session_id cookie name AUTHP_SESSION_ID
set access_token cookie name AUTHP_ACCESS_TOKEN ALT_ACCESS_TOKEN
```

Cookie name settings map to `PolicyConfig.SessionIDCookieName` and
`AccessTokenCookieNames`. Explicit access lists replace defaults. Caddy pins
absent settings during runtime resolution so AuthCrunch cannot discover custom
names from unrelated portals. Coordinate both names explicitly when a portal
uses `set cookie name prefix PORTAL`; see
[portal cookie precedence and policy coordination](../configuration-authentication-cookies/SKILL.md#coordinate-gatekeepers-explicitly).
Session IDs are correlation values, not access credentials. Multiple access
names belong on one line; empty names, duplicate names, repeated settings, and
extra session-name arguments are rejected.

`set auth url` must match where the referenced authentication portal is served.
Use the same-host portal path such as `/auth` or `/xauth`, or the full URL for
a split-host or root-mounted dedicated auth host. The HTTP integration route
above owns mount selection and auth URL alignment.

go-authcrunch v1.3.6 preserves the full application return URL over HTTP/1.1,
HTTP/2 and HTTP/3, including authority/port, escaped path and raw query. The
configured auth URL remains the outer destination, including direct portal
OAuth callback URLs. Decode `redirect_url` once to inspect the return URL.
An authority-looking path such as `//other.example/private` stays on the
application origin. JavaScript redirects also preserve the browser fragment.
The library classifies `RequestURI`, since HTTP/3 can populate an absolute
`r.URL` for an origin-form request target. Keep this logic in AuthCrunch;
do not rewrite Caddy request fields, build another redirect, or disable HTTP/3.

Split-host completion still requires compatible access-token keys, cookie
domain/path and an explicit trusted application return destination. A correct
redirect does not relax the portal allowlist. Forwarded origin selection follows
[Caddy edge trust](../configuration-http-integrations/references/edge-trust.md);
separate forwarded port/prefix hints remain stripped.

`set redirect status` accepts only 300 through 308. When `set forbidden url` is
present, access-denied decisions redirect with status `303`; `{uri}`,
`{http.request.uri}`, and `{url}` placeholders are replaced at request time.

Use validation and behavior toggles deliberately:

```caddyfile
validate bearer header
validate method path
validate path acl
validate source address
enable js redirect
enable strip token
enable login hint
enable login hint with email phone
enable additional scopes
disable auth redirect query
disable auth redirect
```

`validate method path` enables policy method/path evaluation without requiring
a token path claim. `validate path acl` additionally requires token path claims.
Token path claims
use exact matching or `*` and `**` wildcards, not regular expressions. `*`
matches one or more ASCII letters, digits, underscores, dots, tildes or hyphens;
`**` also spans slashes. Punctuation is literal: `/tenant.v1/**` cannot grant
`/tenantXv1/file`, and parentheses or `|` cannot expand a token's authority.
This differs from explicit `regex match path` policy conditions.
`validate source address` compares the token address claim to the request
source address. `enable strip token` removes the accepted credential from its
actual source: bearer/named header, Basic/API-key header, query or cookie.
Unrelated request headers, query arguments and cookies remain. Token sources
and validation still determine which credential can authorize the request.

The selected go-authcrunch v1.3.6 checks every original, decoded and cleaned
path interpretation whenever method/path or token path-claim validation is
enabled. Every interpretation must satisfy the policy and any required claim;
this also applies to cached identities. Cleaning must not turn
`/admin/../public/file` into a new grant. Repeated encoding cannot hide a
protected intermediate path before ending at an allowed path.

The library considers cleaning before and after decoding, preserves trailing
slashes, and allows at most four additional decoding passes after Go's initial
URL parsing. Remaining encoded bytes at that limit, mixed valid/invalid escapes,
invalid UTF-8 and initially encoded slashes fail closed. Encoded slashes are
ambiguous because routers disagree about whether they delimit segments.
Literal percent text such as `/public/100%25` remains usable when every
interpretation is allowed. Query strings do not participate in path checks.
These checks leave the request URL unchanged for downstream handlers. Keep
`authorize` ahead of application rewrites or prefix stripping so it sees the
original target; the library cannot recover a path that earlier middleware
already discarded. Ordinary role-only policies do not enable path validation.

For API key or basic auth proxying, configure a portal and realm:

```caddyfile
with basic auth portal myportal realm local
with api key auth portal myportal realm local
with api key header name X-Api-Key
with auth realm header name X-Auth-Realm
```

Basic/API-key auth is consulted after normal token sources fail. The request
realm must match `with auth realm header name`, defaulting to `X-Auth-Realm`;
failed Basic or API-key auth returns `401`.

Client checks for Basic and API-key auth:

```bash
curl -H 'X-Auth-Realm: local' --user 'jsmith:My@Password123' https://app.example.com/api/foo
curl -H 'X-Auth-Realm: local' -H 'X-Api-Key: <api-key>' https://app.example.com/api/foo
```

If clients cannot send `X-Auth-Realm`, set a default before `authorize` with
Caddy's `request_header` directive:

```caddyfile
route /api/* {
	request_header +X-Auth-Realm "local"
	authorize with api_policy
}
```

A malformed API key or failed Basic credential should return `401`. If the API
key header name is wrong or absent, the policy may treat the request like an
unauthenticated browser request and redirect to the auth URL unless
`disable auth redirect` is set. For multiple realms, configure one
`with basic auth portal ... realm ...` or `with api key auth portal ... realm
...` line per accepted realm and require clients to send the matching realm
header.

Bypass authorization only for paths that do not need authenticated user
metadata:

```caddyfile
bypass uri exact /healthz
bypass uri prefix /assets/
bypass uri regex ^/public/.*
```

Bypass match types are `exact`, `partial`, `prefix`, `suffix`, and `regex`.
The same decoding/cleaning checks above apply even without path-validation
options: each interpretation must match some configured bypass rule. An
ambiguous target receives normal authentication/authorization instead of a
bypass. A bypass grants no authenticated identity or claim metadata.

Inject claims only when an upstream explicitly expects them:

```caddyfile
inject headers with claims
inject header "X-User-Email" from email
```

`inject headers with claims` sets default `X-Token-*` headers for name, email,
roles, and subject. Custom `inject header` entries map a header name to a claim
field and are applied only after a user is authorized. Configured destination
headers are cleared before authentication, including deny and bypass paths, so
client-supplied identity values cannot survive as trusted claims.

## Direct OAuth Without a Portal

A policy can own the external OAuth login/session flow without a portal, local
store, or JWT key. It rejects JWT crypto and conflicting auth mechanisms.
Read [direct OAuth configuration](references/direct-oauth.md) for provider
selection, callback/logout routing, cookies, capacity, claims, and persistence.
All callbacks and handled responses stay with the authorization handler;
unauthenticated requests must not reach the protected upstream.

## Fixtures

Use these examples:

- `caddyfile_authz_test.go` for detailed ACL and misc behavior.
- `testdata/caddyfile_adapt/testcase_authorize_ok.Caddyfile`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile`.

`TestAuthzPathDelegation` checks the Caddy authentication provider's decisions,
identity metadata and preservation of the original URL. `TestCaddyAuthorizationPathE2E`
adapts policies and exercises real Caddy TLS over HTTP/1.1 and HTTP/2: bypasses,
method/path rules, token path claims, cached identities, encoded traversal,
invalid UTF-8 and concurrent literal wildcard grants. Denials assert that the
downstream handler was never reached; successful requests retain their URI.

`TestAuthzRedirectRequestTargets` exercises the actual authorization wrapper
with origin-form, absolute-form and HTTP/3 request representations, both
renderers and unchanged downstream request fields. `TestCaddyAuthorizationRedirectE2E`
checks separate app/portal hosts over verified HTTP/1.1, HTTP/2 and UDP/QUIC
HTTP/3, HEAD/GET redirects, local password and synthetic OAuth login, shared
cookies and final resource authorization. Its Chrome journeys assert the
negotiated protocol and execute JavaScript fragment redirects. The suite also
retains untrusted-return rejection, custom/disabled queries, status selection
and proxy trust. See [redirect qualification](../testing-and-ci/references/test-surfaces.md#authorization-login-redirects).

## Acceptance criteria

- A valid token with the intended role reaches the protected handler; an invalid,
  expired, wrong-purpose, or denied token does not. Verify response behavior and
  downstream call counts, not just returned errors.
- Path grants are checked before and after identity caching without rewriting
  the upstream request URI. `TestAuthzPathDelegation` and
  `TestCaddyAuthorizationPathE2E` cover this boundary.
- A direct OAuth policy completes its callback through the same handler and
  rejects a replay or incompatible JWT setting. Session restart persistence is
  qualified separately under explicit root state, never inferred from a redirect.
