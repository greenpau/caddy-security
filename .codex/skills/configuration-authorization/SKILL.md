---
name: configuration-authorization
description: "Configure caddy-security authorization policies, direct OAuth without a portal, authorize routes, ACLs, bypasses, JWT verification, auth proxies and injected identity headers."
---

# Configuration Authorization

## Purpose

Use this skill to configure `authorization policy <name>` blocks and the
route-level `authorize [<matcher>] with <policy>` handler.

Use `configuration-http-integrations` for route placement, matcher forms,
same-host or split-host auth wiring, portal/protected route separation, and
directive-order guardrails when attaching a policy to HTTP routes.

Use `configuration-crypto` for detailed policy `crypto` key syntax, token
verification material, token names and lifetimes, auto-generated key behavior,
secret-backed key material, and System API `system` keys for remote Basic or
API-key auth.

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
Put auth proxy settings inside the policy block, not inside a block under the
route-level `authorize` directive. The current route parser only reads the
directive arguments.

## Runtime Defaults

An authorization policy must have a name and at least one ACL rule. When no
`crypto key ...` entries are present, go-authcrunch auto-generates an ES512
`sign-verify` key with token name `access_token` and lifetime `900`; for real
portal-issued tokens, configure compatible verification material explicitly.
When explicit key entries are present, at least one key must be `verify` or
`sign-verify`.

Defaults applied by `PolicyConfig.Validate()` and `Gatekeeper.configure()`:

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
if no later deny overrides it, unless `stop` is used.

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
a split-host or root-mounted dedicated auth host. Use
`configuration-http-integrations` to choose and align the route shape.

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

The selected go-authcrunch v1.3.3 checks every original, decoded and cleaned
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

Select one configured OAuth identity provider inside a policy:

```caddyfile
authorization policy app_policy {
	use oauth identity provider upstream
	oauth public origin https://app.example.test
	oauth base path /private/oauth
	oauth session cookie name __Host-APP_SESSION
	oauth login cookie name __Host-APP_LOGIN
	oauth session lifetime 900
	oauth maximum sessions 10000
	oauth maximum pending logins 1024
	validate method path
	allow roles authp/user
}
```

The provider is an ordinary `oauth identity provider upstream` declaration;
use [configuration-oauth-providers](../configuration-oauth-providers/SKILL.md)
for its credentials and protocol settings. No portal, local store or JWT key
is required. The shared `pkg/authz/oauth/parser` owns all `use oauth` and `oauth`
statements. Collect the complete set before calling `ConfigureOAuth`; duplicates,
unknown fields, extra arguments and nested blocks fail. Use `{$VARIABLE}` for
these statement values; restricted origin/path/numeric values are validated
during adaptation and do not defer `{env.*}` resolution.

Only provider selection is required. Omitted base path defaults to
`/_authcrunch/oauth2/POLICY`; cookie names to `AUTHZ_POLICY_SESSION` and
`AUTHZ_POLICY_LOGIN`. Session lifetime is absolute, 1–86400 seconds (default
900), with no sliding renewal or upstream refresh. Session/pending capacities
are 1–65536 (defaults 10000/1024); explicit zero is invalid. Policy names use
1–128 ASCII letters, digits, underscores or hyphens. Public origin, if supplied,
must be HTTPS without credentials, query, fragment or a non-root path. Without
it, incoming requests need TLS and trusted Host routing. Behind TLS termination,
pin the external origin and preserve Host through a trusted proxy.

Mount the whole base namespace through the same policy as the application:
the GET callback is `BASE/authorization-code-callback`; same-origin POST
`BASE/logout` revokes the local session. With the example base, a
`route /private/* { authorize with app_policy ... }` covers both. Do not strip
the base path, bypass callbacks, accept provider tokens as app credentials,
or synthesize callback success. Callbacks retain state, browser, origin, nonce,
PKCE and replay checks in AuthCrunch. Cookies are host-only, root-path, Secure,
HttpOnly and SameSite=Lax; duplicate/invalid credentials fail closed.

The verified identity receives `authp/user` plus provider roles. Allowing that
baseline grants every account accepted by the provider; choose narrower ACLs
when needed. Every session request reevaluates current ACLs. Use
`validate method path` for resource restrictions: generic provider identities
do not carry token path grants required by `validate path acl`.
Direct policies do not apply portal transforms/MFA/profile/refresh/OP features.
They cannot mix JWT crypto, bearer validation, token sources, auth proxies or
portal cookie-name settings. Existing JWT policies keep those features.

`authorize` adapts to `http.handlers.authorization`. Its three-outcome wrapper
runs downstream only for `Authorized` or `Bypassed`; handled redirects,
callbacks, logout and denials retain status/headers/body, including capacity
503s. Unhandled authentication errors deny and retain the
`{http.auth.authorizer.error}` placeholder for existing `handle_errors` routes.
App admission failures retain their 503 status through Caddy's error helper.
The legacy JSON authenticator
`http.authentication.providers.authorizer` remains available, but Caddy's
generic authentication chain cannot preserve handled OAuth responses; use the
new handler for direct policies and regenerate old adapted route JSON.

Without state, completed sessions and pending exchanges disappear at restart.
[Persistent runtime state](../configuration-state/SKILL.md) retains completed
sessions and revocations across stop/start; pending exchanges still disappear.

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
