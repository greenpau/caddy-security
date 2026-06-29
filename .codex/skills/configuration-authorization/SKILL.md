---
name: configuration-authorization
description: "caddy-security authorization policy Caddyfile configuration. Use when creating, reviewing, or modifying security authorization policy blocks, route-level authorize directives, ACL rules, allow or deny shortcuts, bypass rules, crypto verification keys, auth redirects, bearer token validation, basic or API key auth proxy settings, user identity fields, and injected claim headers."
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
security {
	authorization policy app_policy {
		crypto key verify {env.JWT_SHARED_KEY}
		set auth url /auth
		allow roles authp/admin authp/user
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
- token names in cookies, auth headers, and query params: `access_token`,
  `jwt_access_token`
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

`validate path acl` also enables method/path ACL evaluation. Path ACL claims are
matched against the request path using exact matching or `*` and `**`
wildcards. `validate source address` compares the token address claim to the
request source address. `enable strip token` removes only cookie-sourced auth
tokens from the upstream request.

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

Bypass match types are `exact`, `partial`, `prefix`, `suffix`, and `regex`, and
they match `r.URL.Path`.

Inject claims only when an upstream explicitly expects them:

```caddyfile
inject headers with claims
inject header "X-User-Email" from email
```

`inject headers with claims` sets default `X-Token-*` headers for name, email,
roles, and subject. Custom `inject header` entries map a header name to a claim
field and are applied only after a user is authorized.

## Fixtures

Use these examples:

- `caddyfile_authz_test.go` for detailed ACL and misc behavior.
- `testdata/caddyfile_adapt/testcase_authorize_ok.Caddyfile`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile`.
