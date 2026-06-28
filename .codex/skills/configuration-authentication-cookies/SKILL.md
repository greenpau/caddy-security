---
name: configuration-authentication-cookies
description: "caddy-security authentication portal cookie Caddyfile configuration. Use when creating, reviewing, or modifying authentication portal cookie directives, cookie domains, paths, lifetimes, SameSite, insecure cookies, guessed or stripped domains, token cookie names, cookie name prefixes, access token cookie validation, or authcrunch cookie defaults."
---

# Configuration Authentication Cookies

## Purpose

Use this skill for `cookie` directives and token-cookie naming inside
`authentication portal <name>` blocks.

Read these files when details matter:

- `caddyfile_authn_cookie.go` for accepted Caddyfile cookie syntax.
- `caddyfile_authn_misc.go` for `set <token> cookie name` and cookie prefix
  directives.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/cookie/` for cookie
  defaults, domain matching, SameSite validation, and emitted attributes.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/portal.go` for how
  access-token cookie names feed the portal validator and grantor.

Use `configuration-authentication` for the surrounding portal and
`authenticate` handler wiring.

## Cookie Directives

Configure global cookie settings with two-argument forms:

```caddyfile
authentication portal myportal {
	cookie domain example.com
	cookie path /
	cookie lifetime 86400
	cookie samesite lax
	cookie insecure off
	cookie guess domain
	cookie strip domain
}
```

`cookie domain <name>` creates a domain-specific entry. `cookie guess domain`
derives a cookie domain from the request host and omits the domain when the
derived value is a public suffix. `cookie strip domain` forces host-only
cookies.

Configure domain-specific overrides with `cookie <domain> <key> <value>`:

```caddyfile
cookie example.com path /
cookie example.com lifetime 3600
cookie example.com samesite strict
cookie example.com strip domain
```

Supported keys are `domain`, `path`, `guess`, `lifetime`, `samesite`,
`insecure`, and `strip domain`; `guess` only affects the global two-argument
form. `lifetime` must be a positive integer. `samesite` is validated by
authcrunch and accepts `lax`, `strict`, or `none`.

## Cookie Names

Authcrunch defaults use the `AUTHP` prefix:

- `AUTHP_SESSION_ID`
- `AUTHP_REDIRECT_URL`
- `AUTHP_SANDBOX_ID`
- `AUTHP_ID_TOKEN`
- `AUTHP_ACCESS_TOKEN`
- `AUTHP_REFRESH_TOKEN`

Use `set <token> cookie name <name>` for individual cookie names:

```caddyfile
set session_id cookie name AUTHP_SESSION_ID
set redirect_url cookie name AUTHP_REDIRECT_URL
set sandbox_id cookie name AUTHP_SANDBOX_ID
set id_token cookie name AUTHP_ID_TOKEN
set access_token cookie name AUTHP_ACCESS_TOKEN
set refresh_token cookie name AUTHP_REFRESH_TOKEN
```

Setting `access_token` also updates the portal token grantor and validator
cookie names. Use `set cookie name prefix <prefix>` to uppercase the prefix and
rebuild all default cookie names:

```caddyfile
set cookie name prefix AUTHP
```

## Fixtures

Use these fixtures as examples:

- `testdata/caddyfile_adapt/testcase_authenticate_with_cookie_domain.Caddyfile`
- `testdata/caddyfile_adapt/testcase_authenticate_with_cookie_guess.Caddyfile`
- `testdata/caddyfile_adapt/testcase_authenticate_with_ui.Caddyfile`
