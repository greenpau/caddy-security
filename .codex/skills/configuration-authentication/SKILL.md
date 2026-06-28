---
name: configuration-authentication
description: "caddy-security authentication portal Caddyfile configuration. Use when creating, reviewing, or modifying security authentication portal blocks, route-level authenticate directives, portal crypto, enabled identity stores, OAuth or SAML identity providers, SSO app providers, trusted redirects, source address validation, or portal wiring. For cookies, UI, and user transforms use the focused authentication subskills."
---

# Configuration Authentication

## Purpose

Use this skill to configure `authentication portal <name>` blocks and the
route-level `authenticate with <portal>` handler.

Read these files when details matter:

- `caddyfile_authn.go` for the portal block.
- `caddyfile_authn_crypto.go` for crypto key directives.
- `caddyfile_authn_misc.go` for `enable`, `validate`, and `trust`.
- `plugin_authn.go` for route-level `authenticate` syntax.
- `~/dev/src/github.com/greenpau/go-authcrunch/config.go` for portal
  validation, default backend attachment, and user registration wiring.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/config.go` and
  `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/portal.go` for
  portal defaults and runtime behavior.

Use focused sibling skills for specialized portal sub-blocks:

- `configuration-crypto` for portal `crypto` defaults, JWT signing keys,
  auto-generated keys, token names and lifetimes, secret-backed key material,
  and System API `system` keys.
- `configuration-authentication-cookies` for `cookie` and token-cookie naming.
- `configuration-authentication-ui` for `ui` blocks, templates, static assets,
  custom CSS/JS/HTML, themes, languages, logos, and private links.
- `configuration-authentication-user-transforms` for `transform user` blocks,
  ACL matchers, transform actions, challenges, claim replacements, and UI links
  emitted by transforms.

## Shape

```caddyfile
security {
	local identity store localdb {
		realm local
		path assets/config/users.json
	}

	authentication portal myportal {
		crypto default token lifetime 3600
		crypto key sign-verify {env.JWT_SHARED_KEY}
		enable identity store localdb
	}
}

example.com {
	route /auth* {
		authenticate with myportal
	}
}
```

The portal name must match the `authenticate with <portal>` reference.
Route-level syntax also allows a matcher: `authenticate @matcher with
<portal>`.

## Portal Wiring

Add only the backends the portal should use:

```caddyfile
enable identity store localdb
enable identity provider github azure
enable sso provider aws
```

Define those stores, identity providers, or SSO app providers with the matching
domain skills before enabling them. `enable identity provider <name>` references
`oauth identity provider <name>` or `saml identity provider <name>` blocks;
`enable sso provider <name>` references `sso provider <name>` SSO app blocks.
Identity stores and identity providers can take multiple names on one line.

If a portal has no explicit identity stores and no explicit identity providers,
authcrunch currently attaches all configured identity stores and identity
providers during `Config.Validate()`. Prefer explicit `enable` lines in new
examples. After defaults and disabled-backend filtering, a portal must have at
least one identity store or identity provider; SSO providers are additional app
providers and do not satisfy the login-backend requirement by themselves.

User registration is global authcrunch config. A `user registration <name>`
block names its target identity store; authcrunch validates that store, marks it
registration-enabled, and attaches the registry to any portal that has that
identity store enabled. Do not generate an `enable user registration <name>`
portal line: the current `enable` parser does not accept it even though an old
syntax comment still mentions it.

## Common Portal Options

Use crypto keys for token signing and verification:

```caddyfile
crypto default token lifetime 3600
crypto key sign-verify {env.JWT_SHARED_KEY}
```

Use both `enable source ip tracking` and `validate source address` when issued
tokens should carry and verify the source address. The first sets authcrunch
token grantor source-address tracking; the second makes the token validator
enforce the source-address claim.

Trusted redirect URI checks support login and logout redirect targets:

```caddyfile
trust login redirect uri domain exact example.com path prefix /app
trust logout redirect uri domain example.com path /
```

The match type is optional and defaults to `exact`; supported match types are
`exact`, `partial`, `prefix`, `suffix`, and `regex`.

## Fixtures

Use these fixtures as examples:

- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`
- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`
