---
name: configuration-http-integrations
description: "caddy-security HTTP integration Caddyfile configuration. Use when creating, reviewing, or modifying route-level authenticate and authorize directives, portal and protected route separation, matcher forms, same-host or split-host auth wiring, auth URL routing and alignment, auth-path collisions such as upstream /auth routes, dedicated auth hosts with root-mounted portals, portal-owned path prefixes to avoid, or unnecessary global Caddy directive-order overrides."
---

# Configuration HTTP Integrations

## Purpose

Use this skill to wire caddy-security's route-level HTTP integrations:
`authenticate [<matcher>] with <portal>` and
`authorize [<matcher>] with <policy>`.

The `security` app defines authentication portals and authorization policies;
the HTTP integrations attach those configured objects to Caddy routes. Use
`configuration-authentication` for portal internals and
`configuration-authorization` for policy internals.

Prefer names that reveal the referenced object type in generated examples, such
as `myportal` or `local_portal` for portals and `app_policy` or `local_policy`
for policies. Policy names are not required to end in `_policy`, but the suffix
makes `authorize with <policy>` intent clear.

Use `authentication portal myportal` with `authenticate with myportal`, or choose
a descriptive portal name. Avoid `authentication portal portal` in examples,
fixtures, and tests; the repeated word obscures the declaration's name.

Read these files when details matter:

- `plugin_authn.go` for `authenticate` syntax and directive order.
- `plugin_authz.go` for `authorize` syntax and directive order.
- `assets/config/Caddyfile`, `assets/config/home.Caddyfile`, and
  `assets/config/multiportal.Caddyfile` for current route shapes.
- `testdata/caddyfile_adapt/testcase_authenticate_ok.Caddyfile`,
  `testdata/caddyfile_adapt/testcase_authorize_ok.Caddyfile`, and
  `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`
  for focused adapt fixtures.

## Route Roles

`authenticate` serves the authentication portal. Put it on the portal host or
portal path, such as `/auth*`. It is not the access-control layer for a file
server or upstream app.

`authorize` protects resource routes. It loads an authorization policy, checks
tokens or configured auth proxy methods, injects authenticated identity where
configured, and redirects unauthenticated browser users to the policy's auth
URL.

Keep portal and protected-resource routes separate:

```caddyfile
example.com {
	route /auth* {
		authenticate with myportal
	}

	route /app* {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

For same-host browser login, put the portal route before a catch-all protected
route so the portal is not itself protected by `authorize`:

```caddyfile
https://localhost:8443 {
	route /auth* {
		authenticate with local_portal
	}

	route {
		authorize with local_policy
		root * /srv/files
		file_server browse
	}
}
```

The referenced policy should point browser users to the portal:

```caddyfile
authorization policy local_policy {
	crypto key verify {env.JWT_SHARED_KEY}
	set auth url /auth
	allow roles authp/user
}
```

For split-host deployments, put `authenticate` on the auth host and `authorize`
only on the protected app or asset host. Use a full auth URL when the portal is
on a different host.

## Public JWKS Routing

The portal serves access-token public keys at
`<mount>/.well-known/jwks.json` through the existing `authenticate` handler.
Place the portal before any protected catch-all and use path-segment
boundaries when the deployment must keep neighboring prefixes private:

```caddyfile
example.com {
	@portal path /auth /auth/*
	route {
		route @portal {
			authenticate with myportal
		}
		route {
			authorize with app_policy
			reverse_proxy 127.0.0.1:8080
		}
	}
}
```

This routes `/auth/.well-known/jwks.json` publicly while `/authentication/`
stays under the policy. A `/tenant/auth` mount uses `/tenant/auth` and
`/tenant/auth/*` in the matcher. A dedicated root portal exposes
`/.well-known/jwks.json` with the existing root `authenticate` route.

Do not put `authorize` before `authenticate` on the portal route or add a
generic suffix-based bypass to the gatekeeper. Caddy owns mount selection;
the library owns public discovery, method validation, and serialization.
There is no discovery enable directive. See
[the HTTP contract](../authentication-portal-api/SKILL.md#public-signing-key-discovery).

## Browser Refresh Routing

Keep POST `<mount>/api/refresh_token`, `/api/refresh_session`, and `/api/logout`
on the complete, unstripped portal route before any protected catch-all.
`Portal.ServeHTTP` authenticates these operations using their own credentials,
so expired access can renew or log out; other APIs stay protected. Forward the
refresh/session headers, Origin/Fetch Metadata, cookies and body unchanged.
Do not add retries, CORS allowances or gatekeeper suffix bypasses.

Serve `<mount>/assets/js/refresh.js`, continuation, fresh login and logout
confirmation through that same portal. Use top-level portal navigation for
external application continuation; a GET link to `/api/refresh_token` is invalid.
The embedded client does not renew arbitrary cross-origin applications.
See the [browser HTTP/UI contract](../authentication-portal-api/references/browser-refresh.md).

## Portal Path Selection

For a portal with `oidc provider`, the issuer's path is also the HTTP mount.
Route its exact path and descendants through `authenticate`, before a protected
catch-all, using the same segment-boundary pattern above. For example, an issuer
`https://login.example.com/tenant/auth` requires `/tenant/auth` and
`/tenant/auth/*`; a dedicated root issuer uses a root `authenticate` route.
Use `route` or a non-stripping `handle`, never `handle_path`, `uri strip_prefix`,
or a generic path handler that removes the issuer mount.

Discovery at `<mount>/.well-known/openid-configuration` and all `<mount>/oidc/*`
endpoints, including `/oidc/continue` for login/consent, belong to the portal.
Do not add gatekeeper bypass rules or manually dispatch an OP adapter. AuthCrunch
handles OP requests before its ordinary access-token gates and HTML negotiation.
`<mount>/.well-known/jwks.json` publishes portal access-token keys;
`<mount>/oidc/jwks` publishes separate OP ID-token keys. See the
[OIDC protocol contract](../configuration-oauth-applications/references/oidc-provider.md#http-mount-and-protocol-contract)
for capabilities, native callbacks, and TLS relying-party tests.

The authorization policy's `set auth url` must align with the path where the
authentication portal is actually served:

- Same host: use the portal route path, such as `/auth` for `route /auth*`.
- Same host with path conflict: use `/xauth` for `route /xauth*`.
- Dedicated auth host at root: use the full root URL, such as
  `https://auth.example.com/`.

Do not leave `set auth url` at the `/auth` default when the portal is mounted
at `/xauth`, `/`, or a different host. For split-host deployments, prefer the
full portal URL over a relative path.

Use `/auth` as the default portal route path in new examples:

```caddyfile
route /auth* {
	authenticate with myportal
}
```

Use a different portal path, commonly `/xauth`, when the protected upstream
application already owns `/auth` for its own login, callbacks, API endpoints,
or framework routes. In that case, do not shadow the upstream's `/auth` path
with caddy-security's portal route; mount the portal elsewhere and point the
authorization policy's `set auth url` to that path:

```caddyfile
{
	security {
		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url /xauth
			allow roles authp/user
		}
	}
}

app.example.com {
	route /xauth* {
		authenticate with app_portal
	}

	route {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

Use `/` when a dedicated auth host serves only the authentication portal for a
parent domain. For example, if `auth.myfiosgateway.com` exists only to serve
the portal for the `myfiosgateway.com` domain and has no upstream app or static
content of its own, mounting the portal at root keeps the login URL short and
avoids reserving an unnecessary path prefix:

```caddyfile
{
	security {
		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url https://auth.myfiosgateway.com/
			allow roles authp/user
		}
	}
}

auth.myfiosgateway.com {
	route {
		authenticate with domain_portal
	}
}

app.myfiosgateway.com {
	route {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

Do not mount the portal at `/` on a host that also needs to serve an upstream
application or other site content; use `/auth` or `/xauth` in that case.

## Avoid Portal-Owned Prefixes

Do not use a portal-owned endpoint family as the public mount prefix for
`authenticate`. These names are valid internal endpoints below the chosen base
path, such as `/auth/login`, but they SHOULD NOT be the base path itself:

- `/api`, including `/api/refresh_token`, `/api/profile`, and admin API
  endpoints.
- `/qrcode`.
- `/assets` and `/favicon`.
- `/profile`.
- `/portal`.
- `/recover` and `/forgot`.
- `/register`.
- `/whoami`.
- `/apps`, especially `/apps/sso` and `/apps/mobile-access`.
- `/oauth2` and `/saml`.
- `/basic` and `/basic/login`.
- `/barcode`, especially `/barcode/mfa`.
- `/sandbox`.
- `/login` and `/logout`.
- `/beacon` for JSON/API-style requests.

go-authcrunch dispatches several portal requests with substring or suffix
checks before falling back to generic base-path inference. A mount such as
`/api`, `/profile`, `/portal`, or `/login` can therefore make ordinary portal
login, callback, static asset, refresh-token, or JSON requests hit the wrong
internal handler.

Prefer `/auth` for ordinary same-host portals, `/xauth` when `/auth` collides
with the protected upstream, or `/` only on a dedicated auth-only host. If an
upstream application owns one of the reserved names, leave that upstream path
alone and mount the portal at `/xauth` or a dedicated auth host.

Avoid:

```caddyfile
route /api* {
	authenticate with app_portal
}

route /profile* {
	authenticate with app_portal
}
```

Prefer:

```caddyfile
{
	security {
		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url /xauth
			allow roles authp/user
		}
	}
}

app.example.com {
	route /xauth* {
		authenticate with app_portal
	}
}
```

## Syntax

Prefer route blocks for clarity:

```caddyfile
route /auth* {
	authenticate with myportal
}

route /api/* {
	authorize with api_policy
	reverse_proxy 127.0.0.1:9000
}
```

The optional matcher form is valid when it keeps the surrounding Caddyfile
smaller:

```caddyfile
authenticate /auth* with myportal
authorize /api/* with api_policy
```

The portal or policy name must match a configured object in the `security` app.
Keep subconfiguration inside `authentication portal <name>` and
`authorization policy <name>` blocks. Do not put policy internals, such as
`with api key auth ...`, under the route-level `authorize` directive; the route
handler parser reads only the directive arguments.

## Directive Order

Do not generate global Caddy directive-order overrides for caddy-security:

```caddyfile
{
	order authenticate before respond
	order authorize before file_server
}
```

Also do not generate `order authorize before basicauth` by default. The plugin
already registers its order in code:

- `authenticate` before `respond`
- `authorize` before `basicauth`

Only add global `order` directives when debugging a proven directive-order
conflict with another third-party plugin, and explain the conflicting directive
order. Do not use global order directives as a default fix for login failures,
redirect loops, or authorization denials.

Legacy docs-site examples and old solution briefs may still include global
`order authenticate before respond` and `order authorize before basicauth`
lines. Treat those examples as historical route-shape references, not as
current guidance to copy into new Caddyfiles.

## Validation

When changing Caddyfile examples or fixtures, validate with the narrowest
adapt-focused test from `testing-and-ci`. For skill-only edits, run the skill
validator from `skill-creator`.
