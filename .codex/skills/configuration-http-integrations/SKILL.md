---
name: configuration-http-integrations
description: "Mount authenticate and authorize handlers, separate portal and protected routes, align auth URLs, and preserve trusted proxy metadata. Use for path conflicts, split hosts, public JWKS, and route ordering."
---

# Configuration HTTP Integrations

## Purpose

Use this skill to wire caddy-security's route-level HTTP integrations:
`authenticate [<matcher>] with <portal>` and
`authorize [<matcher>] with <policy>`.

The `security` app defines authentication portals and authorization policies;
the HTTP integrations attach those configured objects to Caddy routes.
Portal internals belong to [configuration-authentication](../configuration-authentication/SKILL.md);
policy internals belong to [configuration-authorization](../configuration-authorization/SKILL.md).
Route mounting does not require reloading either owner unless its configuration
also needs changes.

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

## Caddy Host Defaults

Cross-device login uses the existing portal handler for its entire mount-relative
`/cross-device` namespace. Preserve the prefix and library `strict-origin`
Referrer-Policy; no extra handler or CORS layer is needed. Provider realms named
`cross-device` retain their own namespace. Use
[configuration-authentication-cross-device](../configuration-authentication-cross-device/SKILL.md)
to review transfer paths, HTTPS/Origin boundaries and root/nested mount tests.

The selected Caddy v2.11.7 limits request headers to 16 KiB by default and
defaults idle request-body reads and response writes to 60 seconds. Review
large JWT/cookie sets and slow uploads or streams when upgrading. Tune Caddy's
global `servers` options (`max_header_size`, `timeouts read_body_idle` and
`timeouts write_idle`) only for a measured deployment need; these are host
settings, not `security` directives. An idle deadline measures stalled I/O,
not the whole request duration.

Caddy drops incoming dot-containing headers by default and controls underscore
headers separately. Prefer ordinary hyphenated names for identity and proxy
metadata. If a trusted integration needs other spellings, configure the host's
`expected_dot_headers` or `expected_underscore_headers` deliberately and review
hyphen/underscore/dot aliases together. The allowlists do not establish trust in
client-supplied identity; trusted-proxy and authorization rules still apply.

The legacy Caddy authentication chain buffers individual provider responses
when several providers are configured. Only the successful provider's response
headers are retained; a failed provider must not contaminate another provider's
success. Current `authorize` routes use `AuthorizationHandler` directly and
preserve handled gatekeeper responses. See the published
[v2.11.6 changes](https://github.com/caddyserver/caddy/releases/tag/v2.11.6) and
[v2.11.7 fixes](https://github.com/caddyserver/caddy/releases/tag/v2.11.7).

## Route Roles

`authenticate` serves the authentication portal. Put it on the portal host or
portal path, such as `/auth` and `/auth/*`. It is not the access-control layer for a file
server or upstream app.

`authorize` protects resource routes. It loads an authorization policy, checks
tokens or configured auth proxy methods, injects authenticated identity where
configured, and redirects unauthenticated browser users to the policy's auth
URL.

Keep portal and protected-resource routes separate:

```caddyfile
example.com {
	@portal path /auth /auth/*
	route @portal {
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
	@portal path /auth /auth/*
	route @portal {
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
on a different host. A redirect alone does not transfer a host-only access
cookie to the app host. For browser access across sibling hosts, coordinate the
access-cookie domain/path, its policy-discovered name, and signing/verification
keys; only trusted hosts may share that domain. OIDC/refresh cookies retain
their own host and issuer constraints and must not be broadened automatically.
Use [configuration-authentication-cookies](../configuration-authentication-cookies/SKILL.md)
to configure cross-host access-cookie scope and validate prefix restrictions.
For unrelated domains, a shared Domain attribute is impossible; choose an
explicit token or separate authentication integration instead.

## Edge Trust

Caddy owns trusted-proxy selection. The plugins preserve the trusted host and
client-address interpretation before authcrunch sees a request; arbitrary
forwarded headers cannot establish it. Read [edge trust](references/edge-trust.md)
for direct/forwarded behavior, duplicate hints, current IPv6 limits, exact mount
matching, and verification through actual Caddy TLS.

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

## Direct OAuth Routing

Direct OAuth without a portal uses the policy's own callback/logout namespace.
Route that namespace and application resources through the same `authorize`
handler. See [direct OAuth](../configuration-authorization/SKILL.md#direct-oauth-without-a-portal).
The directive now emits `http.handlers.authorization`, which preserves handled
responses without allowing the protected handler to run. Legacy manually written
JSON using `authentication.providers.authorizer` retains Caddy's generic
authentication-chain behavior and should be regenerated for direct OAuth.

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

Native JSON login uses POST `<mount>/login` on the same unstripped portal route
and requires neither admin nor profile APIs. Preserve the JSON body and error
status/metadata. Do not synthesize Cookie, Origin or Fetch Metadata headers for
native requests, strip supplied browser headers to evade transport validation,
or infer an OIDC browser session from a bearer/API-key credential. The public Go
client and explicit native refresh/logout contract are documented separately in
[JSON/native interoperability](../authentication-portal-api/references/native-client.md).

## Portal Path Selection

Default to exact `/auth` plus `/auth/*`, and point the policy's auth URL at that
mount. If the upstream owns `/auth`, choose another namespace; a dedicated auth
host can mount at `/`. Read [portal mount patterns](references/portal-mounts.md)
for routing fragments, required declarations, path preservation, and split-host alignment.

## Avoid Portal-Owned Prefixes

Portal endpoint names constrain custom mount choices. Check the
[reserved path contract](references/portal-mounts.md#avoid-portal-owned-prefixes)
before choosing a prefix; an upstream namespace collision is resolved by moving
the portal mount and its auth URL together.

## Syntax

Prefer route blocks for clarity:

```caddyfile
@portal path /auth /auth/*
route @portal {
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
@portal path /auth /auth/*
authenticate @portal with myportal
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

## Acceptance criteria

- `/auth` and descendants reach the portal; `/authentic` does not. Protected
  handlers receive no call after denial or a handled OAuth callback.
- A custom mount preserves the original request path and aligns login, logout,
  callback, public JWKS, and policy auth URLs. Reserved prefixes are rejected or
  avoided using the linked contract.
- A split-host browser login delivers the access cookie to the intended app and
  the policy finds and verifies it. Host-only cookie defaults cannot establish
  that flow. Preserve the narrower refresh/OIDC scopes and test both hosts.
- Direct TLS and a configured trusted proxy agree on the intended identity and
  origin; hostile forwarded headers from untrusted peers cannot supply authority.
