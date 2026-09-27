# Portal mount selection and reserved paths

Read this reference when choosing same-host/custom/root mounts, diagnosing
upstream path collisions, or mounting a portal beside protected services.

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
[OIDC protocol contract](../../configuration-oauth-applications/references/oidc-provider.md#http-mount-and-protocol-contract)
for capabilities, native callbacks, and TLS relying-party tests.

The selected go-authcrunch pin supplies its own themed OIDC page headers;
preserve them through Caddy. For older v1.2.6 browser consent, use the explicit
[consent response policy](../../configuration-oauth-applications/references/oidc-provider.md#consent-response-policy-for-v126).
It uses Caddy's deferred response-header matcher before `authenticate`; it does
not rewrite incoming Origin or weaken the provider's CSRF checks.

The authorization policy's `set auth url` must align with the path where the
authentication portal is actually served:

- Same host: use the portal route path, such as `/auth` for an exact `/auth` plus `/auth/*` matcher.
- Same host with path conflict: use `/xauth` for an exact `/xauth` plus `/xauth/*` matcher.
- Dedicated auth host at root: use the full root URL, such as
  `https://auth.example.com/`.

Do not leave `set auth url` at the `/auth` default when the portal is mounted
at `/xauth`, `/`, or a different host. For split-host deployments, prefer the
full portal URL over a relative path.

Use `/auth` as the default portal route path in new examples:

```caddyfile
@portal path /auth /auth/*
route @portal {
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
	@portal path /xauth /xauth/*
	route @portal {
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
	@portal path /xauth /xauth/*
	route @portal {
		authenticate with app_portal
	}
}
```
