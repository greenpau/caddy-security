# Portal mount selection and reserved paths

Read this reference when choosing a same-host, custom or root mount, diagnosing
upstream path collisions, or mounting a portal beside protected services.

## Declare the mount

Use an explicit mount in new configurations:

```caddyfile
@portal path /company/auth /company/auth/*
route @portal {
	authenticate with myportal at /company/auth
}
```

The native handler equivalent is:

```json
{
  "handler": "authenticator",
  "route_matcher": "*",
  "portal_name": "myportal",
  "base_path": "/company/auth"
}
```

`at <mount>` occurs once, at the end of `authenticate` arguments. The directive
accepts no block. Use `/` for root or a canonical absolute nested path without a
trailing slash. The field is literal: no runtime placeholders, secrets, wildcard
matching, URL escapes, query or fragment. Whitespace, control characters,
backslashes, repeated separators and dot segments are rejected, not normalized.
The declared path must be ASCII, require no URL escaping and contain no semicolon:
browser cookies use that same mount as their Path, while cookie serialization
strips non-ASCII bytes or treats a semicolon as an attribute delimiter. Rejecting those mounts
prevents silently changing the browser-proof scope. Reserved words are checked
in every segment as described below. These restrictions concern mount
declarations; realms and resource data retain their own validation.

Omitting `at`, or omitting/nulling native `base_path`, retains legacy mount
inference. An explicitly empty value fails validation. Existing compatibility
fixtures intentionally retain omission; they do not qualify an explicit mount.

Caddy's matcher still selects the handler. An explicit mount does not create
routes, inspect surrounding route trees or prove that a proxy forwards all
intended requests. For a nested declaration, requests must use the exact mount
or a descendant beginning with `<mount>/`; neighboring prefixes, outside paths,
case aliases and encoded aliases of the mount receive 404 with `no-store` before
portal handling. Root owns the entire path space and has no outside-prefix case.
Feature-owned escaping within child data remains subject to that feature's
validation; the declaration does not globally forbid all encoded child values.

Use `route` or a non-stripping `handle`. An explicit handler rejects changes to
the request's path or encoded path made earlier in the Caddy chain, so
`handle_path`, `uri strip_prefix` and path rewrites cannot remove the mount.
Query-only changes are allowed. Preserve the body, cookies, Origin, Fetch
Metadata and trusted-proxy interpretation through delegation.

## Feature agreement

The app compares an explicit handler mount with the resolved configuration of
that portal. Enabled token refresh and Documents API, the portal OP issuer path, selected bundled
SQLite ticket providers and selected enabled SQLite registration workflows must
hold the same mount. An issuer with no path means `/`. Disabled features and
unused backend declarations do not constrain another portal. Cookie prefix/path
requirements also apply; for example, a `__Host-` sandbox cookie requires a root
mount. These checks use private configuration snapshots and do not open a backend
just to compare paths. The snapshot applies the enabled refresh-cookie name
override before cookie defaults and collision validation, matching portal runtime
precedence without mutating the declared configuration.

A portal without a feature that pins its mount may be attached at multiple
neutral paths; the request keeps its own declared mount without mutating the
shared portal. Third-party backends retain responsibility for restrictions the
host cannot inspect. Mount agreement does not establish an external origin or
replace each feature's origin, callback and TLS validation.

Documents stores permanently bind their origin and base path. A matching
explicit handler is required when declaring a mount; a valid but externally
misrouted origin is still the operator's responsibility. Disabling Documents or
declaring only storage settings adds no mount constraint. See
[Documents configuration](../../configuration-authentication/references/documents.md)
for the separate database namespace and reload restrictions.

For `oidc provider`, route the issuer path and its descendants through the same
explicit handler. Discovery at `<mount>/.well-known/openid-configuration` and all
`<mount>/oidc/*` endpoints, including login/consent continuation, belong to the
portal. Do not manually dispatch an OP adapter or add gatekeeper bypass rules.
AuthCrunch handles OP requests before ordinary access-token gates and HTML
negotiation, after checking the explicit mount boundary.

`<mount>/.well-known/jwks.json` publishes access-token public keys;
`<mount>/oidc/jwks` publishes separate OP ID-token keys. Explicit mode admits only
the exact signing-JWKS path, so `/company/auth/other/.well-known/jwks.json` cannot
publish that keyset by suffix. Preserve the portal's themed OP response headers.
See the [OIDC protocol contract](../../configuration-oauth-applications/references/oidc-provider.md#http-mount-and-protocol-contract)
for protocol capabilities, callbacks and TLS relying-party acceptance.

## Portal path selection

Use `/auth` by default and align the authorization policy's `set auth url` with
the actual mount:

```caddyfile
@portal path /auth /auth/*
route @portal {
	authenticate with myportal at /auth
}
```

If the protected upstream already owns `/auth`, leave that route available to it
and choose a neutral mount such as `/xauth`. The following fragments assume
`app_portal` and its signing key are declared in the global `security` block:

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
		authenticate with app_portal at /xauth
	}
	route {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

Use `/` on a dedicated auth host that serves only the portal:

```caddyfile
auth.example.com {
	route {
		authenticate with domain_portal at /
	}
}
```

The protected host's policy then uses `set auth url https://auth.example.com/`.
Do not leave it at `/auth` when the mount or host changes. A redirect does not
transfer a host-only access cookie to another host; use the
[cookie configuration owner](../../configuration-authentication-cookies/SKILL.md)
for shared-domain scope, token discovery and signing/verification coordination.
Refresh and OP cookies retain their narrower host and issuer restrictions.

Avoid a root portal when the same host must serve upstream application routes
or unrelated content. A complete runnable example with explicit `/auth` and
`/xauth` mounts is [assets/config/Caddyfile](../../../../assets/config/Caddyfile).

## Avoid portal-owned prefixes

The shared mount validator checks each segment case-sensitively:

| Reservation | Names |
| --- | --- |
| Segment starts with | `profile`, `portal`, `recover`, `forgot`, `register`, `whoami`, `logout`, `favicon`, `beacon`, `login` |
| Complete segment | `connected-accounts`, `.well-known`, `api`, `apps`, `assets`, `barcode`, `basic`, `cross-device`, `oauth2`, `oidc`, `provider`, `qrcode`, `saml`, `sandbox` |

Thus `/company/login-team` and `/company/api/auth` are rejected. Neutral
lookalikes such as `/team-login`, `/saml-service`, `/cross-device-team`, `/auth`
and `/xauth` remain valid, as do uppercase variants such as `/LOGIN`. Do not
assume that changing the spelling of a reserved name is desirable deployment
design; choose a path whose meaning is clear to operators.

These reservations apply to the declared mount, not to route data below it.
`/auth/login` is an intended login endpoint, and an OAuth realm named `login`
remains data within the provider's namespace. Arbitrary child paths still follow
the selected library's endpoint dispatch; an explicit mount does not turn every
legacy substring-based handler into a complete first-segment router.

Legacy omission cannot reject a reserved deployed mount before requests arrive.
Move the mount, policy auth URL and any pinned feature paths together rather
than relying on inferred routing to disambiguate a collision.

## Validation

`plugin_authn_mount_test.go` covers parser arity, literal syntax and native
presence/validation. `testcase_authenticate_explicit_mounts` and
`testcase_authenticate_reserved_mount` are registered adaptation fixtures.
`TestPortalMountResolvedSnapshot`, `TestPortalMountFeatureBindings` and
`TestPortalMountBundledProviderBindings` exercise resolved feature agreement,
disabled/unused selections, private snapshots and persistent candidates.
`TestCaddyPortalMountE2E` uses actual Caddy TLS to qualify root/nested login and
resource access, mounted assets and exact
discovery, containment despite a broad matcher, path-rewrite rejection and
preservation of the serving app after a rejected candidate.

Refresh API routing acceptance includes GET `/api/logout`, `/api/refresh_token`
and `/api/refresh_session` with HTML Accept: each must return JSON 405 with
`Allow: POST`, no redirect and no credential mutation, before and after login.
Existing refresh and OP journeys remain required for their protocol behavior;
adaptation alone establishes neither request ownership nor session safety.
