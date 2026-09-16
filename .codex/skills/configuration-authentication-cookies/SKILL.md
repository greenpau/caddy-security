---
name: configuration-authentication-cookies
description: "caddy-security authentication portal cookie Caddyfile configuration. Use when creating, reviewing, or modifying authentication portal cookie directives, cookie domains, paths, lifetimes, SameSite, insecure cookies, guessed or stripped domains, token cookie names, cookie name prefixes, access token cookie validation, or authcrunch cookie defaults."
---

# Configuration Authentication Cookies

## Contract and Sources

Portal cookie statements are collected in `caddyfile_authn.go`. The thin
translation in `caddyfile_authn_cookie.go` preserves legacy Caddy spellings;
`pkg/authn/cookie/parser.NewCookieConfigFromDirectives` in the pinned
AuthCrunch v1.2.5 owns grammar, normalization, duplicates, and validation.
`PortalConfig.ConfigureCookies` installs one complete validated snapshot.
It replaces previous cookie settings, rather than merging individual lines.
Portal construction wires the final access name into its grantor and validator.

Use `configuration-authentication` for portal wiring and
`configuration-authorization` for policies. Upstream source is read-only.

## Set Every Default Name with One Prefix

```caddyfile
authentication portal myportal {
    enable identity store localdb
    set cookie name prefix PORTAL
}
```

That one statement covers all eight roles:

| Role | Effective cookie name |
| --- | --- |
| Session ID | `PORTAL_SESSION_ID` |
| Referer/redirect URL | `PORTAL_REDIRECT_URL` |
| Sandbox ID | `PORTAL_SANDBOX_ID` |
| Identity token | `PORTAL_ID_TOKEN` |
| Access token | `PORTAL_ACCESS_TOKEN` |
| Refresh token | `PORTAL_REFRESH_TOKEN` |
| OIDC session ID | `PORTAL_OIDC_SESSION_ID` |
| OIDC request ID | `PORTAL_OIDC_REQUEST_ID` |

`set cookie name prefix portal` preserves the legacy uppercasing behavior.
The shared spelling `cookie prefix PORTAL` preserves the supplied case.
With neither statement, every role uses the same suffix with `AUTHP_`.
For initialized Go configs, call `SetCookieNamePrefix`; assigning
`CookieNamePrefix` directly does not rename already initialized fields.

## Explicit Names and Precedence

Explicit names are complete, literal cookie names. No prefix is added to them.
Keep the naming convention consistent in examples:

```caddyfile
authentication portal myportal {
    enable identity store localdb
    cookie session id name AUTHP_SESSION_ID
    cookie access token name AUTHP_LOGIN_ACCESS
    cookie oidc session id name AUTHP_LOGIN_SESSION
    cookie oidc request id name AUTHP_LOGIN_REQUEST
    cookie refresh token name AUTHP_LOGIN_REFRESH
    cookie referer name AUTHP_LOGIN_REDIRECT
    cookie sandbox id name AUTHP_LOGIN_SANDBOX
    cookie identity token name AUTHP_LOGIN_IDENTITY
}
```

An explicit name wins independently of statement order, including one equal
to an old default. For example, `cookie session id name AUTHP_SESSION_ID`
plus `set cookie name prefix PORTAL` leaves that session name unchanged and
sets all seven omitted names to `PORTAL_<SUFFIX>`.
`cookie access token name LOGIN_ACCESS` is also valid and stays exactly
`LOGIN_ACCESS`; use `AUTHP_LOGIN_ACCESS` when the intended convention is AUTHP.

`redirect url` aliases `referer`; `id token` aliases `identity token`.
Legacy `set <role> cookie name <name>` supports `session_id`, `redirect_url`,
`sandbox_id`, `id_token`, `access_token`, and `refresh_token`.

Each prefix, name (including aliases), and attribute per scope may be set
once. Duplicate statements are errors even when the values agree. Final
names must be valid HTTP cookie names and distinct across all eight roles.
Names may be explicitly unprefixed. `__Host-` and `__Secure-` remain optional
compatibility cases; a name alone does not establish the required attributes.

For enabled [portal token refresh](../configuration-authentication/references/token-refresh.md),
an explicit `token refresh { cookie name ... }` overrides the shared refresh
name before shared-parser collision checks and cookie factory construction.
An override may free the old name for another role; duplicate shared settings
still fail. Deferred refresh also defers cookie parsing, even for literal cookies.
Without that override, the shared name/prefix wins. Disabled refresh does not
rename cookies. Active refresh cookies use the configured portal mount with
host-only, Secure, HttpOnly, SameSite=Lax attributes; the legacy refresh subpath
below only describes retired-cookie cleanup.

### Reserved-Prefix Compatibility

AuthCrunch v1.2.3 preserves `Secure`, `HttpOnly`, `SameSite`, domain, and path
on matching deletion cookies, with a past expiry and `Max-Age=0`.
`__Secure-` names require secure cookies. `__Host-` additionally requires no
Domain and `Path=/`; a configured access path or domain must respect that scope.
Prefix checks are case-insensitive.

Access and session cookies can use explicit `__Host-` names with a portal
mounted at `/auth`, because their configured/default paths can remain `/`:

```caddyfile
cookie session id name __Host-SESSION
cookie access token name __Host-ACCESS
cookie path /
```

A common `__Host-` prefix also names referer and sandbox cookies, so that portal
must be mounted at `/`. Its identity-cookie role needs a compatible override
because identity cookies use the `/whoami` subpath:

```caddyfile
cookie prefix __Host-PORTAL
cookie identity token name __Secure-PORTAL_ID_TOKEN
```

Static incompatibilities fail configuration. A dynamically inferred non-root
mount with host-prefixed referer/sandbox cookies fails the request with HTTP 500
before issuing portal cookies. The retired refresh-cookie subpath cannot carry
a `__Host-` cookie; upstream omits that legacy tombstone and leaves active refresh
cleanup to its feature runtime. These examples do not enable OIDC or refresh.

## Attributes and Domains

```caddyfile
cookie path /app
cookie lifetime 3600
cookie same site lax
cookie insecure disabled
cookie guess domain disabled
cookie strip domain enabled

cookie domain example.com
cookie domain example.com path /app
cookie domain example.com lifetime 600
cookie domain example.com same site strict
cookie domain example.com insecure disabled
cookie domain example.com strip domain enabled
```

`same site`/`samesite` accepts `lax`, `strict`, or `none`, normalized by the
shared validator. Lifetime is an integer interpreted by the issuing runtime;
use positive seconds for an expiring access cookie. Global and domain settings
are separate scopes. Domain `guess domain` is unsupported. Legacy forms remain:

```caddyfile
cookie guess domain
cookie strip domain
cookie insecure off
cookie example.com path /app
cookie example.com lifetime 600
cookie example.com samesite strict
cookie example.com insecure off
cookie example.com strip domain
```

Legacy `insecure` also accepts `on/off`, `yes/no`, `true/false`, and `1/0`.
Domain `insecure` no longer mutates global or unrelated domain settings.
An explicit domain defaults to secure cookies; global `insecure enabled` alone
does not make an explicit domain insecure. Do not rely on the old parser's
order-dependent propagation of `insecure` across domains.

Domain names are lowercased and a leading dot is removed. Attributes can
create a domain entry without a separate declaration. The first occurrence
sets its sequence; subsequent attributes do not move it. Runtime matching
prefers an exact host, otherwise the last matching suffix in declaration order.
Choose overlapping domains deliberately; this is not automatic longest-suffix
selection. Duplicate normalized domain declarations/settings are rejected.

Host-only cookies are the default. `guess domain` omits public suffixes such as
`fly.dev`. Domain-level `strip domain enabled` keeps the selected domain's
attributes while emitting a host-only cookie.

Access cookies use domain/global path, lifetime, and SameSite settings.
Session cookies use `/`. Referer and sandbox cookies use the portal base path;
identity-token cookies use `<base>/whoami`; legacy refresh cookies use
`<base>/api/refresh_token`. These roles do not all inherit the access path.
OIDC and refresh features own additional, stricter issuance requirements.

## Placeholders and JSON

Caddy `{$ENV}` expansion happens before adaptation. Empty and whitespace-only
arguments are rejected before `cfgutil.EncodeArgs`, which trims trailing empties.
Quoted values retain token boundaries; replacements cannot inject statements.

If any portal cookie statement contains a runtime placeholder or secret lookup,
the entire collection is retained as `security.portal_cookie_directives`, keyed
by portal name. Provisioning expands each argument, translates legacy syntax,
and parses/applies the complete snapshot once. All cookie statements for that
portal are deferred together, so duplicate aliases, colliding resolved names,
and domains that resolve to the same value are checked together. Deferred
validation happens during provisioning; adaptation alone cannot validate it.

Preserve argument values through every encode/decode step, including trailing
tabs and Unicode whitespace. The shared CSV codec trims record-edge whitespace;
use the lossless directive encoder so an invalid cookie name cannot become valid
before validation or be hidden by an enabled refresh-name override. Resolve into
tokens and translate legacy syntax before re-encoding, with no lossy intermediate
statement. Reject CR/LF in saved statements before decoding: the decoder consumes
one record and would otherwise ignore subsequent settings. Replacements must
also reject empty, multiline, NUL and invalid UTF-8 arguments before encoding.

The deferred snapshot replaces any typed `cookie_config` supplied for that
portal in JSON. Unknown or ambiguous portal references fail. Literal-only
Caddyfiles emit typed `cookie_config` directly. JSON roundtrips preserve both
forms. Existing typed JSON supports runtime replacement of path/domain fields;
use the deferred statement collection for runtime names and prefixes.
Resolved path values remain literal, including braces or spaces, in both legacy
and shared syntax. Typed JSON domain maps are rebuilt once; two entries resolving
to the same key fail instead of silently replacing one domain's settings.

## Coordinate Gatekeepers Explicitly

For the prefix-only portal above:

```caddyfile
authorization policy app_policy {
    crypto key verify {env.JWT_SHARED_KEY}
    set session_id cookie name PORTAL_SESSION_ID
    set access_token cookie name PORTAL_ACCESS_TOKEN
    set token sources cookie
    allow roles authp/user
}
```

Use compatible portal signing keys. For the AUTHP explicit-name example, use:

```caddyfile
set session_id cookie name AUTHP_SESSION_ID
set access_token cookie name AUTHP_LOGIN_ACCESS
```

The Caddy policy parser maps these to `PolicyConfig.SessionIDCookieName` and
`AccessTokenCookieNames`. The session name carries correlation information;
it is not an access credential. Multiple access names can be intentionally
listed on one statement. Explicit access lists replace defaults.

During runtime resolution, absent policy cookie settings become
`AUTHP_SESSION_ID` and `[AUTHP_ACCESS_TOKEN, access_token, jwt_access_token]`.
This prevents AuthCrunch's server-wide portal-name discovery. Custom portal
names are never implicitly shared across policies, including portals in one
security app. Deployments that relied on automatic discovery must add explicit
policy names. Equal names and signing keys still share credentials by design;
cookie names alone do not isolate trust.

Naming does not enable bearer, Basic, API-key, refresh, or identity-token
credentials. Existing token source settings still apply. AuthCrunch also adds
explicit access names, lowercased, to its named header/query lookup lists;
use `set token sources cookie` when only cookie transport should be accepted.
Policy cookie names can use Caddy `{$ENV}` expansion; typed policy names are
not runtime-replaced.

OAuth `IdentityTokenCookieName` belongs to the upstream identity provider,
which can be shared by portals. A portal prefix never rewrites it. Configure
that provider explicitly when changing its ID-token cookie name; the portal's
identity-cookie role is not an override of the shared provider.

## Validation

- `caddyfile_authn_cookie_test.go`: grammar, legacy translation, all eight prefix
  defaults, order independence, domains, quoted/empty values, duplicates,
  malformed input, runtime replacement, and typed/deferred JSON roundtrips.
- `cookie_policy_test.go`: defaults/overrides, session ID consumption, shared
  provider ownership, and malformed policy settings.
- `cookie_e2e_test.go`: real TLS Caddy login, protected resources, and logout;
  public-suffix-aware jars, host/path boundaries, matching deletion, negative
  credential transports, cross-portal names, literal resolved paths, and rejected
  reloads. Includes explicit secure-prefixed cookies and root-mounted host-prefixed
  cookies, with issuance/deletion checks for Secure, HttpOnly, SameSite, domain,
  path, Max-Age, and expiry. Certificate verification is enabled. These are HTTP
  attribute assertions and jar tests; the jar does not enforce a browser's
  SameSite or reserved-prefix rules.
- `testdata/caddyfile_adapt/testcase_authenticate_with_cookie_parser.*` covers
  complete explicit grammar, `set cookie name prefix PORTAL` alone, reserved
  prefixes, and legacy runtime paths containing literal braces.
  Domain/credentials fixtures retain runtime placeholders and resolved snapshots.

Run focused checks with:

```sh
go test -mod=readonly -race -count=1 -run 'TestPortalCookie|TestPolicyCookie|TestAppCookie|TestCaddyCookiesE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' .
```

`TestCaddyTokenRefreshE2E` and `TestCaddyOIDCProviderE2E` exercise the stricter
refresh/OP cookie scopes, origin checks, rotation, and logout requirements.
The refresh E2E also rejects malformed shared-cookie names and saved multiline
statements during reload, then rotates the original session to verify that the
failed candidate preserved its store. The registered
`testcase_authenticate_with_token_refresh_cookie_whitespace` fixture covers
literal whitespace rejection before a refresh-name override.
