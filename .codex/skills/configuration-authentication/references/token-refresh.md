# Portal Token Refresh

## Contents

- [Configuration](#configuration)
- [Lifetime interaction](#lifetime-interaction)
- [Body transport](#body-transport)
- [Session and rotation limits](#session-and-rotation-limits)
- [Mounts and cookies](#mounts-and-cookies)
- [Placeholders and JSON](#placeholders-and-json)
- [Runtime ownership](#runtime-ownership)
- [Validation](#validation)

## Configuration

Use one `token refresh` block inside `authentication portal <name>`:

```caddyfile
authentication portal myportal {
    enable identity store employeesdb contractorsdb guestsdb
    crypto key sign-verify {env.JWT_SHARED_KEY}
    token refresh {
        realms employees contractors
        public origin https://auth.example.com
        base path /auth
        body transport disabled
    }
}
```

This enables portal refresh for the two named realms. `guestsdb` may still
provide ordinary access-only login. Each selected realm must identify exactly
one attached local store and no upstream identity provider. Missing, ambiguous,
unattached, LDAP, OAuth, and SAML realms cannot participate. Never default the
refresh realm list to all portal backends. API-key and native-client distinctions
are runtime authentication/transport contracts, not identity-store capabilities.

`caddyfile_authn_token_refresh.go` forwards encoded body statements to
`pkg/authn/token_refresh/parser.NewTokenRefreshConfigFromDirectives` from the
pinned go-authcrunch v1.2.4. Its result is `*authn.TokenRefreshConfig`, assigned to
`PortalConfig.RefreshTokens` before portal validation. The engine package's Go
identifier is `tokenrefresh`; `authn.RefreshConfig` and `pkg/authn/refresh` are
obsolete. Keep refresh consumer filenames qualified with `token_refresh`.

| Setting | Arguments | Enabled default |
| --- | --- | --- |
| `enabled` / `disabled` | None; mutually exclusive | Enabled when block exists |
| `realms` | One or more realm names | Required |
| `public origin` | One canonical HTTPS origin, without path | Required |
| `base path` | One clean absolute mount; `/` for root | Required |
| `cookie name` | One complete cookie name | Inherit shared refresh name |
| `access lifetime` | Integer seconds | 300 |
| `idle timeout` | Integer seconds | 1800 |
| `absolute timeout` | Integer seconds | 28800 |
| `body transport` | `enabled` or `disabled` | Disabled |
| `max sessions` | Integer count | 10000 |
| `max rotations` | Integer count | 1024 |

Omitted or zero integers select library defaults, not unlimited operation.
Enabled durations/counts must be positive;
access and idle lifetimes cannot exceed the absolute lifetime, which is capped
at 30 days. Access issuance is additionally capped by the actual signing key's
lifetime. Durations do not accept suffixes such as `5m`.

Keywords occupy separate tokens. No underscore aliases or `true`/`false`/`0`/`1`
state arguments exist. Each setting occurs once, including through imports;
repeating even identical values fails. Reject duplicate blocks, extra header
values, nested blocks, unknown fields, missing/empty arguments and integer
overflow. Lists belong on one line. A missing block stays nil and access-only;
an empty block is invalid. A standalone `disabled` opts out, with no required
origin, mount or realms; its explicit settings still require valid grammar.
There are no distributed-store directives.

## Lifetime Interaction

`access lifetime` bounds each access token issued by an eligible login or
rotation. It is also capped by the signing key's lifetime and the time remaining
before the family's absolute deadline. A shorter value requires more frequent
renewal to maintain continuous access; it does not shorten access-only logins
from nonparticipating realms or unsupported login kinds.

`idle timeout` sets the refresh credential's deadline at issuance and advances
it on successful rotation. Ordinary authenticated requests and session probes
do not extend that deadline. `absolute timeout` starts at the original
authentication time and never slides with rotation; both the next access token
and the next idle deadline are capped by it. Reaching either refresh deadline
requires a fresh login.

For example, with the default lifetimes and a signing key allowing at least
300 seconds, a login at 12:00 issues access expiring at 12:05, allows refresh until
12:30, and fixes the absolute deadline at 20:00. A successful refresh at 12:20
issues access expiring at 12:25 and moves the idle deadline to 12:50; the absolute
deadline remains 20:00. Access expiry alone does not prevent refresh.

## Body Transport

`body transport disabled` leaves cookie transport available for eligible
browser sessions. With cookie transport, tokens arrive in HttpOnly cookies and
JSON carries metadata without bearer credentials. Refresh requests must pass
the configured origin and required refresh-header checks.

`body transport enabled` additionally permits native clients to request
`refresh_transport: body` at every login checkpoint. These clients send no
Cookie, Origin or Sec-Fetch headers. Login/rotation returns access and refresh
credentials in JSON without cookies, and later refresh/logout requests supply
`refresh_token` in the JSON body. This supports clients that manage their own
credentials instead of a browser cookie jar. Enabling it does not opt ordinary
login requests into body transport or grant arbitrary CORS origins.

Each family is bound to the selected transport: copying a cookie credential
into a native request does not switch it to body transport. The explicit opt-in
and browser-header restrictions keep native delivery separate from browser
cookie and CSRF handling. See the
[portal API transport contract](../../authentication-portal-api/SKILL.md#portal-refresh-transports)
for request details.

## Session and Rotation Limits

`max sessions` counts live refresh families in one portal's in-memory store,
shared across its selected realms and both transports. A family is one login
session and all credentials produced by rotating it. Multiple independent
logins by the same user can consume multiple slots; tabs sharing one family do
not consume extra slots merely by opening. This is neither a per-user quota nor
an HTTP request rate limit.

At capacity, an additional independent login returns 503 without evicting a
live family. Expired families are reclaimed opportunistically during admission;
revocation removes a family and its credential history. A fresh browser login that
presents an existing family with the same portal/origin/mount/transport binding
can replace it atomically, including at capacity. Failed admission preserves
existing live families. Separate portal runtimes have separate limits; runtime
replacement or restart discards their stores and requires login again.

`max rotations` limits successful refresh exchanges per family. The initial
credential is not a rotation: with `max rotations 1`, the first refresh succeeds
and the next attempt revokes the family and returns 401. This releases capacity
and requires fresh authentication even if the idle/absolute deadlines have not
yet elapsed. Lower rotation limits can therefore force earlier reauthentication.

The store retains spent credential hashes for each live family so replay of an
older credential revokes its current descendant. Removing that history while
leaving the family alive would lose replay detection. Together the two limits
bound retained credential hashes to `max sessions * (max rotations + 1)`, plus
session metadata. This is an entry-count bound, not an exact byte budget; raising
both limits raises potential memory use. Zero restores the documented defaults
and cannot disable either bound.

## Mounts and Cookies

Mount the portal without stripping its prefix:

```caddyfile
auth.example.com {
    route /auth/* {
        authenticate with myportal
    }
}
```

For root mounting, use `base path /` and serve `authenticate with myportal` at
the site's root. The configured HTTPS public origin must match the request's
actual origin, including any nondefault port. A mount/origin mismatch fails
refresh login and requests; Caddy cannot infer an intended public origin from
an untrusted request. Preserve the original URL through `Portal.ServeHTTP`,
including refresh endpoints before ordinary access-token gating. Do not use
`handle_path` to strip the mount or mint authentication evidence in middleware.

When an OIDC provider is also enabled, its issuer must be exactly the refresh
origin plus mount (omit the root slash for the OIDC issuer). The library rejects
incompatible enabled configurations at construction. Portal refresh does not
add OIDC refresh grants or change upstream identity-provider refresh behavior.

The shared `cookie prefix` and `cookie refresh token name` apply unless enabled
refresh explicitly sets `cookie name`. Caddy applies that override before the
shared cookie parser checks collisions; the library also applies it before
cookie factory construction. Another cookie may therefore reuse the old refresh
name if the final names are distinct. Keep every shared cookie statement when
applying the override so duplicate settings and malformed names still fail.
Disabled refresh cannot rename a cookie or repair a collision. Keep all active
cookie purposes distinct, including OIDC session/request cookies.

Refresh cookies remain host-only, Secure, HttpOnly, SameSite=Lax, with the
configured refresh base path. Their attributes and lifetime do not inherit
ordinary access-cookie domain/path/insecure settings. `__Host-` refresh names
require a root mount. Use the shared cookie skill for ordinary cookie settings
and the [portal API skill](../../authentication-portal-api/SKILL.md#portal-refresh-transports)
for refresh, rotation, and logout requests.

## Placeholders and JSON

Caddy's `{$ENV}` substitution runs during adaptation. Bodies containing runtime
`{env.*}` or `secrets:<manager>:<key>` values are preserved, keyed by portal name,
in `App.PortalTokenRefreshDirectives` / `portal_token_refresh_directives`.
Keep the complete app snapshot when saving adapted JSON. Provisioning resolves
each argument once and then calls the shared parser before portal validation.
Numeric and state placeholders are supported. A replacement remains one argument;
it cannot inject a realm list or another setting. Empty replacements fail.
Deferred semantic/duplicate-setting errors are rejected during provisioning.
When refresh is deferred, retain the complete cookie snapshot too, even without
cookie placeholders. Resolve refresh before parsing that snapshot so collisions
are checked against the effective cookie names, independent of directive order.

Literal blocks adapt directly to `config.authentication_portals[].refresh_tokens`.
Native JSON retains that typed form; origin, base path, cookie name and individual
realm strings support runtime replacement. JSON booleans/numbers retain their
types: the readable state grammar is specific to the Caddyfile block.
A portal cannot supply both a typed refresh config and deferred refresh body.
Unknown/duplicate snapshot targets, malformed statements and null/empty bodies
fail restoration. Runtime resolution must not rewrite the declarative snapshot
or expand substituted values twice.

## Runtime Ownership

AuthCrunch owns the bounded in-memory session/rotation store, credential hashing,
local password/MFA evidence, signing, fresh identity checks, replay revocation,
and cookie responses. State is process-local and does not survive replacement
or restart. Caddy only configures and delegates to the portal.

A new independent login at capacity returns 503. Exhausting a family's rotation
limit revokes that family and reclaims capacity. Replaying a spent refresh token
revokes the whole family. Serialize rotations and do not automatically retry an
ambiguous refresh response. API-key, Basic, upstream OAuth/OIDC/SAML, and LDAP
logins remain access-only; native body credentials require explicit opt-in.

## Validation

- `caddyfile_authn_token_refresh_test.go`: all fields, defaults/disabled behavior,
  malformed grammar, duplicate/import boundaries, environment and secret
  replacements, saved app snapshots and native JSON restoration; cookie overrides
  before collision validation, including reused names, duplicate rejection and
  exact shared-cookie argument preservation through literals and replacements.
- `testcase_authenticate_with_token_refresh.*`: registered Caddy adaptation and
  runtime-resolution fixtures, including zero defaults and deferred values.
- `TestCaddyTokenRefreshE2E` in `token_refresh_e2e_test.go`: actual verified Caddy
  TLS, parsed root/nested mounts, real password challenges, two selected realms
  and an unselected realm, cookie inheritance/overrides, access and signing-key
  lifetime caps, rotation/replay, body opt-in/off, capacity limits, fresh browser
  replacement at capacity across selected realms, logout, unsupported realms,
  cookie collisions and origin/mount mismatch rejection. Invalid shared-cookie
  values and saved multiline statements must fail reload while the original
  family remains usable for rotation.
- `testcase_authenticate_with_token_refresh_cookie_whitespace.*`: registered
  rejection fixture proving a refresh override cannot conceal an invalid shared
  cookie name by trimming its trailing tab.
- `TestCaddyOIDCProviderE2E`: parsed refresh configuration coexisting with the
  OP, rejected origin/mount mismatches, and browser logout revoking OP grants.

Run the focused group and broader repository validation from this checkout:

```sh
go test -mod=readonly -race -count=1 -run 'TestPortalTokenRefresh|TestCaddyTokenRefreshE2E|TestCaddyOIDCProviderE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' .
make test
make build
```

Upstream sources and its refresh-token-implementation skill are read-only
references. Do not run sibling tests or change sibling files to validate this
integration; report upstream defects separately.
