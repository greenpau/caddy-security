# Portal Token Refresh

## Contents

- [Configuration](#configuration)
- [Provider snapshot renewal](#provider-snapshot-renewal)
- [Lifetime interaction](#lifetime-interaction)
- [Body transport](#body-transport)
- [Session and rotation limits](#session-and-rotation-limits)
- [Mounts and cookies](#mounts-and-cookies)
- [Placeholders and JSON](#placeholders-and-json)
- [Runtime ownership](#runtime-ownership)
- [Storage backend boundary](#storage-backend-boundary)
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
one supported attached source. Missing, ambiguous, unattached, LDAP and SAML
realms cannot participate. Never default the refresh realm list to all portal
backends. API-key and native-client distinctions are runtime
authentication/transport contracts, not identity-store capabilities.

The shared parser additionally accepts
`provider revalidation REALM snapshot`, once per distinct OAuth/OIDC realm also
listed in `realms`. The provider's identity-token cookie must be disabled.
Omission does not opt a provider into renewal. Snapshot renewal reuses captured
upstream identity, rechecks current local attachment and portal policy, and
does not redeem upstream refresh tokens or observe upstream logout, disablement
or role changes. Only a fresh upstream login observes those changes; choose a
bounded absolute lifetime accordingly. Modes `userinfo` and `refresh_token`
are unsupported. See [provider snapshot renewal](#provider-snapshot-renewal)
for identity, transport and restart requirements.

`caddyfile_authn_token_refresh.go` forwards encoded body statements to
`pkg/authn/token_refresh/parser.NewTokenRefreshConfigFromDirectives` from the
selected go-authcrunch module. Its result is `*authn.TokenRefreshConfig`, assigned to
`PortalConfig.RefreshTokens` before portal validation. The engine package's Go
identifier is `tokenrefresh`; `authn.RefreshConfig` and `pkg/authn/refresh` are
obsolete. Keep refresh consumer filenames qualified with `token_refresh`.

Use the [qualified operator examples](../../configuration/references/operator-examples.md)
for complete outer Caddyfiles and generated native JSON, including browser/native
transport, two eligible local realms, an unselected realm and combined OP use.

| Setting | Arguments | Enabled default |
| --- | --- | --- |
| `enabled` / `disabled` | None; mutually exclusive | Enabled when block exists |
| `realms` | One or more realm names | Required |
| `provider revalidation` | One selected OAuth/OIDC realm and `snapshot`; repeat for distinct realms | No provider mode |
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
state arguments exist. Except for distinct provider revalidation realms, each
setting occurs once, including through imports;
repeating even identical values fails. Reject duplicate blocks, extra header
values, nested blocks, unknown fields, missing/empty arguments and integer
overflow. Lists belong on one line. A missing block stays nil and access-only;
an empty block is invalid. A standalone `disabled` opts out, with no required
origin, mount or realms; its explicit settings still require valid grammar.
There are no distributed-store directives.

## Provider Snapshot Renewal

Select the provider realm explicitly in both statements:

```caddyfile
token refresh {
    realms corporate
    provider revalidation corporate snapshot
    public origin https://auth.example.com
    base path /auth
}
```

The portal must enable exactly one OAuth/OIDC provider with realm `corporate`;
its identity-token cookie must be disabled. A local store is not a provider,
and LDAP/SAML cannot use snapshot mode. The callback uses the provider's configured upstream validation before a family
can be issued; keep nonce, PKCE and signature verification enabled. Snapshot mode
does not override weakened provider settings. An
access JWT or provider-supplied session claim cannot establish that evidence.

Renewal preserves the captured upstream subject and claims, original
`auth_time`, actual login methods and family SID. The signed `id` identifies
the attached local account, distinct from the provider subject and family SID.
Provider-supplied authentication methods, timestamps, session identifiers and
credentials are not local proof. Protocol credentials are removed recursively
from the bounded snapshot; no upstream refresh credential is retained for reuse.

Current local attachment and portal transforms are checked on every exchange.
Supported role, disablement, session or required-factor mutations invalidate
older proof: the old family is denied, and fresh login is required. Fresh login
uses the current local roles and factor requirements. Upstream AMR alone cannot
satisfy a local challenge. Renewal can also fail when current request-dependent
portal policy differs from callback policy. External identity does not become
local profile or downstream OP authority merely by obtaining refresh cookies.

Provider callbacks issue cookie-transport families. Enabling body transport for
local native clients does not change external callbacks; copying a refresh
cookie into a native request fails. Replay, logout, deadlines and fresh-login
replacement use the same family lifecycle as local refresh. Stateless access
JWTs retain their own expiration and authorization behavior after family logout.

To retain a provider family across a complete Caddy stop/start, enable root
[state](../../configuration-state/SKILL.md), select an explicit file-backed local
attachment with `attach to local identity store NAME`, and preserve that database
and the same effective security configuration. Root snapshots alone cannot
restore implicit provider-private memory identities. Accepted configuration
changes retire prior authority; restoring the earlier configuration does not
revive families in the same observed state history. Restart renewal makes no
upstream token/userinfo call; normal startup discovery and JWKS loading remain.

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

`max sessions` counts live refresh families in one portal's refresh store,
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
existing live families. Separate portal runtimes have separate limits. Without
the root `state` block, runtime replacement or restart discards their stores and
requires login again. With persistence enabled, completed families and their
deadlines survive a complete stop/start with the same storage and configuration;
overlapping persistent reload is rejected. See [runtime ownership](#runtime-ownership).

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

Cross-device approval records refer only to a committed local refresh family.
AuthCrunch's `tokenrefresh.Manager.ValidateSession` and optional store
`SessionValidator` check binding, revocation, idle/absolute deadlines and store
health without rotating credentials or altering replay history. The family ID
is not authentication evidence, and custom access/provider `sid` claims must
not become family references. Unsupported stores fail closed. Caddy delegates
these checks: normal rotation keeps approval valid, while replay, replacement
and logout (including without an access cookie) invalidate it. See
[cross-device identity and lifecycle](../../configuration-authentication-cross-device/SKILL.md#identity-cancellation-and-lifecycle).

Mount the portal without stripping its prefix:

```caddyfile
auth.example.com {
    @portal path /auth /auth/*
    route @portal {
        authenticate with myportal at /auth
    }
}
```

For root mounting, use `base path /` and serve
`authenticate with myportal at /` at the site's root. The configured HTTPS public origin must match the request's
actual origin, including any nondefault port. A mount/origin mismatch fails
refresh login and requests; Caddy cannot infer an intended public origin from
an untrusted request. Preserve the original URL through the portal handler,
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
realm strings and each `provider_revalidation` entry's `realm` and `mode` support
runtime replacement. When enabled, the resolved mode must still be exactly
`snapshot`; realm collisions after resolution fail validation. Disabled native
settings retain ignored semantics; deferred statements still require valid grammar. JSON booleans/numbers retain their
types: the readable state grammar is specific to the Caddyfile block.
A portal cannot supply both a typed refresh config and deferred refresh body.
Unknown/duplicate snapshot targets, malformed statements and null/empty bodies
fail restoration. Runtime resolution must not rewrite the declarative snapshot
or expand substituted values twice.

## Runtime Ownership

AuthCrunch owns the bounded session/rotation store, credential hashing,
local password/MFA evidence, signing, fresh identity checks, replay revocation,
and cookie responses. Caddy configures the portal and owns admission/draining
around the shared AuthCrunch runtime.

Without a root `state` block, refresh state is volatile and does not survive
runtime replacement or restart. Use
[configuration-state](../../configuration-state/SKILL.md) to configure optional
durable state and its required stop/start deployment boundary. With that opt-in,
completed browser/native families, absolute and idle deadlines, spent-token
replay history, and successful revocations survive restart. Pending login
checkpoints do not. Restart never extends a deadline or makes an uncertain
rotation safe to retry. Configuration changes can invalidate retained authority;
follow the state skill's binding and recovery rules.

A new independent login at capacity returns 503. Exhausting a family's rotation
limit revokes that family and reclaims capacity. Replaying a spent refresh token
revokes the whole family. Serialize rotations and do not automatically retry an
ambiguous refresh response. API-key, Basic, SAML, LDAP and unselected upstream
OAuth/OIDC logins remain access-only; native body credentials require explicit
opt-in. Provider snapshot callbacks issue browser cookies, not native body
refresh credentials.

For browser continuation, Web Locks/storage coordination, SID preconditions,
GET confirmation and POST logout, use the
[browser HTTP/UI contract](../../authentication-portal-api/references/browser-refresh.md).

## Storage Backend Boundary

Portal refresh has no configurable storage backend selector. The portal creates
a concrete `tokenrefresh.MemoryStore` and its own manager; neither
`authn.PortalParameters` nor root `ServerOptions` accepts a refresh store.
`TokenRefreshConfig` and the `token refresh` parser likewise expose no database
path or driver. The root's OAuth login-store injection serves pending upstream
login transactions, not portal refresh families.

AuthCrunch's `plugins/session-and-refresh-storage/sqlite` supplies a separate
`Store`, `ReplacementStore` and `SessionValidator` for direct composition through
`tokenrefresh.NewManager`. Its public parser configures that library, not this
portal. Importing it, supplying its JSON fields, or configuring the root `state`
block does not select SQLite. Existing root persistence attaches snapshot records
to the portal's owned memory store; it is a different implementation with the
documented exclusive stop/start boundary.

A host adapter needs a public, pre-publication root/portal injection path first,
including disabled/unknown binding rejection, caller ownership, failed-candidate
cleanup and explicit interaction with root persistence. It must preserve the
portal's identity transaction, current policy checks, staged signing and
publish-after-commit behavior. Do not fork the portal issuer, replace private
fields, or expose a selector that cannot reach the real portal runtime.

Once that boundary exists, acceptance requires actual Caddy TLS login, refresh
and protected requests using the selected store, concurrent rotation and durable
replay across processes/restarts, wrong-binding isolation, identity/MFA changes,
replacement at capacity, cancellation/lock contention, real failed commits,
unavailable storage and reload/cleanup. Uncertain commit must withhold every
staged credential and require fresh authentication without retrying the exchange.
Retain identity epochs and signing keys across restart; a refresh database alone
does not provide them, persist OIDC/OAuth sessions, or establish portal HA.
Library consumer tests and the existing snapshot-persistence E2E do not qualify
this unavailable host adapter.

## Validation

- `caddyfile_authn_token_refresh_test.go`: all fields, defaults/disabled behavior,
  malformed grammar, duplicate/import boundaries, environment and secret
  replacements, saved app snapshots and native JSON restoration; cookie overrides
  before collision validation, including reused names, duplicate rejection and
  exact shared-cookie argument preservation through literals and replacements.
- `caddyfile_authn_token_refresh_provider_test.go` and
  `app_token_refresh_provider_test.go`: provider selection, native/deferred realm
  and mode resolution, exact argument preservation, runtime eligibility and
  immutable immediate/persistent app configuration.
- `TestCaddyProviderRefreshE2E`: actual OAuth callback and cookie renewal,
  captured upstream claims without token/userinfo requests, current local proof
  and request policy, replay, logout, deadlines and transport/authority limits.
  `TestCaddyRuntimeStateE2E/provider_snapshot` adds durable attachment, replay and
  logout across fresh processes, changed/restored configuration retirement, and
  rejection when only an implicit memory identity was available.
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
- `TestCaddyRuntimeStateE2E` in `runtime_state_e2e_test.go`: optional persistent
  browser/native families across fresh processes, replay revocation retained
  across restart, and durable logout. The state skill owns its process, storage
  and reload checks; the ordinary refresh suites above qualify volatile behavior.

Run the focused group and broader repository validation from this checkout:

```sh
go test -mod=readonly -race -count=1 -run 'TestPortalTokenRefresh|TestCaddyTokenRefreshE2E|TestCaddyOIDCProviderE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' .
make test
make build
```

Upstream sources and its refresh-token-implementation skill are read-only
references. Do not run sibling tests or change sibling files to validate this
integration; report upstream defects separately.
