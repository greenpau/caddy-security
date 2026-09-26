---
name: configuration-runtime-resolution
description: "caddy-security runtime replacement guidance for Caddyfile configuration. Use when creating, reviewing, or modifying configs that rely on Caddy replacer placeholders, env placeholders, secrets manager lookups, resolved Caddyfile fixtures, runtime credential resolution, unresolved token checks, or caddyfile_resolve behavior."
---

# Configuration Runtime Resolution

## Purpose

Use this skill when generated Caddyfiles rely on values resolved during
provisioning. Runtime replacement is implemented in `caddyfile_resolve.go` and
tested by `caddyfile_resolve_test.go`.

Keep this skill aligned with `github.com/greenpau/go-authcrunch` config shapes:
some sections preserve raw encoded directive arguments and are revalidated after
replacement, while others are typed structs where only selected fields are
resolved.

## Replacement Forms

Use Caddy replacer placeholders for environment-backed values:

```caddyfile
password {env.SMTP_PASSWORD}
client_secret {env.OIDC_CLIENT_SECRET}
crypto key sign-verify {env.JWT_SHARED_KEY}
```

Use secrets manager lookups for values provided by `security.secrets` modules:

```caddyfile
password "secrets:users/jsmith:password" overwrite
crypto key sign-verify "secrets:access_token:shared_secret"
```

Secret lookup syntax is:

```text
secrets:<secret_id>:<key>
```

The `secret_id` must match the second argument of a `secrets <plugin> <secret_id>`
block, and `<key>` must be returned by that secrets manager.

Secret lookups run after Caddy replacer expansion and must be the entire value.
The parser accepts exactly three colon-separated parts, so the secret key cannot
contain another colon.

## What Gets Resolved

`ResolveRuntimeAppConfig` mutates the authcrunch app config, then calls the
affected authcrunch `Validate` methods so derived configs are rebuilt.
The app supplies a fresh config copy for each runtime; never run resolution on
a serving graph. JSON inputs can omit optional portal UI and cookie settings.
Resolve those fields only when present and leave their defaults to AuthCrunch.
Reject null entries in typed component collections, including nested ACL,
redirect, credential, and registration objects, before calling validators or
constructors. `app_config.go` uses explicit typed validators and generic slice
and map helpers for those checks, following the coding skill's prohibition on
`reflect`. When upstream adds a component collection, extend its typed validator
and unit/E2E coverage. The checks permit omitted optional objects and leave
flexible parameter maps to the resolver. After substitution, decode
local/LDAP/OAuth/SAML parameter maps
into AuthCrunch's exported config types and check decoding errors and null
objects. Some dispatch validators ignore JSON decoding errors; do not let a
partially decoded user or provider config reach construction. Reuse upstream
types and semantic validation instead of maintaining field allowlists here.
Object lists in those maps must contain objects throughout;
do not silently skip a null or scalar entry after the first object. Return field
paths so malformed replacements fail without disrupting the active deployment.
The unit tests in `app_lifecycle_test.go` and actual Caddy reload tests in
`app_lifecycle_e2e_test.go` cover these JSON provisioning cases.

Guard raw instruction argument counts before calling AuthCrunch's dispatch
parsers: a one-token `crypto` statement or messaging/registration `kind` statement
can otherwise panic during provisioning. For crypto, credentials, messaging,
registration and transform instructions, check resolved tokens before `cfgutil.EncodeArgs`,
which trims trailing empty tokens. Reject empty arguments and report the
field/statement index without including secret values.
Keep command semantics in AuthCrunch. Include literal empty tokens and empty
environment replacements in unit and Caddy reload rejection tests, verifying
that the old deployment still authorizes requests.

Resolve these app config areas:

- `state.directory`: replace the original scalar in the private config copy,
  then run the shared state validator without creating files. Whole environment
  and secrets-manager references retain exact token boundaries; unresolved or
  empty replacements fail with a redacted error. See
  [persistent runtime state](../configuration-state/SKILL.md).
- `credentials.raw_credential_configs`, `messaging.raw_configs`, and
  `user_registration.raw_configs`: decode each instruction, replace each
  argument independently, then re-encode it for AuthCrunch validation. A resolved
  value is one argument, including spaces, quotes, and newlines; it must not
  inject instruction syntax. Resolve secret references at the argument level,
  where the command word cannot hide them. Preserve single-token flags such as
  messaging `passwordless`. Invoke these parsing
  validators only when raw instructions are present. Empty sections and typed
  configurations restored without raw instructions are preserved; values in
  those typed sections must already be resolved.
- `identity_stores[].params` and `identity_providers[].params`: recursively
  replace map keys, string values, string lists, lists of maps, and nested lists
  supported by `substitute`; non-string scalar values remain unchanged.
- `sso_providers[]`: replace `entity_id`, `cert_path`, `private_key_path`, and
  each `locations` entry. Do not assume `name` or `driver` is replaced.
- `authentication_portals[]`: replace raw crypto key-store lines,
  user-transformer matcher/action encoded arguments, selected UI strings
  (`logo_url`, `logo_description`, meta fields, `auto_redirect_url`, custom CSS
  and JS paths, template paths, private link titles/links, static asset path,
  content type, and filesystem path), cookie path, cookie domain map keys, and
  per-domain domain/path values.
  Resolve domain-map keys into a fresh map and reject collisions before replacing
  the map; in-place key updates can silently overwrite settings or process a newly
  inserted key twice.
- `authorization_policies[]`: replace raw crypto key-store lines only; the
  subsequent validation rebuilds `crypto_key_store_config`. Pin absent cookie
  names to `AUTHP_SESSION_ID` and the default access-cookie list before server
  construction, preventing implicit cross-portal discovery.

Cookie Caddyfile statements containing runtime placeholders are held separately
in `App.PortalCookieDirectives` (`portal_cookie_directives` in Caddy JSON), keyed
by portal name. After `ResolveRuntimeAppConfig`, app provisioning resolves
that portal's entire statement collection and applies one validated snapshot
through the shared cookie parser and `PortalConfig.ConfigureCookies`. This
supports runtime names, prefixes, domains, and attributes without partially
validating an unresolved cookie config. The deferred snapshot replaces any
existing typed cookie config and is applied after other replacement to avoid expanding substituted
paths a second time. Literal-only statements adapt directly to typed
cookie config. See [cookie configuration](../configuration-authentication-cookies/SKILL.md#placeholders-and-json).
After replacement, legacy translation treats braces in a resolved path as data;
it must not defer that statement again. Keep cookie values as tokens until that
translation and lossless encoding; an intermediate `EncodeArgs` roundtrip can
silently trim an invalid name's trailing whitespace. Reject CR/LF in saved cookie
statements before decoding so additional records cannot hide settings. See the
cookie skill for the exact argument-preservation checks and reload regressions.

Token refresh blocks with runtime references are preserved in
`App.PortalTokenRefreshDirectives` (`portal_token_refresh_directives`). Resolve
each argument once and attach the shared parser's `*authn.TokenRefreshConfig`
before portal validation; do not also supply typed `refresh_tokens` for that
portal. Defer that portal's complete cookie statements too, including literal
ones, until the enabled refresh override is known: collision checks must use
the effective names. Literal refresh blocks need no snapshot. Native JSON origin, base path, cookie
name and individual realm values support replacement. See
[token refresh placeholders](../configuration-authentication/references/token-refresh.md#placeholders-and-json)
for numeric/state values, duplicate checks, and JSON restoration coverage.

OAuth provider statements with runtime references are also retained separately,
in `App.OAuthProviderDirectives` (`oauth_provider_directives` in Caddy JSON).
They pass shared validation during adaptation. App provisioning then resolves
each original argument once and reparses the whole provider, replacing the
adapted Params instead of substituting that already-normalized map. This keeps
Google client-ID suffixes and driver-derived URLs from changing secret lookup
keys. Snapshot names must identify exactly one OAuth provider. Shared duplicate,
state, key-file, and typed-only-field validation remains authoritative after
replacement. Substituted strings are data and are not expanded again.
See the [OAuth reference](../configuration-oauth-providers/references/shared-parser.md#runtime-references)
for boundaries and the unit/TLS E2E coverage. Keep this app-level snapshot when
copying adapted JSON; `ResolveRuntimeAppConfig` alone accepts an AuthCrunch config
and does not carry app-level snapshots.

The route plugins have separate runtime replacement: `authenticate ... with
{env.PORTAL}` and `authorize ... with {env.POLICY}` resolve their portal or
gatekeeper names during plugin provisioning, not in `ResolveRuntimeAppConfig`.

Do not claim every string in `authcrunch.Config` is walked. If a placeholder is
needed in an unsupported typed field, add explicit resolver coverage and a
fixture instead of assuming the existing recursive helper will reach it.

Unsupported app fields currently include portal and policy names, portal enabled
identity store/provider/SSO references, trusted redirect configs, portal role
sets and patterns, most token options, cookie names in typed portal JSON (use deferred cookie
statements instead), authorization policy ACL rules, bypass configs, header injection configs,
auth proxy raw config, auth URL and forbidden URL fields, and access-token or
session-cookie name fields.

## Fixture Pattern

Adapt fixtures may include:

- `<prefix>.Caddyfile` for source configuration.
- `<prefix>.env` for environment variables used by `{env.*}` placeholders.
- `<prefix>.json` for adapted JSON before runtime resolution.
- `<prefix>_resolved.json` for expected JSON after runtime resolution.

`TestResolveRuntimeAppConfig` lists the fixtures that exercise runtime
resolution. It extracts `apps.security.config` from `<prefix>.json`, loads `<prefix>.env`,
runs app-aware resolution (including `apps.security.oauth_provider_directives` and
`apps.security.portal_token_refresh_directives`)
followed by any `apps.security.portal_cookie_directives` snapshot, and compares
the dumped authcrunch config to `<prefix>_resolved.json`.

For fixtures covered by `TestResolveRuntimeAppConfig`, the test fails when
unresolved `{env.` tokens remain. Plain adapt fixtures may still contain
placeholders unless they are also listed in the runtime-resolution test.

## Transform claim templates

Only user-transformer matcher/action arguments preserve `{claims.*}` for the
AuthCrunch runtime. Claim expansion applies to supported action values; ACL
matcher values stay literal. Resolution uses a scoped replacer without mutating the
shared Caddy replacer; other fields still reject unknown placeholders. Resolve
mixed environment/claim arguments and whole-value secret references as single
arguments, then compile the resulting transformer with the shared parser.
Empty replacements must fail before the codec can drop a token and change its
meaning. Reject CR/LF in raw transform instructions before decoding, since the
CSV decoder can discard later records. Shared validation also rejects multiline
resolved transform values. Native JSON transformers receive the same validation.
With refresh or OIDC enabled, or with System API crypto keys, reject `match any`
by its decoded ACL meaning, including quoted and runtime-resolved encodings: the selected upstream
identity checks lack the timestamp that matcher assumes. Use explicit realm
matchers; see the [compatibility restriction](../configuration-authentication-user-transforms/SKILL.md#unconditional-matcher-restriction-in-v133).

`TestPortalTransformRuntimeValues` and `TestPortalTransformRuntimeBoundaries`
cover mixed environment/claim values, quoted secrets, empty/unknown tokens,
replacer isolation and invalid native JSON. The challenges adapt/resolution
fixture and actual Caddy challenge E2E verify claim expansion after login.

## Guidance

Prefer placeholders for secrets in examples intended for real deployment. Use
literal values only in tests or intentionally local examples.

When a generated config includes secret lookups, also include the matching
`secrets <plugin> <secret_id>` blocks or tell the user which external secrets
manager module must provide them.

When adding a new placeholder-bearing field, check the authcrunch struct and
validation path first. Raw encoded directive fields usually need
`cfgutil.DecodeArgs`, replacement of each argument, `cfgutil.EncodeArgs`, and
validation. Typed fields need explicit assignment in `caddyfile_resolve.go`.

`caddyfile_resolve_instructions_test.go` checks encoded credentials, messaging,
and registration values with environment and secret lookups. The credentials
adapt/resolution fixture includes quoted literal and resolved passwords.
The Caddy lifecycle E2E suite loads both kinds of replacement, checks the runtime
values, performs login/authorization, and verifies a missing secret leaves the
old deployment usable.

Use `configuration-secrets` for secrets manager block syntax.
