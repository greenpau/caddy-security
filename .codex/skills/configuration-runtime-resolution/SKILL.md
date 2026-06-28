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

Resolve these app config areas:

- `credentials.raw_credential_configs`, `messaging.raw_configs`, and
  `user_registration.raw_configs`: replace each raw argument string, then let
  authcrunch parse the raw directives during validation.
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
- `authorization_policies[]`: replace raw crypto key-store lines only; the
  subsequent validation rebuilds `crypto_key_store_config`.

The route plugins have separate runtime replacement: `authenticate ... with
{env.PORTAL}` and `authorize ... with {env.POLICY}` resolve their portal or
gatekeeper names during plugin provisioning, not in `ResolveRuntimeAppConfig`.

Do not claim every string in `authcrunch.Config` is walked. If a placeholder is
needed in an unsupported typed field, add explicit resolver coverage and a
fixture instead of assuming the existing recursive helper will reach it.

Unsupported app fields currently include portal and policy names, portal enabled
identity store/provider/SSO references, trusted redirect configs, portal role
sets and patterns, most token options, cookie names set with `set ... cookie
name`, authorization policy ACL rules, bypass configs, header injection configs,
auth proxy raw config, auth URL and forbidden URL fields, and access-token or
session-cookie name fields.

## Fixture Pattern

Adapt fixtures may include:

- `<prefix>.Caddyfile` for source configuration.
- `<prefix>.env` for environment variables used by `{env.*}` placeholders.
- `<prefix>.json` for adapted JSON before runtime resolution.
- `<prefix>_resolved.json` for expected JSON after runtime resolution.

`TestResolveRuntimeAppConfig` lists the fixtures that exercise runtime
resolution. It extracts the nested `apps.http.servers...security.config`
object from `<prefix>.json`, loads `<prefix>.env`, runs resolution, and compares
the dumped authcrunch config to `<prefix>_resolved.json`.

For fixtures covered by `TestResolveRuntimeAppConfig`, the test fails when
unresolved `{env.` tokens remain. Plain adapt fixtures may still contain
placeholders unless they are also listed in the runtime-resolution test.

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

Use `configuration-secrets` for secrets manager block syntax.
