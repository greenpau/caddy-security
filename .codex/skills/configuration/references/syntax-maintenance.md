# Caddyfile Syntax Maintenance

## Contents

- [When to audit](#when-to-audit)
- [Establish the selected implementation](#establish-the-selected-implementation)
- [Grammar ownership](#grammar-ownership)
- [Inventory and update](#inventory-and-update)
- [Validate at the right layer](#validate-at-the-right-layer)
- [Known boundaries](#known-boundaries)

## When to Audit

Audit syntax when changing a Caddyfile parser, upgrading Caddy/go-authcrunch,
selecting a local dependency replacement, updating examples, or porting an
upstream configuration skill. A shared parser can expose new grammar without
any change to a Caddy switch statement. Keep that grammar documented here.

The configuration domain skill owns its grammar and examples. Go syntax
comments provide the nearby implementation reference. This document owns the
cross-domain audit procedure; avoid copying full grammar tables into it.

## Establish the Selected Implementation

Run from the caddy-security root:

```sh
go list -m -json github.com/caddyserver/caddy/v2 github.com/greenpau/go-authcrunch
```

Read `Version`, `Dir`, and any `Replace` entry, alongside `go.mod` and `go.work`
when present. Source references to `pkg/...` below are relative to the selected
go-authcrunch module. Read the sibling `../go-authcrunch` and its module skills
for newer contracts, but distinguish them from the version used by this build.
Never run sibling tests, modify its source/Git state, or generate files there.

Follow the whole path: Caddy tokenization and header/block handling → local
translation or raw encoding → upstream parser → shared dispatcher → typed
validation → runtime consumer. A field can be recognized by one layer and
rejected or deferred by the next. Record the layer and the selected version
when documenting a restriction. Do not infer grammar from JSON fields alone.

## Grammar Ownership

| Surface | Caddy owner | Selected upstream owner / next validation |
| --- | --- | --- |
| Global `security` and child headers | `caddyfile.go`, `caddyfile_identity.go`, `caddyfile_user.go` | `Config.Add*` methods and `Config.Validate` |
| HTTP `authenticate` / `authorize` | `plugin_authn.go`, `plugin_authz.go` | Caddy route matching; provisioned portal/policy |
| Portal body and backend enablement | `caddyfile_authn.go`, `caddyfile_authn_misc.go` | `pkg/authn/config.go`, redirect validation, backend attachment |
| Portal cookies | `caddyfile_authn_cookie.go` | `pkg/authn/cookie/parser`, `PortalConfig.ConfigureCookies` |
| Portal admin API and private-key export | `caddyfile_authn_admin_api.go` | `pkg/authn/admin_api/parser`, `PortalConfig.ConfigureAdminAPI` |
| Portal UI | `caddyfile_authn_ui.go` | `pkg/authn/ui`, `pkg/translate`, portal asset/template loading |
| User transforms | `caddyfile_authn_transform.go` | `pkg/acl`, `pkg/authn/transformer` |
| Portal/policy crypto | `caddyfile_authn_crypto.go`, `caddyfile_authz_crypto.go` | `pkg/kms/crypto_keystore_config.go`, `crypto_key_config.go`, `crypto_key.go` |
| Policy ACL rules and shortcuts | `caddyfile_authz_acl.go`, `caddyfile_authz_acl_shortcuts.go` | `pkg/acl` conditions, fields, actions |
| Policy options, bypass, headers, auth proxy | `caddyfile_authz_misc.go`, `caddyfile_authz_bypass.go`, `caddyfile_authz_inject.go` | `pkg/authz`, `pkg/authz/bypass`, `pkg/authz/injector`, `pkg/authproxy` |
| Local/LDAP stores and static users | `caddyfile_identity_store.go` | `pkg/ids/config.go`, `pkg/ids/local`, `pkg/ids/ldap`, `pkg/authn/icons` |
| Upstream OAuth | `caddyfile_identity_provider_oauth.go` | `pkg/idp/parser/oauth.go` → `pkg/idp/oauth/parser` → shared `pkg/idp/config.go`; runtime `pkg/idp/oauth` |
| Named OAuth applications | `caddyfile_oauth_application.go`, collected first in `caddyfile.go` | `pkg/oidc/parser/application.go`, `client.go` → `Config.AddOAuthApplication`; explicit or stored credentials, repeatable single-value `redirect_uri`, no generation during adaptation |
| `oauth registration store` | `caddyfile_oauth_registration_store.go`, `oauth_registration_config.go`, `command_provision.go` | Host-owned immutable revisions, `pkg/oidc/provisioning.go` only on explicit creation |
| Portal OIDC provider | `caddyfile_authn_oidc.go`, `caddyfile_authn.go`, `oidc_config.go` | `Config.ConfigureOIDCProvider` → `pkg/oidc/parser/provider.go` → `PortalConfig.ConfigureOIDCProvider`; collect all applications first, attach before portal validation, reject overlapping issuer mounts across portals |
| Upstream SAML | `caddyfile_identity_provider.go` | `pkg/idp/config.go`, `pkg/idp/saml` |
| SSO apps | `caddyfile_sso_provider.go` | `pkg/sso` |
| Credentials | `caddyfile_credentials.go` | `pkg/credentials` |
| Messaging | `caddyfile_messaging.go` | `pkg/messaging/email_provider.go`, `file_provider.go` |
| User registration | `caddyfile_user_registration.go` | `pkg/registry/local_user_registry.go`, domain rules |
| Secrets manager body | `caddyfile_secrets.go` | Registered external `security.secrets.<module>` parser |
| Runtime placeholders | `caddyfile_resolve.go`, `app_config.go`, deferred cookie collection | Selected typed validators and raw instruction parsers; see the runtime-resolution skill |

## Inventory and Update

1. Inventory tracked standalone files with
   `rg --files -g '*Caddyfile*' -g '!vendor/**'`. Inspect `assets/config`,
   adaptation fixtures and their registered test cases, parser `Syntax:`
   comments, inline test snippets, and `caddyfile` fences in configuration
   skills/references. Include commented examples users might uncomment.
2. Classify each as a runnable configuration, contextual fragment, syntax
   catalogue, legacy compatibility test, or intentional rejection. Preserve
   the last two categories and their expected behavior.
3. Trace every affected header and subdirective through the ownership table.
   For forwarded bodies, inventory upstream scalar/list/state fields, aliases,
   argument counts, repetition and duplicate handling, defaults, driver
   restrictions, key formats, and parser-time I/O. Compare upstream skills with
   implementation; neither an old Caddy comment nor a newer sibling document
   alone establishes support in the selected build. When a shared parser applies
   defaults, test runtime references as well as literals: derived URLs and
   credential suffixes must not modify a secret key before lookup.
4. Update Go comments and the owning domain skill together. Include all exposed
   fields, or link to the precise delegated grammar and a complete domain
   reference. Keep recognized-but-restricted forms visible, with the rejecting
   layer and version. Keep unsupported typed-only fields distinct from usable
   Caddy syntax; never filter them away to make validation pass.
5. Use required `<value>` / `<a|b>`, optional `[value]`, and repetition `...`
   consistently. Multiword argument values need quoting; multiword keywords
   must remain separate tokens when the shared parser requires it. State
   whether repetitions append, replace, or fail, including aliases across an
   entire block. A syntax catalogue lists alternatives, not a configuration
   that should enable every feature simultaneously.
6. In standalone examples, place `security` inside outer global `{ ... }`
   braces and HTTP directives inside site/routes. Label smaller examples by
   their enclosing scope. Keep portal/provider names, callback paths, signing
   and verification keys, and explicit policy cookie names coordinated.
   Preserve functioning legacy aliases in compatibility tests; prefer shared
   canonical forms in new runnable examples without silently changing behavior.
7. Update `.json` and `_resolved.json` expectations only for intentional output
   changes. Keep documentation in the owning skill, not a new docs directory.

## Validate at the Right Layer

Use [testing-and-ci](../../testing-and-ci/SKILL.md) and
[scripts-and-automation](../../scripts-and-automation/SKILL.md) for commands:

```sh
make build
bin/authcrunch adapt --adapter caddyfile --config assets/config/Caddyfile
go test -mod=readonly -run 'TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' .
```

Enumerate and adapt **every** standalone file in the inventory, not just the
example above. Keep audit output under `tmp/` in this repository. Adapt output
can include configuration secrets; use synthetic values and do not publish it.
For fragments, use temporary enclosing blocks and synthetic backend references.
Do not treat placeholder notation or explicitly invalid examples as runnable.

Adaptation checks only the validation reached by the adapter. It can accept
raw crypto/messaging/registration instructions whose deeper parser runs during
resolution. Use focused typed/shared-parser validation and existing resolution
fixtures for those bodies; successful adaptation alone does not prove issuance,
provider discovery, key loading, or login. Code changes still require the unit,
adaptation, and actual Caddy E2E coverage specified by `testing-and-ci`.

Use isolated local resources for runtime checks. Do not start workers or fetch
provider discovery to establish parsing support. OAuth parsing may validate
static PEM files; custom HTML header parsing reads its file. External secrets
plugins may perform their own I/O. Inspect those paths before choosing checks.
Never require disabled TLS, nonce, PKCE, or signature checks for a syntax audit.

Known fixture outcomes: `testcase_authenticate_malformed`,
`testcase_authenticate_with_admin_api_malformed`,
`testcase_authenticate_with_oauth_icon_malformed`, and
`testcase_authenticate_with_redirect_trust_malformed`,
`testcase_security_oauth_application_boundary_malformed`,
`testcase_security_oauth_application_enclosing_malformed`,
`testcase_security_oauth_application_header_malformed`, and
`testcase_security_oauth_application_empty` intentionally fail adaptation;
`testcase_security_with_secrets` requires an external module absent from the
normal test binary; `testcase_authenticate_malformed_replacement` adapts but
fails runtime resolution. Check test registrations if these outcomes change.

Run the skill-creator validator for each changed skill, verify relative links
and `agents/openai.yaml`, then format changed Go comments and Caddyfiles.
Run `make license` as required by the coding skill and inspect its diff.
Summarize the inventory, corrections, validation performed, and remaining
restrictions without claiming that parsing tests prove runtime behavior.

## Known Boundaries

Recheck these against the selected implementation when dependencies change.
The following were verified with go-authcrunch v1.2.3:

- OAuth `logout_url <logout_url>` (also `logout url <logout_url>`) exists in
  the typed field parser but is excluded from the shared OAuth allowlist in
  `pkg/idp/config.go`. The Caddy adapter forwards it and fails validation.
  `enable logout` / `logout enabled` is a separate supported setting. See the
  [OAuth grammar inventory](../../configuration-oauth-providers/references/shared-parser.md).
- Upstream OAuth configuration belongs to `pkg/idp`, not downstream `pkg/oidc`.
  KMS `crypto` keys and upstream OAuth `jwks key` pins also have different
  loaders: KMS accepts RSA/EC/Ed25519 PEM; OAuth static pins accept RSA/Ed25519,
  while OAuth EC keys retain discovery support.
- KMS auto-generation supports `ES512`, `EdDSA`, and `Ed25519`. Do not retain
  the old assertion that EdDSA material is unsupported. Direct key values are
  HMAC secrets; PEM input requires the appropriate file/env source form.
- Local/LDAP `fallback role` / `fallback roles` is recognized by the Caddy
  parser, but its current slice drops the first supplied role. Keep the defect
  documented; a syntax refresh must not disguise it with a dummy argument.
  Fixing the mapping requires a separate behavior change and coverage here.
- Transform collection rewrites bare `match` to `exact match` and classifies
  lines by a `match` token. Not all upstream ACL conditions are exposed as
  transform matchers. User-database challenge fields do not automatically
  create Caddyfile user directives.
- Portal `ui logo url` / `logo description` are valid; JSON field spellings
  `logo_url` / `logo_description` are not UI directives. Registration attaches
  through the global registry's identity store, not `enable user registration`.
- Messaging file providers use `root_dir` and require `sender`. Registration
  `admin email` (alias `admin emails`) takes exactly one address per line;
  repeating it replaces the prior address. SSO apps require `cert`, a private
  key, and a supported driver at validation; Caddy requires a location even
  for disabled SSO definitions.
