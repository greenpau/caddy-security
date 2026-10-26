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
rejected or deferred by the next. Record the layer and selected version in the
audit evidence under `tmp/`; keep skill guidance version-neutral. Do not infer
grammar from JSON fields alone.

Caddy treats quoted braces as literal tokens. Qualify both sides of that
contract: preserve literal brace arguments and following declarations, while
requiring unquoted block delimiters and rejecting missing owned closing braces.
Direct dispenser tests and the public adapter exercise different boundaries;
do not mistake a missing outer Caddy global brace for a missing `security` or
portal brace. Keep source context and credential redaction when diagnostics
change with the selected host parser.

## Grammar Ownership

| Surface | Caddy owner | Selected upstream owner / next validation |
| --- | --- | --- |
| Global `security` and child headers | `caddyfile.go`, `caddyfile_identity.go`, `caddyfile_user.go` | `Config.Add*` methods and `Config.Validate` |
| Root diagnostic `logging` | `caddyfile_logging.go` | `pkg/logging/parser` → `Config.Logging`; `NewServer` filters components, not Caddy's separate authentication logger |
| Root runtime `state` | `caddyfile_state.go`, `caddyfile_resolve.go` | `pkg/state/parser` → `Config.State`; initialization belongs to `NewServer` in `App.Start` |
| HTTP `authenticate` / `authorize` | `plugin_authn.go`, `app_portal_mounts.go`, `plugin_authz.go` | Caddy route matching; optional literal `at <mount>` uses `pkg/portalpath.Validate` and `Portal.ServeHTTPAt`; omitted mounts retain inference |
| Portal body and backend enablement | `caddyfile_authn.go`, `caddyfile_authn_misc.go` | `pkg/authn/config.go`, redirect validation, backend attachment |
| Portal cookies | `caddyfile_authn_cookie.go` | `pkg/authn/cookie/parser`, `PortalConfig.ConfigureCookies` |
| Named refresh storage | `caddyfile_refresh_store.go`, `plugins/session-and-refresh-storage-sqlite/plugin.go`, `app_refresh_stores.go` | Public `plugins/session-and-refresh-storage/sqlite/parser` complete-body grammar; immutable factory and core `ExternalStoreConfig`/`ManagedStore` binding; [storage contract](../../configuration-authentication/references/refresh-storage.md) |
| Portal token refresh | `caddyfile_authn_token_refresh.go`, `caddyfile_resolve_token_refresh.go` | `pkg/authn/token_refresh/parser` → `authn.TokenRefreshConfig`; attach before validation, then library cookie factory and selected local/provider-realm checks |
| Portal admin API and private-key export | `caddyfile_authn_admin_api.go` | `pkg/authn/admin_api/parser`, `PortalConfig.ConfigureAdminAPI` |
| Portal Documents API | `caddyfile_authn_documents.go`, `caddyfile_resolve_documents.go` | `pkg/authn/documents/parser.NewDocumentsAPIConfigFromDirectives` → `PortalConfig.ConfigureDocumentsAPI`; flat enable/storage/limit statements, deferred values before validation, independent API flags; see [Documents configuration](../../configuration-authentication/references/documents.md) for realm, mount and storage boundaries |
| Portal UI | `caddyfile_authn_ui.go` | `pkg/authn/ui`, `pkg/translate`, portal asset/template loading |
| User transforms | `caddyfile_authn_transform.go` | `pkg/authn/transformer/parser`, `pkg/authchal/parser`, `pkg/acl`, transformer runtime |
| Named access signers and consumer profiles | `caddyfile_access_signer.go`, `caddyfile_access_token_profile.go`, `caddyfile_resolve_access_tokens.go` | `plugins/cryptographic-signing/rsapss/parser` and `pkg/kms/parser`; host owns block/selection syntax and once-only deferred values, core owns strict profile semantics |
| Portal/policy crypto | `caddyfile_authn_crypto.go`, `caddyfile_authz_crypto.go` | `pkg/kms/crypto_keystore_config.go`, `crypto_key_config.go`, `crypto_key.go` |
| Policy ACL fields, rules and shortcuts | `caddyfile_authz_acl.go`, `caddyfile_authz_acl_shortcuts.go` | `pkg/acl/parser.NewACLFieldConfigFromDirectives` → one `PolicyConfig.ConfigureAccessListFields` call before rule compilation; `pkg/acl` conditions/actions |
| Static claims enrichment | `caddyfile_authz_enrichment.go`, `plugins/claims-enrichment-static/plugin.go` | `pkg/authz/enrichment/parser`, `plugins/claims-enrichment/static/parser`; host checks source, contract, age and requested types |
| HTTP JSON external authorization | `caddyfile_authz_external.go`, `plugins/external-authorization-httpjson/plugin.go` | `pkg/authz/external/parser`, `plugins/external-authorization/httpjson/parser`; host owns TLS files/transport and attaches `external.New` before publication |
| Direct policy OAuth | `caddyfile_authz.go`, `plugin_authorization.go` | `pkg/authz/oauth/parser` → `PolicyConfig.ConfigureOAuth`; route handler preserves authorization, bypass and handled responses |
| Policy options, bypass, headers, auth proxy | `caddyfile_authz_misc.go`, `caddyfile_authz_bypass.go`, `caddyfile_authz_inject.go` | `pkg/authz`, `pkg/authz/bypass`, `pkg/authz/injector`, `pkg/authproxy` |
| Consul password identities, tickets and refresh | `plugins/identity-stores-consul`, `plugins/identity-providers-consul`, `plugins/session-and-refresh-storage-consul` | Host flat parsers and `internal/consulstate`; public typed core consumers and unchanged root/local-attachment boundaries; [Consul contract](../../configuration-state/references/consul-companions.md) |
| SQLite password identities | `caddyfile_identity_backend.go`, `plugins/identity-stores-sqlite/plugin.go` | `plugins/identity-stores/sqlite/parser`; `identity store sqlite <name>` selects literal typed config and named portal injection |
| SQLite ticket providers | `caddyfile_identity_backend.go`, `plugins/identity-providers-sqlite/plugin.go` | `plugins/identity-providers/sqlite/parser`; `identity provider sqlite <name>` binds literal configuration and an optional copied attachment through root provider injection |
| External account attachments | `caddyfile_identity_attachment.go`, SAML/LDAP provider/store parsers, OAuth shared parser, SQLite ticket module | `pkg/identity/attachment/parser`; complete single `attach to local identity store <name>` clause, exact target and root-owned binding; [attached identities](../../configuration-identity-stores/references/connected-accounts.md) owns selection and continuity |
| Local/LDAP stores and static users | `caddyfile_identity_store.go` | `pkg/ids/config.go`, `pkg/ids/local`, `pkg/ids/ldap`, `pkg/authn/icons` |
| Upstream OAuth | `caddyfile_identity_provider_oauth.go` | `pkg/idp/parser/oauth.go` → `pkg/idp/oauth/parser` → shared `pkg/idp/config.go`; runtime `pkg/idp/oauth` |
| OAuth pending-login storage | `caddyfile_oauth_login_store.go`, `plugins/oauth-login-storage-{sqlite,consul}/plugin.go` | SQLite delegates to `plugins/oauth-login-storage/sqlite/parser`; Consul owns its optional flat body and borrows configured Caddy storage. Host owns exact named headers; existing provider parser owns `login store NAME namespace NAMESPACE` |
| Named OAuth applications | `caddyfile_oauth_application.go`, collected first in `caddyfile.go` | `pkg/oidc/parser/application.go`, `client.go` → `Config.AddOAuthApplication`; explicit or stored credentials, repeatable single-value `redirect_uri`, no generation during adaptation |
| `oauth registration store` | `caddyfile_oauth_registration_store.go`, `oauth_registration_config.go`, `command_provision.go` | Host-owned immutable revisions, `pkg/oidc/provisioning.go` only on explicit creation |
| Portal OIDC provider | `caddyfile_authn_oidc.go`, `caddyfile_authn.go`, `oidc_config.go` | `Config.ConfigureOIDCProvider` → `pkg/oidc/parser/provider.go` → `PortalConfig.ConfigureOIDCProvider`; collect all applications first, attach before portal validation, reject overlapping issuer mounts across portals |
| Upstream SAML | `caddyfile_identity_provider.go` | `pkg/idp/config.go`, `pkg/idp/saml` |
| SSO apps | `caddyfile_sso_provider.go` | `pkg/sso` |
| Consul credential authenticators and secrets | `plugins/credential-authenticators-consul/plugin.go`, `plugins/secrets-consul/plugin.go` | Host flat parsers, existing app typed bindings and immutable secret snapshots; [API-key contract](../../configuration-authorization/references/consul-api-keys.md) and [secrets contract](../../configuration-secrets/references/consul.md) |
| SQLite credential authenticators | `caddyfile_credential_authenticator.go`, `plugins/credential-authenticators-sqlite/plugin.go` | `plugins/credential-authenticators/sqlite/parser`; root `credential authenticator sqlite <name>` declarations bind existing policy API-key syntax with exact names/realms before root construction |
| Credentials | `caddyfile_credentials.go` | `pkg/credentials` |
| Messaging | `caddyfile_messaging.go`, `caddyfile_messaging_backend.go`, `plugins/messaging-sqlite/plugin.go` | `pkg/messaging/email_provider.go`, `file_provider.go`, `plugins/messaging/sqlite/parser` |
| User registration | `caddyfile_user_registration.go`, `caddyfile_registration_workflow.go`, `plugins/registration-workflows-sqlite/plugin.go` | `pkg/registry/local_user_registry.go` owns legacy policy; `plugins/registration-workflows/sqlite/parser` owns fixed SQLite enrollment; portal selection maps to `PortalConfig.UserRegistries` |
| Secrets manager body | `caddyfile_secrets.go`, `plugins/secrets-sqlite/plugin.go` | Registered `security.secrets.<module>` parser; bundled SQLite delegates to `plugins/secrets/sqlite/parser`, reads one record and closes before consumer construction |
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
   reference. Apply the [parser documentation guidance](../../coding-directives/SKILL.md#caddyfile-parsers)
   to explain operational meaning, defaults, scope, interactions and reasoning
   beside the grammar; verify those claims against the runtime consumer.
   Keep recognized-but-restricted forms visible, identifying the rejecting
   layer; retain version details in the audit evidence. Keep unsupported typed-only fields distinct from usable
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

Validation commands follow [testing-and-ci](../../testing-and-ci/SKILL.md);
side effects and Make targets follow
[scripts-and-automation](../../scripts-and-automation/SKILL.md):

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

Known fixture outcomes: `testcase_authorize_acl_fields_duplicate`,
`testcase_authorize_acl_fields_blocks`,
`testcase_authorize_acl_fields_policy_brace`,
`testcase_authenticate_with_argon2_malformed`,
`testcase_authenticate_malformed`,
`testcase_authenticate_with_admin_api_malformed`,
`testcase_authenticate_with_documents_block`,
`testcase_authenticate_with_documents_duplicate`,
`testcase_authenticate_with_token_refresh_cookie_whitespace`,
`testcase_authenticate_with_oauth_icon_malformed`, and
`testcase_authenticate_with_redirect_trust_malformed`,
`testcase_security_oauth_application_boundary_malformed`,
`testcase_security_oauth_application_enclosing_malformed`,
`testcase_security_oauth_application_header_malformed`, and
`testcase_security_oauth_application_empty`,
`testcase_authenticate_with_oidc_noncanonical_issuer`,
`testcase_authenticate_with_oidc_unterminated`,
`testcase_security_oauth_registration_legacy`, and
`testcase_security_oauth_registration_malformed` intentionally fail adaptation;
`testcase_security_with_secrets` requires an external module absent from the
normal test binary; `testcase_authenticate_malformed_replacement` adapts but
fails runtime resolution. `testcase_authenticate_with_match_any_refresh` and
`testcase_authenticate_with_match_any_system` adapt and resolve; the library
evaluates unconditional rules without timestamps.
Check test registrations if these outcomes change.
`testcase_security_oauth_registration_store` needs
`SECURITY_TEST_REGISTRATION_PATH` set to an isolated private store containing
the `website` application's `v1` revision. Its registered Go test provisions
that fixture automatically; a standalone binary audit must prepare the same
input with the private provisioning commands. Missing fixture data is not a
grammar rejection.

Run the skill-creator validator for each changed skill, verify relative links
and `agents/openai.yaml`, then format changed Go comments and Caddyfiles.
Run `make license` as required by the coding skill and inspect its diff.
Summarize the inventory, corrections, validation performed, and remaining
restrictions without claiming that parsing tests prove runtime behavior.

## Known Boundaries

Recheck these against the selected implementation when dependencies change. Use the
[dependency compatibility map](authcrunch-compatibility.md) for changed surfaces
and their Caddy validation:

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
- LDAP `fallback role` / `fallback roles` preserves every role; repeated
  directives replace the list. Local stores reject this LDAP-only parameter.
- Transforms delegate complete blocks to the shared parser, preserving
  `match any`, field existence checks, custom claims and conditional policies.
  Bare ordinary `match` retains historical exact spelling in JSON. Static
  local users expose repeated `auth challenges <rule body>`. Both surfaces
  reject unsupported email checkpoints; neither setting enrolls credentials.
- The selected runtime supports `match any` transforms with refresh, OIDC and System
  API keys: unconditional evaluation no longer requires timestamps. Keep the
  positive policy/claims and unsatisfied-factor regressions in the Caddy suite.
- `{claims.*}` placeholders survive Caddy resolution only in transform
  arguments. Resolved transforms are compiled again, including native JSON.
- Portal `ui logo url` / `logo description` are valid; JSON field spellings
  `logo_url` / `logo_description` are not UI directives. Portal
  `enable user registration <name> [<name>...]` selects global registries;
  external SQLite workflows require this explicit selection and an attached
  target identity store. Legacy registries retain automatic eligible-store
  attachment when no selection is present.
- Documents uses flat portal statements, not a nested `documents api` block.
  Omitted, disabled and storage-only settings do not enable the API or open its
  database. Disabled input still obeys directive syntax and duplicate checks;
  enabled storage additionally validates realms, permanent origin/mount binding
  and quotas. Runtime-backed collections resolve before shared validation.
  Parsing success alone does not establish current local browser-session
  authority, private filesystem readiness or ciphertext ownership; those use
  the [Documents API contract](../../authentication-portal-api/references/documents.md)
  and its actual Caddy acceptance.
- Messaging file providers use `root_dir` and require `sender`. Registration
  `admin email` (alias `admin emails`) takes exactly one address per line;
  repeating it replaces the prior address. SSO apps require `cert`, a private
  key, and a supported driver at validation; Caddy requires a location even
  for disabled SSO definitions.

Authorization path interpretation and token path wildcard matching are runtime
contracts independent of delegated Caddyfile grammar. Follow
[authorization path behavior](../../configuration-authorization/SKILL.md#policy-options)
and its provider/TLS regressions when upgrading: successful adaptation alone
cannot establish the stricter request-time authorization contract.
