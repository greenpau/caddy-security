# Repository Guidelines

## Project Summary

`caddy-security` is a Go module that provides a Caddy v2 `security` app and
HTTP authentication/authorization integrations backed by
`github.com/greenpau/go-authcrunch`. The global `security` Caddyfile option is
adapted into the app configuration and can define credentials, messaging,
identity stores, OAuth and SAML identity providers, SSO app providers, local
users, registration flows, authentication portals, authorization policies, and
pluggable secrets managers.

The module registers two primary HTTP integrations: `authenticate`, which serves
an authentication portal for form-based, basic, local, LDAP, OpenID Connect,
OAuth 2.0, and SAML authentication; and `authorize`, which applies gatekeeper
policies to JWT/PASETO claims and direct OAuth sessions. The legacy authorization
provider remains available for Caddy's authentication provider chain.

In Caddy terms, `security` is an application: a top-level Caddy module with its
own lifecycle, configuration, provisioning, and shared runtime state. The
`authenticate` and `authorize` directives are Caddy plugins: HTTP-facing modules
that attach to routes and delegate to the provisioned `security` app. The app
owns reusable authcrunch configuration such as portals, gatekeepers, identity
stores, credentials, messaging, and secrets managers; the plugins apply that
configuration to individual requests in the HTTP handler/authentication chain.
The `security` app can also load external plugins of its own, especially under
the `security.secrets` namespace, such as
`github.com/greenpau/caddy-security-secrets-static-secrets-manager` and
`github.com/greenpau/caddy-security-secrets-aws-secrets-manager`.

## Repository Scope

Keep all repository changes inside `caddy-security`. Sibling repositories,
including `../go-authcrunch`, are read-only references and are updated
separately. Do not edit their files or Git state, run their build/test/maintenance
commands, or write generated output into them.

The sole sibling-write exception is `../xcaddy-caddy-security`, the workspace
for integrated xcaddy builds. It may be created, updated, and cleaned for that
workflow. This exception does not extend to go-authcrunch or other modules
used by the build. Compatibility work and local dependency replacements do not
expand this boundary.

Follow the [repository scope](.codex/skills/coding-directives/SKILL.md#repository-scope)
for command and output-path checks. Report required upstream changes as separate
work; do not perform them or seek to expand this task into sibling repositories.

## Project Structure

Most production code lives in the root Go package,
`github.com/greenpau/caddy-security` (`package security`), because the Caddy
modules register from package `init` hooks.

- `app.go` defines the Caddy `security` app, its lifecycle/provisioning, the
  `SecretsManager` plugin interface, and access to provisioned authcrunch
  portals and gatekeepers.
- `plugin_authn.go` registers the authentication portal handler.
  `plugin_authz.go` implements policy delegation and the legacy authentication
  provider. `plugin_authorization.go` supplies the current `authorize` route
  handler, preserving handled OAuth callbacks, redirects and denials.
- `caddyfile.go` registers the global `security` Caddyfile option and dispatches
  parser blocks. The `caddyfile_<domain>.go` files parse credentials,
  messaging, identity stores, OAuth and SAML identity providers, SSO app
  providers, local users, registrations, authentication portals, authorization
  policies, secrets, and runtime replacement behavior.
- `caddyfile_oauth_application.go` registers named OAuth clients with explicit
  or persisted credentials. `command_provision.go` owns explicit local creation
  and rotation; `command_security.go` registers the CLI namespace and reports
  the linked go-authcrunch dependency through `security version`.
  `oauth_registration_store.go` owns private immutable revisions.
  `caddyfile.go` collects applications before resolving other declarations.
- `command_local*.go` implements `security local` administration through the
  portal admin API; `command_credentials.go` provides offline password/API-key
  generation and private terminal input.
- `caddyfile_authn_*` files parse authentication portal subdirectives such as
  cookies, crypto, UI, transforms, and miscellaneous portal settings.
  `caddyfile_authz_*` files parse authorization policy subdirectives such as
  ACLs, shortcuts, bypass rules, crypto, header injection, and miscellaneous
  policy settings. `caddyfile_utils.go` contains small parser helpers.
- `caddyfile_resolve.go` applies Caddy replacer values and
  `security.secrets.*` plugin lookups to authcrunch configuration during
  provisioning.
- `caddyfile_state.go` adapts the optional root runtime-state block. Persistent
  roots are constructed in `App.Start`; overlapping persistent reload is rejected
  before candidate routes start, and Cleanup drains calls before root disposal.
- `*_test.go` files sit beside the code they exercise. `caddyfile_adapt_test.go`
  is fixture-driven and compares Caddyfile input against expected adapted JSON.
- `testdata/caddyfile_adapt/` contains `.Caddyfile`, `.json`, optional `.env`,
  and `_resolved.json` fixtures for Caddyfile adapt and runtime resolution
  tests. `testdata/oauth/` contains OAuth fixture keys and notes.
- `pkg/util/` contains shared helpers for Caddy replacer expansion and request
  IDs used by the app and plugins.
- `cmd/authcrunch/` builds the local Caddy binary that imports standard Caddy
  modules, this module, and `caddy-trace`; build outputs land in
  `bin/authcrunch`.
- `cmd/caddy-authenticator/` builds a standalone, go-installable portal login
  client using authclient, with named profiles and private token/log storage.
  `make build` outputs `bin/caddy-authenticator`; its `README.md` owns user-facing
  CLI usage, including interactive opt-in and version reporting.
- `assets/config/` stores runnable/example Caddy configs and supporting files.
  `assets/scripts/` stores documentation/release automation. `assets/docs/`
  holds non-Markdown assets such as images; `assets/cla/` holds CLA materials.
- `go.mod` and `go.sum` define the module and dependencies. `Makefile` wraps
  local build, test, coverage, config formatting, dependency, and release
  workflows. `.goreleaser.yaml` contains release packaging configuration.
- `.github/workflows/` contains build, CLA, and release CI workflows;
  `.github/ISSUE_TEMPLATE/` contains issue forms.
- `.codex/skills/` contains repo-local Codex skills referenced by this file.
- `bin/`, `tmp/`, `.coverage/`, `.doc/`, `dist/`, and `vendor/` are ignored or
  generated working areas, not canonical source.

## Coding Directives

Use [coding-directives](.codex/skills/coding-directives/SKILL.md) to create,
modify, or review application code, Caddyfile directives, Caddy modules,
authcrunch config mapping, HTTP handlers, or Go tests in this repository.

## Configuration

Use [configuration](.codex/skills/configuration/SKILL.md) to create, review, or modify
Caddy Caddyfile configurations for caddy-security authentication portals,
authorization policies, identity stores, OAuth and SAML identity providers, SSO
app providers, local users, registration flows, messaging, credentials, secrets
managers, runtime replacement, or the `authenticate` and `authorize` HTTP
integrations.

When changing syntax or updating Caddy/go-authcrunch, follow
[Syntax maintenance](.codex/skills/configuration/references/syntax-maintenance.md)
to audit Caddyfiles, parser syntax comments, delegated upstream grammar, and
the corresponding configuration skills together.

The configuration router delegates `oauth application <nickname>`
registrations, private `oauth registration store` configuration, the
`security oauth` and `security oidc` CLI commands, and portal `oidc provider` blocks
to [configuration-oauth-applications](.codex/skills/configuration-oauth-applications/SKILL.md);
[configuration-oauth-providers](.codex/skills/configuration-oauth-providers/SKILL.md)
owns external login providers.

[configuration-state](.codex/skills/configuration-state/SKILL.md) owns the root
`state` block, restart persistence, exclusive runtime ownership and the
stop/start deployment boundary. Direct OAuth without a portal belongs to
[configuration-authorization](.codex/skills/configuration-authorization/SKILL.md).

[configuration-logging](.codex/skills/configuration-logging/SKILL.md) owns root
diagnostic skip rules and issue #280's logger ownership boundary.
AuthCrunch component filtering does not suppress
Caddy v2.11.7's independent authentication middleware logger.

## Portal API Integration

Use [authentication-portal-api](.codex/skills/authentication-portal-api/SKILL.md)
to implement or troubleshoot JSON/native login, token refresh, profile/admin API
calls, and public JWKS clients. Portal declarations and route mounting retain
their configuration owners.

## Break-Fix Troubleshooting

Use [break-fix-troubleshooting](.codex/skills/break-fix-troubleshooting/SKILL.md)
to diagnose reported configuration, deployment, or runtime failures; analyze
Caddyfiles, Caddy logs, redirect loops, login failures, authorization denials,
OAuth/OIDC/SAML, LDAP, local-user, module-version, or runtime secret issues; or prepare
responses for `.github/ISSUE_TEMPLATE/break-fix.md`.

## Source Code Management

Use [source-code-management](.codex/skills/source-code-management/SKILL.md) to
create or review commit messages and their required message files.

## Scripts and Automation

Use [scripts-and-automation](.codex/skills/scripts-and-automation/SKILL.md) to
choose, run, or document Makefile targets, repository scripts, build/test/report
workflows, generated artifacts, dependency automation, or release/version
procedures.

Use its [local user command reference](.codex/skills/scripts-and-automation/references/local-user-commands.md)
for `security local` user-store administration and offline credential generation.

Use its [standalone authenticator reference](.codex/skills/scripts-and-automation/references/caddy-authenticator.md)
for `cmd/caddy-authenticator` implementation, profiles, storage and validation.
Keep the utility's user-facing usage in `cmd/caddy-authenticator/README.md`.

## Versioning and Releases

The scripts-and-automation router delegates `VERSION`, generated download
links, versioned CI artifacts, release preparation and execution, release Make
targets, GoReleaser packaging, and publication workflows to
[release-and-versioning](.codex/skills/release-and-versioning/SKILL.md).

## Skill Authoring

Keep repository documentation in the relevant repo-local skill or its linked
references under `.codex/skills/`. Do not place Markdown documentation in
`docs/` or `assets/docs/`.

Use [skill-authoring](.codex/skills/skill-authoring/SKILL.md) to create, port,
review, or validate repo-local skills, `agents/openai.yaml` metadata, and
actionable skill routing from `AGENTS.md`. Apply it with the default
`skill-creator`; its linked caddy-security supplement owns local authoring details.
Diagrams are optional and are not a requirement for skill authoring or audits.

## Testing and CI

Use [testing-and-ci](.codex/skills/testing-and-ci/SKILL.md) to choose or run tests,
add or update test coverage, maintain Caddyfile adapt or runtime resolution
fixtures, interpret CI failures, reproduce GitHub Actions locally, or document
validation for a change.

Code changes must have unit and E2E coverage. Caddyfile directive changes also
require new or amended adaptation cases in `testdata/caddyfile_adapt/`. Follow
the skill's coverage requirements and validation workflow.

Use the [CodeQL workflow](.codex/skills/scripts-and-automation/references/codeql.md)
for local scans, Go/JavaScript/Python/Actions regression validation, findings
reports and advanced code scanning. Apply only the reviewed exceptions in
`.github/codeql/suppressions.json` and retain raw findings plus the suppression
audit. Sibling logging exceptions do not apply automatically here.

For official OP plans against the actual Caddy binary, use the
[Caddy conformance workflow](.codex/skills/configuration-oauth-applications/references/oidc-conformance.md).
Run it only with `make oidc-conformance-test`; its tests and artifacts are
separate from regular testing. Existing local OIDC regression E2E remains enabled.
Keep every non-pass outcome and the original runner status visible.
The separate manual-only `OIDC conformance` GitHub Action runs those Make targets
and uploads a readable summary plus the complete disposable test evidence
directly in one artifact ZIP, with signed exports and checksums. Follow its
[setup and artifact guidance](.codex/skills/configuration-oauth-applications/references/oidc-conformance-actions.md).
Use `make oidc-conformance-cleanup` to remove OIDC run bundles and supplemental
logs, audits and browser reports while retaining the prepared suite and
dependencies. The isolated tests live under
`assets/scripts/oidc_certification_conformance_tests/`; keep OIDC conformance
source/test filenames explicit about their scope.
