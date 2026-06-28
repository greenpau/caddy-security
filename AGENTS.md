# Repository Guidelines

## Project Summary

`caddy-security` is a Go module that provides a Caddy v2 `security` app and
HTTP authentication/authorization integrations backed by
`github.com/greenpau/go-authcrunch`. The global `security` Caddyfile option is
adapted into the app configuration and can define credentials, messaging,
identity stores and providers, SSO providers, local users, registration flows,
authentication portals, authorization policies, and pluggable secrets managers.

The module registers two primary HTTP integrations: `authenticate`, which serves
an authentication portal for form-based, basic, local, LDAP, OpenID Connect,
OAuth 2.0, and SAML authentication; and `authorize`, which plugs into Caddy's
authentication provider chain to authorize requests using gatekeeper policies and
JWT/PASETO-derived user claims.

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

## Project Structure

Most production code lives in the root Go package,
`github.com/greenpau/caddy-security` (`package security`), because the Caddy
modules register from package `init` hooks.

- `app.go` defines the Caddy `security` app, its lifecycle/provisioning, the
  `SecretsManager` plugin interface, and access to provisioned authcrunch
  portals and gatekeepers.
- `plugin_authn.go` and `plugin_authz.go` define the HTTP integrations:
  `authenticate` registers the authentication portal handler, while `authorize`
  registers the authorization provider used in Caddy's authentication chain.
- `caddyfile.go` registers the global `security` Caddyfile option and dispatches
  parser blocks. The `caddyfile_<domain>.go` files parse credentials,
  messaging, identity stores/providers, SSO providers, local users,
  registrations, authentication portals, authorization policies, secrets, and
  runtime replacement behavior.
- `caddyfile_authn_*` files parse authentication portal subdirectives such as
  cookies, crypto, UI, transforms, and miscellaneous portal settings.
  `caddyfile_authz_*` files parse authorization policy subdirectives such as
  ACLs, shortcuts, bypass rules, crypto, header injection, and miscellaneous
  policy settings. `caddyfile_utils.go` contains small parser helpers.
- `caddyfile_resolve.go` applies Caddy replacer values and
  `security.secrets.*` plugin lookups to authcrunch configuration during
  provisioning.
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
- `assets/config/` stores runnable/example Caddy configs and supporting files.
  `assets/scripts/` stores documentation/release automation. `assets/docs/` and
  `assets/cla/` contain project documentation assets and CLA materials.
- `go.mod` and `go.sum` define the module and dependencies. `Makefile` wraps
  local build, test, coverage, config formatting, dependency, and release
  workflows. `.goreleaser.yaml` contains release packaging configuration.
- `.github/workflows/` contains build, CLA, and release CI workflows;
  `.github/ISSUE_TEMPLATE/` contains issue forms.
- `.codex/skills/` contains repo-local Codex skills referenced by this file.
- `bin/`, `tmp/`, `.coverage/`, `.doc/`, `dist/`, and `vendor/` are ignored or
  generated working areas, not canonical source.

## Coding Directives

Use the repo-local `coding-directives` skill when creating, modifying, or
reviewing application code, Caddyfile directives, Caddy modules, authcrunch
config mapping, HTTP handlers, or Go tests in this repository.

## Source Code Management

Use the repo-local `source-code-management` skill for commit message rules and
for the workflow used when asked to create a commit message for a change.

## Scripts and Automation

Use the repo-local `scripts-and-automation` skill when choosing, running, or
documenting Makefile targets, repository scripts, build/test/report workflows,
generated artifacts, dependency automation, or release/version procedures.

## Testing and CI

Use the repo-local `testing-and-ci` skill when choosing or running tests,
adding or updating test coverage, maintaining Caddyfile adapt or runtime
resolution fixtures, interpreting CI failures, reproducing GitHub Actions
locally, or documenting validation for a change.
