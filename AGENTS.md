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

TODO.

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
