---
name: coding-directives
description: caddy-security repository coding standards and implementation directives for Go/Caddy code, including Caddy module boundaries, security app lifecycle, authenticate/authorize plugin behavior, Caddyfile parser patterns, authcrunch integration, runtime replacement and secrets handling, errors, logging, imports, comments, tests, and fixtures. Use when creating, modifying, or reviewing application code in this repository or when deciding coding patterns for Caddyfile directives, Caddy modules, authcrunch config mapping, HTTP handlers, or Go tests.
---

# Coding Directives

## Overview

Apply these directives when editing or reviewing caddy-security code. Prefer
small, idiomatic Go changes that preserve Caddy module boundaries, delegate auth
logic to `go-authcrunch`, and keep parser behavior covered by focused tests and
fixtures.

Use the repo-local `testing-and-ci` skill when choosing or running tests. Use
`scripts-and-automation` for Makefile targets, generated artifacts, dependency
workflow, or local `go-authcrunch` replacement work.

## Architecture

Treat `security` as the top-level Caddy app. Keep shared authcrunch
configuration, provisioned portals, gatekeepers, identity stores, messaging,
credentials, registration, and secrets managers owned by `App`.

Treat `authenticate` and `authorize` as HTTP-facing integrations that attach to
Caddy routes and resolve named runtime objects from the provisioned `security`
app. Do not duplicate portal or gatekeeper behavior in the Caddy plugins when
`go-authcrunch` already owns it.

Keep the root package focused on Caddy app/plugin wiring and Caddyfile parsing.
Use `pkg/util` only for small reusable helpers that are truly package-external
or shared across multiple root-package files.

## Caddy Modules

Register Caddy modules and Caddyfile directives in `init` functions near the
module implementation. Provide a `CaddyModule` method with the correct public
Caddy module ID and `New` constructor.

Add interface guards for Caddy contracts such as `caddy.Module`,
`caddy.Provisioner`, `caddy.Validator`, `caddy.App`,
`caddyfile.Unmarshaler`, `caddyhttp.MiddlewareHandler`, and
`caddyauth.Authenticator` when a type is expected to satisfy them.

Keep exported configuration fields serializable with consistent struct tags.
For HTTP middleware config fields, preserve matching `json`, `xml`, and `yaml`
tags unless the surrounding type intentionally differs. Keep runtime-only fields
unexported and untagged.

In `Provision`, resolve the `security` app through Caddy context, validate nil
app/config cases, apply Caddy replacer substitutions where needed, retrieve
named authcrunch objects, and return contextual errors. Let `Validate` check
required names and provisioned runtime pointers.

## Caddyfile Parsers

Follow the existing parser shape:

```go
func parseCaddyfileSurface(d *caddyfile.Dispenser, cfg *authcrunch.Config) error
```

Use `d.RemainingArgs()` to validate directive arguments, `d.Nesting()` with
`d.NextBlock(nesting)` for blocks, and small helper functions for nested
subdirectives. Use `mkcp` or the local directive-prefix pattern to build clear
directive paths such as `security.authentication.portal.cookie`.

Return `d.ArgErr()` for malformed top-level argument counts. Use `h.Errf` or
`d.Errf` for Caddyfile parse errors that should include source locations. Use
`go-authcrunch/pkg/errors` helpers where the surrounding parser already uses
them for malformed directive values.

Keep syntax comments above parser functions current when adding or changing
directives. Future agents rely on those comments to discover Caddyfile shape.

When mapping Caddyfile input, prefer authcrunch config constructors and `Add*`
methods over duplicating validation in this repository. Use
`cfgutil.EncodeArgs` for raw instruction strings that authcrunch later decodes.
Use `map[string]interface{}` only where authcrunch expects flexible parameter
maps.

Preserve exact error wording when tests assert it. Many parser tests compare
`err.Error()` strings, including Caddy-added file and line suffixes.

## Runtime Config

Keep Caddy replacer behavior centralized through `util.FindReplace`,
`util.FindReplaceAll`, and `ResolveRuntimeAppConfig`. Add new replacement paths
there when adapted JSON can contain `{env.*}` or secret placeholders that need
runtime resolution.

Treat `secrets:<manager-id>:<key>` values as sensitive. Resolve them through
`SecretsManager` methods and avoid logging secret values, credentials, tokens,
passwords, API keys, or private keys.

Pass `context.Context` first when adding helpers that can touch secrets,
external state, Caddy context, or request-scoped work.

## HTTP Handlers

Keep request handling thin. For `authenticate`, construct the authcrunch request
object, attach `util.GetRequestID(r)`, and delegate to the portal. For
`authorize`, delegate to the gatekeeper and only translate successful
authcrunch authorization data into Caddy `caddyauth.User` metadata.

When adding metadata, check presence before type assertions unless the upstream
authcrunch contract guarantees the field. Keep metadata values string-based for
Caddy compatibility.

## Errors And Logging

Return errors instead of panicking. Include the directive path, operation, or
named portal/gatekeeper/provider in errors so failures are actionable.

Use `%w` when a caller may need to unwrap an error, but preserve existing `%v`
or exact string formatting when tests or Caddyfile diagnostics depend on it.

Use zap structured logging for app lifecycle and runtime diagnostics. Log
identifiers, paths, directive names, and types; never log secrets or token
payloads.

## Style

Keep the Apache license header on Go files. Use package `security` for root
application files and package `main` only for `cmd/authcrunch`.

Run `gofmt` on Go changes. Let Go tooling group imports into standard library,
third-party packages, and local module packages. Use side-effect imports only
for module registration or command bootstrapping, and keep the reason obvious
from local context.

Run `make license` after changing repository files and before final review. It
adds license headers to Go files and regenerates README download links, so
inspect the resulting diff and keep only intentional changes.

Prefer small, unexported helpers for parser branches and runtime plumbing.
Export only Caddy module types, public interfaces, and functions that are
genuinely used outside the package.

Use `const` groups for stable directive prefixes, plugin names, and repeated
keywords. Avoid new global variables unless the value is intentionally mutable
or computed.

Write comments for exported identifiers and for non-obvious parser or runtime
blocks. Avoid comments that merely restate the code.

## Tests And Fixtures

Add focused parser coverage in the closest `caddyfile_*_test.go` when changing
Caddyfile syntax or validation. Include malformed cases when the parser has a
meaningful error path.

Update `testdata/caddyfile_adapt` fixtures when adapted Caddy JSON changes:
`<prefix>.Caddyfile`, `<prefix>.json`, and optional `<prefix>.env`.

Update `<prefix>_resolved.json` and `TestResolveRuntimeAppConfig` coverage when
runtime defaults, replacements, secrets, credentials, UI, OAuth, registration,
cookie behavior, or any resolved authcrunch config output changes.

Use `go-cmp` diffs or semantic JSON map comparison for test assertions. Avoid
order-sensitive string comparisons for JSON unless the surrounding test already
requires formatted output.

After fixture or parser work, run the narrow relevant test first, then broaden
according to the `testing-and-ci` skill.
