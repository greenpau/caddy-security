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

Document implementation and operational guidance in the relevant repo-local
skill or its linked references. Do not add Markdown documentation to `docs/`
or `assets/docs/`; use [skill-authoring-patterns](../skill-authoring-patterns/SKILL.md#ownership-and-routing)
for documentation ownership and placement.

## Repository Scope

Keep source changes inside `caddy-security`. Sibling repositories such as
`../go-authcrunch` are read-only references and are updated separately.

The sole sibling-write exception is `../xcaddy-caddy-security`, the integrated
xcaddy build workspace. Creating, updating, building in, and cleaning that
workspace is allowed when needed for the xcaddy workflow. The exception does
not permit changes to sibling source modules referenced by the build, including
go-authcrunch. No other sibling directory is a permitted write destination.

This boundary covers creating, editing, deleting, restoring, staging, and
committing files, including code, tests, fixtures, dependency files, skills,
generated artifacts, and Git metadata. Outside the named xcaddy workspace,
do not run sibling build, test, formatting, generation, license, dependency,
or cleanup commands, or change those repositories' Git state through fetch,
pull, checkout, reset, tag, or other Git mutations.

Before a mutating command, confirm its repository root and working directory,
inspect the invoked script's side effects, and resolve its output paths. A
command launched from this repository can still write elsewhere. Do not bypass
the boundary through symlinks, linked worktrees sharing a sibling's Git metadata,
module replacement paths, or output-directory flags. Keep task files and chosen
build/report destinations in this checkout's working areas, such as `tmp/`,
`bin/`, and `.coverage/`, except for the named xcaddy build workspace. Resolve
that workspace's physical path before cleanup so a symlink cannot redirect the
exception into another sibling repository.

Reading sibling source, skills, versions, and history is allowed. References to
upstream APIs, tests, and integration wiring are context, not instructions to
modify or run that project. A local Go replacement may select existing sibling
source for tests of this module; it does not authorize sibling changes. If a
fix requires an upstream change, document the affected contract and separate
work needed, complete the work possible here, and state any validation blocker.
Do not patch the sibling, duplicate its runtime here to avoid the boundary, or
request to expand the current task into that repository.

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

For runtime construction, ownership, request draining, reload, or cleanup work,
read [Runtime lifecycle](references/runtime-lifecycle.md). It traces Caddy's
host ordering, the app's disposal contract, identity-file ownership restrictions,
and the unit/E2E tests that verify those behaviors.

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
directives **or updating a dependency that owns delegated grammar**. Document
headers, body scope, argument counts, aliases, repetition, and the parser that
owns deeper validation. Keep restricted forms visible with an explicit status;
do not delete documented syntax merely because a shared validator rejects it.
Update runnable examples and the owning configuration skill in the same change.
Follow the [syntax maintenance workflow](../configuration/references/syntax-maintenance.md)
for the source inventory and validation boundaries.

Explain behavior alongside the syntax when a setting's name is insufficient.
Include units/defaults, the meaning of omission/zero/disabled values, the scope
of limits (per user, session, portal or process), inheritance and precedence,
and consequential interactions or failure behavior. Explain the operational
reason for a restriction or tradeoff when supported by the implementation:
for example, whether a timeout slides, what consumes a session slot, or why
native body transport requires explicit opt-in. Verify these details against
the selected parser **and runtime**; field names alone do not establish them.
Keep the grammar easy to scan, follow it with focused explanatory paragraphs,
and link to the owning feature reference for longer protocol examples. Scale
the detail to the feature instead of repeating a checklist for trivial options.

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

For OP integration, retain the complete canonical request URL when calling
`Portal.ServeHTTP`. It owns OIDC dispatch and completed-login evidence. Do not
strip the issuer mount, preauthorize OP endpoints, call `CompleteLogin`, or
reconstruct authentication evidence in Caddy middleware. Preserve the portal's
status, headers and body; see the
[OIDC HTTP contract](../configuration-oauth-applications/references/oidc-provider.md#http-mount-and-protocol-contract).

The same dispatch owns refresh/session/logout credential authentication before
access-token gates and serves the matching embedded browser client. Preserve
headers (including the SID precondition), strict JSON failures, cookie deletion,
no-store and continuation CSP. Never add automatic rotation retries or recover
uncertainty with session lookup. See the
[browser refresh contract](../authentication-portal-api/references/browser-refresh.md).

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

Do not import or use Go's `reflect` package in repository Go code, including
tests and helpers. Use explicit types, type switches, interfaces, or generics.
Keep configuration validation typed instead of building runtime field walkers.

Keep the Apache license header on Go files. Use package `security` for root
application files and package `main` for executable entrypoints under `cmd/`,
including `cmd/authcrunch` and `cmd/caddy-authenticator`. The standalone
authenticator reuses the public authclient package; see its
[maintenance reference](../scripts-and-automation/references/caddy-authenticator.md).

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

Code changes require relevant unit tests and E2E tests that exercise the changed
behavior. Follow [testing-and-ci](../testing-and-ci/SKILL.md#required-coverage-for-code-changes)
to add or amend coverage and run the applicable checks in this repository.

Add focused parser coverage in the closest `caddyfile_*_test.go` when changing
Caddyfile syntax or validation. Include malformed cases when the parser has a
meaningful error path.

For every Caddyfile directive change, add or amend adaptation cases in
`testdata/caddyfile_adapt/` and register them in `caddyfile_adapt_test.go` as
needed. Include `<prefix>.Caddyfile`, expected `<prefix>.json`, and optional
`<prefix>.env`; this requirement also applies when the JSON shape stays the
same. Adaptation coverage supplements unit and E2E tests.

Update `<prefix>_resolved.json` and `TestResolveRuntimeAppConfig` coverage when
runtime defaults, replacements, secrets, credentials, UI, OAuth, registration,
cookie behavior, or any resolved authcrunch config output changes.

Use `go-cmp` diffs or semantic JSON map comparison for test assertions. Avoid
order-sensitive string comparisons for JSON unless the surrounding test already
requires formatted output.

After fixture or parser work, run the narrow relevant test first, then broaden
according to the `testing-and-ci` skill.
