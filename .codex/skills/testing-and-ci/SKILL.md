---
name: testing-and-ci
description: caddy-security repository testing and CI workflow guidance, including Go test command selection, Makefile report targets, Caddyfile parser/adapt fixture tests, runtime resolution fixtures, coverage artifacts, and GitHub Actions build/release/CLA behavior. Use when choosing or running tests, adding or updating test coverage, interpreting CI failures, reproducing GitHub Actions locally, or documenting validation for this Go/Caddy module.
---

# Testing and CI

## Overview

Use this skill for caddy-security test selection, fixture maintenance, and CI
reproduction. Prefer the narrowest `go test` command while editing, then use
Makefile targets when the user asks for the repository workflow, report
artifacts, or CI-like validation.

The Go module is rooted at the repository top level. Most tests live in the
root `security` package and cover Caddyfile parsing, Caddyfile adaptation, and
runtime authcrunch config resolution.

## Command Selection

Use direct Go tests for quick feedback:

```bash
go test ./...
go test -run TestParseCaddyfileAuthorization ./...
go test -run TestCaddyfileAdaptAuthenticationToJSON ./...
go test -run TestResolveRuntimeAppConfig ./...
```

Use `make test` for the full local workflow. It creates `.coverage`, installs
test report tools if missing, runs `go test -json -v ./...` with a coverage
profile, writes `.coverage/test_output.jsonl`, generates HTML reports, and
fails if any JSON test action failed.

Use `make qtest` only when the Makefile's current `QUICK_TEST_PATTERN` is the
intended scope. Prefer direct `go test -run ... ./...` for a different focused
test instead of editing the Makefile just to run one command.

Use `make coverage` after `.coverage/coverage.out` exists, usually after
`make test`. It writes `.coverage/coverage.html`, refreshes
`.coverage/coverage.out`, and prints non-100% function coverage.

Use `make build` when validation needs the `bin/authcrunch` command binary or
when Caddyfile fixture formatting may matter. Use `make fmtcfg` after a build
to format Caddyfile fixtures under `testdata/caddyfile_adapt` and
`assets/config`.

`make dep`, `make install-test-tools`, `go mod tidy`, `go mod verify`,
`go mod download`, and `go install` may require network access.

## Test Surfaces

Parser tests use inline Caddyfile snippets and `caddyfile.NewTestDispenser`.
They call parser functions, unpack generated JSON into maps, and compare with
`cmp.Diff`. Whitespace in inline `want` JSON is not semantically important.
Add or update these tests when directive parsing behavior changes:

- `caddyfile_authn_test.go`: authentication portal parsing.
- `caddyfile_authn_misc_test.go`: authentication misc/cookie/crypto/UI paths.
- `caddyfile_authz_test.go`: authorization policy parsing.
- `caddyfile_identity*_test.go`: identity stores and providers.
- `caddyfile_credentials_test.go`: credential directives.
- `caddyfile_messaging_test.go`: messaging directives.
- `caddyfile_sso_provider_test.go`: SSO provider directives.
- `caddyfile_test.go`: app-level parse coverage.

Adapt tests live in `TestCaddyfileAdaptAuthenticationToJSON` in
`caddyfile_adapt_test.go`. Each case uses
`testdata/caddyfile_adapt/<prefix>.Caddyfile` as input and compares against
`<prefix>.json`. Optional `<prefix>.env` files provide environment variables;
blank lines and comments are ignored, and variables are cleaned up by the test.
Use this path when a user-visible Caddyfile-to-JSON output changes.

Runtime resolution tests live in `TestResolveRuntimeAppConfig` in
`caddyfile_resolve_test.go`. Each case reads `<prefix>.json`, extracts the
`security.config` object, runs `ResolveRuntimeAppConfig`, and compares against
`<prefix>_resolved.json`. The test also fails if unresolved `{env...}` tokens
remain. It writes temporary `*_tmp_input.json` and `*_tmp_output.json` files,
removing them on success and leaving them on failure for debugging.

Expected-error tests set `shouldErr: true` and compare the exact error string
with `cmp.Diff`. Keep expected errors specific. The static secrets manager
fixture currently expects a module-not-registered error because the external
secrets plugin is not registered in this test binary.

## Adding Coverage

When adding or changing a Caddyfile directive, add focused parser coverage in
the nearest `caddyfile_*_test.go` file. Include both the successful config shape
and a malformed input when the parser has a meaningful error path.

When the change affects Caddy's adapted JSON, add or update a fixture triplet in
`testdata/caddyfile_adapt`: `<prefix>.Caddyfile`, `<prefix>.json`, and
optionally `<prefix>.env`. If runtime defaults, replacements, credentials, UI,
OAuth, registration, or cookie behavior changes after adaptation, also add or
update `<prefix>_resolved.json` and include the prefix in
`TestResolveRuntimeAppConfig`.

After fixture edits, run the focused test first, then a broader command:

```bash
go test -run TestCaddyfileAdaptAuthenticationToJSON ./...
go test -run TestResolveRuntimeAppConfig ./...
go test ./...
```

If `*_tmp_input.json` or `*_tmp_output.json` files remain after a failing
runtime resolution test, inspect them, fix the fixture or implementation, and
remove the generated temp files before finishing unless the user explicitly
wants debug artifacts kept.

## CI Workflow

`.github/workflows/build.yml` runs on pushes and pull requests to `main` using
Ubuntu and Go `1.25.x`. It installs `make` and `libnss3-tools`, sets `GOBIN` to
`/home/runner/.local/bin`, runs `make dep`, `go mod tidy`, `go mod verify`,
`go mod download`, runs `make test || true` followed by `make test`, then runs
`make coverage` and uploads `.coverage/coverage.html`.

For local CI reproduction, use:

```bash
make dep
go mod tidy
go mod verify
go mod download
make test
make coverage
```

The release workflow runs GoReleaser on `v*` tags or manual dispatch with Go
`~1.25`. Treat release workflows, tags, pushes, and chained release Makefile
targets as human-operator actions unless the user explicitly requests them.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.

## Generated Artifacts

Treat these as generated outputs unless the user explicitly asks to preserve or
commit them:

```text
bin/authcrunch
.coverage/coverage.html
.coverage/coverage.out
.coverage/test_output.jsonl
.coverage/test_output.html
testdata/caddyfile_adapt/*_tmp_input.json
testdata/caddyfile_adapt/*_tmp_output.json
```

Formatted Caddyfiles and JSON fixtures can be intentional source changes.
Review the diff after running format, build, test, or coverage commands.
