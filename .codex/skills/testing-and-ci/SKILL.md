---
name: testing-and-ci
description: caddy-security testing through pinned tested, Caddyfile parser/adapt and runtime resolution fixtures, automation tests, complete coverage artifacts, and reusable GitHub Actions gates. Use when choosing or running tests, updating coverage, interpreting CI failures, reproducing CI locally, or validating report and artifact workflows.
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

Follow the [repository scope](../coding-directives/SKILL.md#repository-scope).
Create and run tests in this module only; never run sibling suites to validate
work here or fix a failing test by editing the sibling. `TEST_DIR` and
`QUICK_TEST_DIR` must select this module's packages, and `COVERAGE_DIR` must not
point into another checkout. Existing local replacements are dependency inputs
only. Keep compatibility fixtures and reports here and report required upstream
test or implementation changes as separate work.

## Command Selection

Use direct Go tests for quick feedback:

```bash
go test ./...
go test -run TestParseCaddyfileAuthorization ./...
go test -run TestCaddyfileAdaptAuthenticationToJSON ./...
go test -run TestResolveRuntimeAppConfig ./...
```

Use `make test` for the repository report lifecycle. `go.mod` pins
`github.com/greenpau/tested`, invoked as `go tool tested`; it owns `-json`,
`-coverprofile`, child-process status, and coherent reports. Do not reintroduce
`go test | tee`, log-grep success detection, richgo, tparse, or go-test-report.

```bash
make test
make test TEST='TestParseCaddyfileAuthorization' TEST_DIR='.'
make qtest TEST='TestParseCaddyfileAuthorization'
make run-reports
make test-automation
make ci-check
```

Lifecycle runs use `-mod=readonly -race -count=1 -timeout 20m -v`.
`TEST` is a regex (default `.`), `TEST_DIR` accepts package patterns (default
`./...`), and `TEST_TIMEOUT` overrides the quoted per-package limit.
`MINIMUM_COVERAGE` defaults to 1 percent as a nonzero-profile check, matching
go-authcrunch; it is not a substantial coverage target.

Reports land in `.coverage`. `make qtest` defaults to the root package (`.`) with
reports in `.coverage/quick`; override `QUICK_TEST_DIR` and `TEST` for another
scope. Use `COVERAGE_DIR` to isolate independent concurrent runs. Let tested
refresh its managed files without deleting other bundles or investigation
notes. `make run-reports` regenerates presentations from recorded evidence
and preserves failures; `make coverage` aliases it without rerunning tests.

Use `make build` when validation needs `bin/authcrunch`. Formatting is separate:
`make fmtcfg` formats fixtures under `testdata/caddyfile_adapt` and
`assets/config`. Builds/tests do not rewrite licenses, version files, module
manifests, or Caddyfiles. `make dep` downloads/verifies pinned dependencies and
resolves tested; it may need network access but does not install global tools.

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

`.github/workflows/build.yml` runs on pushes/PRs to `main`, manual dispatch,
and reusable workflow calls. It selects Ubuntu 24.04 and Go `1.26.8` with
`GOTOOLCHAIN=local`, plus Python 3 and NSS utilities. It resolves a versioned
artifact identity, runs `make dep` and `make ci-check`, and checks that
validation did not modify tracked source or add untracked source files.

After the gate is attempted, it always uploads `.coverage/`, including hidden
files and partial failure evidence, with 14-day retention. Missing artifacts
fail the upload and test failures remain failures. Actions are pinned to
immutable revisions and the test workflow has read-only contents permission.

For local CI reproduction, use:

```bash
make dep
make ci-check
```

Use [release-and-versioning](../release-and-versioning/SKILL.md) for release CI,
tag selection, artifact naming, packaging checks, and publication scope. The
release workflow calls this reusable gate before GoReleaser.

`make ci-check` serializes version validation, Python automation fixtures, the
full Go report lifecycle, and the binary build, even under `make -j`. It has no
browser test step; this repository's wrapper does not own go-authcrunch's UI.
The existing `make linter` remains a placeholder and is not a gate.

When changing tested or its invocation, run `make test-automation`. It exercises
real Make/tested processes in disposable repositories: filtering, full/quick/
custom bundle isolation, assertion failures, compile failures, short timeouts,
and failed offline reports. Version fixtures exercise the public artifact
command and validated `GITHUB_OUTPUT` values without publishing remotely.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.

## Generated Artifacts

Treat these as generated outputs unless the user explicitly asks to preserve or
commit them:

```text
bin/authcrunch
.coverage/index.html
.coverage/summary.json
.coverage/junit.xml
.coverage/coverage.html
.coverage/coverage.out
.coverage/test_output.jsonl
.coverage/test_output.html
.coverage/stderr.log
.coverage/run.json
.coverage/manifest.json
testdata/caddyfile_adapt/*_tmp_input.json
testdata/caddyfile_adapt/*_tmp_output.json
```

The manifest is published last for a coherent generation; a failed run can
leave only partial evidence. Inspect `run.json`, `stderr.log`, and
`test_output.jsonl` before rerunning so failures are not overwritten without
review. Test output and coverage sources are unredacted; use synthetic fixtures.

Formatted Caddyfiles and JSON fixtures can be intentional source changes.
Review the diff after explicit format or fixture updates. Skill-only edits use
`skill-authoring-patterns` and the default skill-creator validator instead of
running the Go suite.
