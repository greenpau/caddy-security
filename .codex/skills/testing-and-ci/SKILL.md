---
name: testing-and-ci
description: "Choose and run unit, E2E, Caddyfile fixture, automation, and CI checks for caddy-security. Use for coverage requirements, test evidence, failures, and report workflows; official OP conformance remains opt-in."
---

# Testing and CI

## Browser choice

Use **headless Chrome** for browser E2E tests, screenshots, developer-tools
network traces, and conformance visual evidence. Avoid Firefox unless the user
explicitly requests it for a browser-specific investigation. Prefer a pinned
Chrome for Testing distribution for reproducible external workflows; keep its
binary, driver, profiles, caches and artifacts under this repository's `tmp/`.
Preserve real browser interaction and TLS validation. Do not set
`acceptInsecureCerts`, ignore-certificate flags, disable web security, rewrite
Origin headers, or fabricate successful callbacks to make a conformance run pass.

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

## Required Coverage for Code Changes

When writing or changing code, ensure both unit tests and E2E tests exist and
exercise the changed behavior. Add or amend tests where coverage is missing;
existing tests count when they demonstrably verify that behavior. Run the
relevant unit and E2E tests before considering the code change complete.

Unit tests should check focused behavior and meaningful failure cases. E2E
tests should exercise the affected user-visible flow through the assembled
system. For authentication, authorization, and lifecycle changes, use actual
Caddy provisioning, routes, and HTTP requests as appropriate. Bound network,
process, and worker completion; clean up test-owned resources. Parser/adapt
tests and sibling go-authcrunch tests do not replace this repository's E2E
coverage. Report missing coverage or blocked validation explicitly.

Use `lifecycleAddress` for disposable Caddy listener addresses. It checks both
TCP and UDP availability because Caddy's default HTTPS server also starts a
QUIC listener; a TCP-only ephemeral-port check can select an occupied UDP port.
The occupied-QUIC-port regression also verifies release of the rejected TCP
reservation. Reservations are released before Caddy takes ownership.

Every Caddyfile directive change also requires new or amended adaptation test
cases in `testdata/caddyfile_adapt/`, even when the resulting JSON shape is
unchanged. Register new cases in `TestCaddyfileAdaptAuthenticationToJSON` in
`caddyfile_adapt_test.go` so the fixture is exercised. This is additional to
unit and E2E coverage; use the fixture mechanics below.

Documentation/skill-only edits use metadata, link, and source checks from
[skill-authoring](../skill-authoring/SKILL.md); they do not require new runtime
tests.

## Syntax and Example Audits

Follow [Syntax maintenance](../configuration/references/syntax-maintenance.md)
when parser grammar or a dependency changes. Inventory standalone Caddyfiles,
Go syntax comments, skill examples, and inline positive/negative tests. Adapt
runnable examples with a binary built from the selected dependencies. Wrap
fragments in their actual global/portal/policy/site scope; do not run syntax
catalogues or intentionally invalid examples as complete configurations.

Adaptation verifies only the validation reached by that parser. Raw crypto,
messaging, registration, ACL, and other deferred settings also need focused
resolution/validation checks when their examples change. Do not provision a
real deployment, contact an external provider, or change machine trust merely
to audit syntax. Preserve intentional failure fixtures and legacy alias tests.
Report external-module requirements and runtime checks separately from adapt
success. Comment-only edits do not change parser behavior; use source review,
formatting, and relevant existing tests instead of adding tests that mirror prose.

## Command Selection

Use direct Go tests for quick feedback:

```bash
go test ./...
go test -run TestParseCaddyfileAuthorization ./...
go test -run TestCaddyfileAdaptAuthenticationToJSON ./...
go test -run TestResolveRuntimeAppConfig ./...
```

Use `make test` for the repository report lifecycle. `go.mod` pins
`github.com/greenpau/tested` v1.1.0, invoked as `go tool tested`; it owns `-json`,
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

Lifecycle runs use `-mod=readonly -race -count=1 -p 1 -parallel 2
-timeout 60m -v`. The macOS/Linux resource guard bounds the whole process tree,
including compilers, browser/CLI children and report rendering. Read
[test resource controls](../scripts-and-automation/references/test-resources.md)
when changing defaults or investigating an interrupted run. The default wall
limit is 4,200 seconds, allowing compilation/report time around the 60-minute
package limit. Keep live tested output enabled; the guard also prints progress
every ten seconds.
`TEST` is a regex (default `.`), `TEST_DIR` accepts package patterns (default
`./...`), and `TEST_TIMEOUT` overrides the quoted per-package limit.
`MINIMUM_COVERAGE` defaults to 1 percent as a nonzero-profile check, matching
go-authcrunch; it is not a substantial coverage target.

Go's timeout covers the entire package, including all sequential E2E parent
tests. The Caddy journeys also have their own shorter child-process deadlines.
If CI times out, inspect the captured test events and active test duration to
distinguish an exhausted package budget from a stuck individual journey.
Keep the job budget larger than the package budget so setup, builds and report
upload can finish; the current workflow allows 75 minutes around the 60-minute
Go package limit.

Reports land in `.coverage`. `make qtest` defaults to the root package (`.`) with
reports in `.coverage/quick`; override `QUICK_TEST_DIR` and `TEST` for another
scope. Use `COVERAGE_DIR` for separate evidence bundles; guarded runs in the same
checkout cannot overlap, even with different output directories. Let tested
refresh its managed files without deleting other bundles or investigation
notes. `make run-reports` regenerates presentations from recorded evidence
and preserves failures; `make coverage` aliases it without rerunning tests.

Use `make build` when validation needs `bin/authcrunch` or
`bin/caddy-authenticator`; it builds both and prints their versions. Formatting is separate:
`make fmtcfg` formats fixtures under `testdata/caddyfile_adapt` and
`assets/config`. Builds/tests do not rewrite licenses, version files, module
manifests, or Caddyfiles. `make dep` downloads/verifies pinned dependencies and
resolves tested; it may need network access but does not install global tools.

## Test Surfaces

Read [test surfaces and qualification evidence](references/test-surfaces.md)
when selecting existing unit/E2E tests, extending a feature suite, or changing
coverage collection. It maps conditional authentication, CodeQL, subprocesses,
logging, persistent state, operator examples, OIDC, refresh, native/CLI clients,
local identity, authorization paths, lifecycle, and Caddyfile fixtures to their
actual tests and limits.

For interactions among login, refresh, OIDC, upstream OAuth, authorization,
edge metadata and reload, read
[composition qualification](references/composition-qualification.md).
The feature owner's acceptance contract determines what must be exercised;
a list of parser fixtures alone never proves a user flow works.

## Subprocess coverage

Root-package E2E helpers run the same instrumented test executable. The
[subprocess coverage contract](references/test-surfaces.md#subprocess-coverage)
owns collection before parent completion, isolated child directories, counter
publication, killed-process limits, and the regression workflow. Read it when
adding a subprocess or changing report collection.

## Adding Coverage

When adding or changing a Caddyfile directive, add focused parser coverage in
the nearest `caddyfile_*_test.go` file. Include both the successful config shape
and a malformed input when the parser has a meaningful error path.

For a Caddyfile directive change, add or amend adaptation cases in
`testdata/caddyfile_adapt/`: `<prefix>.Caddyfile`, `<prefix>.json`, and
optionally `<prefix>.env`, and update the test case registration as needed.
If runtime defaults, replacements, credentials, UI,
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
and reusable workflow calls. Its test job skips `main` push events whose head
commit message starts with `ops: released v`: the release script atomically
pushes that commit and its tag, and `release.yml` runs the gate for the tag.
Ordinary pushes, PRs, manual runs, and release tag validation still run tests.
It selects Ubuntu 24.04 and Go `1.26.8` with
`GOTOOLCHAIN=local`, plus Node 24, Python 3 and NSS utilities. It checks the
runner's Google Chrome installation for browser E2E. It resolves a versioned
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

Release CI, tag selection, artifact naming, packaging checks, and publication
scope belong to [release-and-versioning](../release-and-versioning/SKILL.md). The
release workflow calls this reusable gate before GoReleaser.

`make ci-check` serializes version validation, Python automation fixtures, the
full Go report lifecycle, and the binary build, even under `make -j`. The full
Go suite includes real-browser refresh E2E through Caddy. It serves the selected
go-authcrunch embedded UI rather than building or running tests in the sibling
checkout.
The existing `make linter` remains a placeholder and is not a gate.

When changing tested or its invocation, run `make test-automation`. It exercises
real Make/tested processes in disposable repositories: filtering, full/quick/
custom bundle isolation, assertion failures, compile failures, short timeouts,
and failed offline reports. A live-log handshake proves output reaches Make
before the selected Go test completes. Guard unit and Make E2E fixtures cover
accounting, process cleanup, resource refusal, cancellation, lock contention,
nonblocking output and Linux process-exit races. The subprocess fixture retains
exact descendant coverage through guarded test and report invocations.
Version fixtures exercise the public artifact command and validated `GITHUB_OUTPUT` values without publishing remotely.
Archive-checker unit fixtures cover missing targets, checksum failures, mixed
binaries, incorrect documents and Unix executable permissions. For GoReleaser
packaging changes, also run a real snapshot release and the archive checker per
the [packaging workflow](../release-and-versioning/references/ci-and-packaging.md#toolchain-and-packaging-checks);
fixture tests cannot establish cross-compilation or actual archive assembly.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.

## Generated Artifacts

Go's `./...` discovery does not honor `.gitignore`. Name temporary Go helpers
with a leading underscore, or put them in an underscore-prefixed directory,
so ignored working files do not become extra test/coverage packages. Confirm
the package list with `go list -mod=readonly ./...`. Keep source files in place
until both the covered test run and report generation finish: the coverage
renderer still reads them after tests exit. Preserve a failed bundle before
rerunning; do not remove source files or edit coverage profiles to repair it.

Treat these as generated outputs unless the user explicitly asks to preserve or
commit them:

```text
bin/authcrunch
bin/caddy-authenticator
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
.coverage/resource-usage.json
.coverage/resource-report-usage.json
.coverage/test-resource.lock
testdata/caddyfile_adapt/*_tmp_input.json
testdata/caddyfile_adapt/*_tmp_output.json
```

The manifest is published last for a coherent generation; a failed run can
leave only partial evidence. Inspect `run.json`, `stderr.log`, and
`test_output.jsonl` before rerunning so failures are not overwritten without
review. Also inspect `resource-usage.json` for budget or monitoring failures.
A running or aborted guard record prevents offline reporting from accepting older tested
evidence. Preserve interrupted bundles and rerun into a fresh directory.
Test output and coverage sources are unredacted; use synthetic fixtures.

Formatted Caddyfiles and JSON fixtures can be intentional source changes.
Review the diff after explicit format or fixture updates. Skill-only edits use
[skill-authoring](../skill-authoring/SKILL.md) and the default skill-creator
validator instead of running the Go suite.

## Acceptance criteria

- A code change is supported by unit and E2E evidence for its observable behavior;
  parser-only success cannot stand in for authentication, authorization, or restart.
- The relevant repo-local skills reflect the final code and validation evidence,
  following [keeping skills current](../skill-authoring/SKILL.md#keep-skills-current-after-code-changes).
  Review affected examples, test references, and acceptance scenarios before
  calling the code change complete.
- A failing test or scanner leaves its original status and diagnostic evidence
  visible. Offline report regeneration cannot convert a failure into a pass.
- A skill-only edit runs metadata, link, routing, and source checks. It does not
  trigger runtime, release, or conformance workflows merely to validate prose.
