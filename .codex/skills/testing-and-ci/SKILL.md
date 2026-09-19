---
name: testing-and-ci
description: caddy-security unit and E2E coverage requirements, Caddyfile adaptation and runtime resolution fixtures, pinned tested reports, automation tests, CodeQL validation, and reusable GitHub Actions gates. Use when writing or changing code, choosing or running tests, updating coverage, interpreting CI failures, reproducing CI locally, or validating report and artifact workflows.
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
`skill-authoring-patterns`; they do not require new runtime tests.

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

Lifecycle runs use `-mod=readonly -race -count=1 -timeout 45m -v`.
`TEST` is a regex (default `.`), `TEST_DIR` accepts package patterns (default
`./...`), and `TEST_TIMEOUT` overrides the quoted per-package limit.
`MINIMUM_COVERAGE` defaults to 1 percent as a nonzero-profile check, matching
go-authcrunch; it is not a substantial coverage target.

Go's timeout covers the entire package, including all sequential E2E parent
tests. The Caddy journeys also have their own shorter child-process deadlines.
If CI times out, inspect the captured test events and active test duration to
distinguish an exhausted package budget from a stuck individual journey.
Keep the job budget larger than the package budget so setup, builds and report
upload can finish; the current workflow allows 60 minutes around the 45-minute
Go package limit.

Reports land in `.coverage`. `make qtest` defaults to the root package (`.`) with
reports in `.coverage/quick`; override `QUICK_TEST_DIR` and `TEST` for another
scope. Use `COVERAGE_DIR` to isolate independent concurrent runs. Let tested
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

Automation fixtures must create their own generated parent directories before
calling `TemporaryDirectory` or `mkdtemp`. A fresh checkout has no ignored
`tmp/` directory; another test must not be responsible for creating it. When
fixing fixture setup, run the affected test alone in a disposable checkout
without `tmp/`, then run `make test-automation`. Preserve existing workspaces
and report bundles while checking this condition.

### CodeQL scanning

The separate `.github/workflows/codeql.yml` analyzes Go, JavaScript/TypeScript,
Python and Actions with the complete default suites. Local `make scan-codeql`
uses the same checked-in configuration; `CODEQL_LANGUAGE` defaults to `go`.
`.github/codeql/suppressions.json` records the four owner-approved findings.
The shared SARIF filter matches exact rules, paths and CodeQL fingerprints,
preserving raw evidence and an audit. No sibling logging exception applies
automatically. Follow the [CodeQL workflow](../scripts-and-automation/references/codeql.md)
for tool selection, output boundaries, report review and GitHub activation.

`assets/scripts/tests/codeql_test.py` exercises the actual shell helper with a
fake CLI to verify stage failure propagation, per-language build selection,
source-root isolation, quoted paths, fresh evidence and rejected output escapes.
It runs in `make test-automation`, alongside `codeql_filter_test.py`, which
checks approval matching, negative boundaries, retained CSV results, audit
identity, failed-analysis refusal and evidence preservation. `make test-codeql`
runs the real CLI against isolated sources under `.coverage/codeql/`. It
compares raw default results to the unmodified upstream suite, then verifies
approved suppressions and retained neighboring findings in both default and
extended suites. The actual Python and CommonJS test harnesses are copied as
static fixture inputs; they are not executed. Go cases retain debug/ordinary
sensitive logging, SQL injection and other password hashes. JavaScript, Python
and Actions retain code injection, and Actions retains an unpinned-action case.

Run automation tests and real fixtures for all four languages when changing
shared scanning behavior. CLI absence is a failure, not a skipped test. The
CodeQL matrix verifies its own language and applies the shared filter before
uploading reviewed primary SARIF; raw results and suppression audits are
retained as artifacts even after failure. `make ci-check` keeps its existing tool
requirements and does not invoke CodeQL. A successful scan can contain alerts;
do not describe a successful scanner invocation as a vulnerability-free result.

### Subprocess coverage

`subprocess_coverage_test.go` owns the root package's `TestMain`. When Go enables
coverage, it connects inherited `GOCOVERDIR` to `-test.gocoverdir`.
`collectSubprocessCoverage(t, cmd)` assigns each child a private temporary
directory and collects its completed files during parent test cleanup, before
Go's native profile writer merges counters from the parent and descendants
running the same instrumented test executable,
including nested E2E helpers and CLI helpers that exit through `os.Exit`.
Call the collector after setting `cmd.Env` and before starting every copy of the
test executable, including PTY brokers that launch it. Always wait for the child
before returning from its parent test. Cleanup publishes files atomically on
the destination filesystem, so parallel children cannot race Go's metadata
writes. Do not share a writable coverage directory between children or forward
the parent's `-test.coverprofile` flag. Preserve process deadlines, exit status
checks and isolation; never reuse a persistent counter directory across runs.

This applies automatically to `go test -coverprofile=...`, `make test` and
`make qtest`. The merged profile reaches tested before its coverage threshold,
HTML/JSON/JUnit generation and manifest creation; `make run-reports` reuses that
profile. There is no report rewrite or extra postprocessing step. Ordinary
`go test` without coverage is unchanged. The `Test*Process` entries still skip
in normal discovery because their parent tests run them in isolated processes;
keep these truthful skip outcomes visible.

Coverage is limited to the selected instrumented packages and executable.
Separately built CLI binaries are not instrumented by this hook. Killed or
panicking processes can lose unflushed counters; do not alter interruption tests
or suppress their failures to obtain coverage. Official OIDC conformance remains
separate and opt-in.

`TestConfigureSubprocessCoverage` covers flag/environment precedence and inactive
coverage. `TestCollectCoverageFiles` verifies concurrent publication, partial-file
exclusion and collection failures. The automation test
`assets/scripts/tests/subprocess_coverage_test.py` copies the actual bootstrap
into a disposable module under `tmp/` and checks exact parent, parallel
child, grandchild and CLI counters through Go and Make/tested. It also checks
failed-child evidence, coverage thresholds, untouched code, set/count/atomic
modes, fresh filtered runs, custom paths and quick/report regeneration. Run it
with `make test-automation`, then use the real Caddy E2E report to validate the
integrated change.

### Feature suites

`TestCaddyOperatorExamplesE2E` qualifies every complete input under
`assets/config/integration/` through Caddy adaptation, validation, provisioning
and TLS journeys, then reloads generated native JSON independently. The
[operator example reference](../configuration/references/operator-examples.md)
describes private artifact retention and the exact scenario coverage. Keep
those examples in the default gate and test their behavior, not just JSON shape.

Official OP conformance runs only through `make oidc-conformance-test`, with its
own private artifacts. The harness and its unit tests are excluded from regular
Go tests, `make test-automation`, and `make ci-check`. Existing local OIDC
regressions stay in regular testing. The official runner's original nonzero
outcome remains a failure; warnings, skips and reviews are never an all-pass claim.
See [official OP conformance](../configuration-oauth-applications/references/oidc-conformance.md)
for prerequisites, isolated artifacts and all remaining non-pass modules.
The separate `OIDC conformance` GitHub workflow is manual-only and invokes these
same Make targets. Follow [conformance Actions](../configuration-oauth-applications/references/oidc-conformance-actions.md)
for the public encryption recipient, report artifact and failure-preserving
upload. Never upload plaintext private evidence or add conformance to regular CI.
OIDC conformance units live in `assets/scripts/oidc_certification_conformance_tests/`
and use `test_oidc_conformance_*.py` filenames. Keep them out of the regular
automation discovery directory. `test_oidc_conformance_cleanup.py` exercises
deletion boundaries for bundles and supplemental logs/audits/browser profiles,
retention of custom dependencies across repeated cleanup, active-run guards and
the real Make cleanup recipe in a disposable repository. Never delete
historical official evidence as a unit-test
side effect. `make oidc-conformance-cleanup` is an explicit artifact-deletion
target; it preserves tools, the suite and caches for the next opt-in run.
The default `TestCaddyOIDCRelyingPartyE2E` also covers v1.2.6 claims, ACR,
registered RS256 Request Objects and OIDC refresh rotation/replay through real
Caddy TLS. Its discovery expectations track the selected dependency's capability surface;
these local tests do not launch the official suite.
The same RP E2E preserves the provider-owned themed page headers at root and
nested issuer mounts. It checks the consent referrer/CSP restrictions, unchanged
discovery/callback headers, and rejection of null/cross-origin and forged-CSRF
consent submissions. The official workflow additionally exercises the real
Chrome form Origin, both authentications, and the exact screenshot evidence slots.
`CONFORMANCE_RESULTS` selects a new private destination under this checkout's
`tmp/`; its `index.html` links and explains the full evidence, including blocked
or incomplete runs. Report tests are part of the same opt-in target only.

MFA E2E fixtures use independent identities/databases for separate successful
login journeys. Repeated CLI logins for the same account wait for an unused
real TOTP time step; never clear persisted replay counters or disable MFA to
reuse a code. The authentication-client E2E also rejects TOTP replay through
username-case and email aliases.

HTTPS delegation unit fixtures must model inbound requests: use
`httptest.NewRequest` with an HTTPS target and an origin-form `RequestURI`.
An outbound `http.NewRequest` has no server TLS state; an absolute-form test
target also differs from the ordinary Caddy request. Both can fail upstream
Origin validation before the authentication condition under test. The shared
refresh HTTP matrix checks unauthenticated protected routes and cross-origin
API rejection through unit delegation and actual Caddy TLS.

For cross-feature changes, use the
[composed qualification map](references/composition-qualification.md).
`TestCaddyCompositionE2E` covers the actual Caddy TLS feature matrix, edge trust,
credential-purpose isolation, replacement failure/recovery, current roles,
reload/disposal and combined Chromium flow. Run it with the existing browser
refresh suite under race detection; preserve its bounded single-process scope.
Include `TestAuthzSourceTrust` for cached source-bound authorization and
`TestCaddyRefreshBrowserTrust` for the fresh-profile trust boundary. Browser
journeys must reject untrusted certificates and hostname mismatches before
testing login; do not replace these controls with certificate-error allowances.

`TestSecurityAuthcrunchVersion` and `TestSecurityVersionCommand` cover embedded
dependency versions, replacements, missing metadata, command dispatch and output
failures. `TestCaddySecurityVersionE2E` compiles the real Caddy wrapper with
trimpath and stripped symbols, compares `security version` with Go's selected
dependency, and runs outside the checkout without Go on PATH or user-state writes.
Run these and the `TestSecurityCommand*`/`TestCaddySecurityCommand*` registration,
help and redacted-error tests when changing `security version`.

`cmd/caddy-authenticator/*_test.go` covers profile/configuration parsing, command
selection, private persistence, logging and transport/input failure behavior.
`TestCaddyAuthenticatorE2E` builds the standalone command and checks password,
MFA, API keys, native metadata, independent authorization and profile isolation
through actual Caddy TLS with admin/profile APIs disabled. On Unix it also runs
the Python 3 PTY broker for pasted setup, hidden input and terminal restoration
at password and TOTP prompts. Regressions cover symlink-sensitive CA paths,
explicit empty home overrides and state preservation when logging rejects an
operation. Unit tests verify the 45s default and overridden command deadlines;
PTY tests verify non-interactive defaults and `--interactive` prompt opt-in.
`TestCaddyAuthenticatorVersionE2E` verifies actual Go install naming, fallback
version and linker metadata without user-state access. Automation fixtures
check Make builds, failure propagation and fallback synchronization. Run these
along with cached-token/expiry/forced-login and native-refresh tests, including
lost committed responses and prevention of replay across commands,
when changing the standalone CLI or the authclient dependency; see the
[command validation map](../scripts-and-automation/references/caddy-authenticator.md#validation).

`TestAuthzPathDelegation` and `TestCaddyAuthorizationPathE2E` cover the v1.2.5
authorization path contract through the provider and real Caddy TLS. Run them
when changing gatekeeper delegation, bypasses, path claims or the selected
dependency. They check decoded/cleaned paths before and after identity caching,
literal wildcard grants, downstream reachability and unchanged request URIs
over HTTP/1.1 and HTTP/2; see
[authorization behavior](../configuration-authorization/SKILL.md#policy-options).

`TestAuthenticationClientConfigAdapter` covers the existing outbound YAML adapter
and the dedicated public authclient parser. `TestAuthenticationClientConfigWhitespace`
checks exact credential preservation and prevents silently repaired options;
`TestAuthenticationClientLegacyWire`
checks omission of the refresh extension with a strict legacy schema.
`TestAuthnJSONLoginDelegation` compares native/JSON rejection responses with
direct portal dispatch, checking request headers/URL and response metadata at
root/nested mounts. Its error cases also run through Caddy TLS.
`TestCaddyAuthenticationClientE2E` covers password/MFA and API-key JSON login
through actual Caddy TLS with admin/profile APIs disabled, private credential
reopening, independent resource authorization, explicit native refresh/logout,
and the existing CLI consumer. It includes in-flight HTTP cancellation with
server request counts, cookie-mode MFA metadata-only completion, dropped native
transport at checkpoints, and rejected browser/native mixtures without consuming
the refresh family. See the
[native interoperability test map](../authentication-portal-api/references/native-client.md#caddy-validation).

Local identity provisioning/reset units are in `local_identity_test.go`.
`profile_public_key_test.go` checks public parser metadata and binary rejection.
`TestCaddyLocalIdentityE2E` covers TLS login identity/realm/MFA combinations,
management/profile credential mutations, reload invalidation, stateless access,
and persisted user public keys. See
[local identity compatibility](../configuration-identity-stores/references/local-identity.md#caddy-validation).
The default `TestCaddyProfileCanonicalIdentityRegression` verifies transformed
claims cannot select another local account after the upstream fix; see
[profile isolation](../authentication-portal-api/references/profile-public-keys.md#canonical-profile-identity-regression).

Runtime ownership unit tests live in `app_lifecycle_test.go`.
`TestCaddyLifecycleE2E` in `app_lifecycle_e2e_test.go` launches a bounded child
process with real Caddy listeners and reloads; `TestCaddyLifecycleProcess` is
its subprocess helper. Use these for app/plugin lifecycle changes, including
drain ordering, abandoned candidates, shared providers, and worker disposal.
Read the [runtime lifecycle reference](../coding-directives/references/runtime-lifecycle.md#validation)
for the precise scenarios and host limitations.

Parser tests use inline Caddyfile snippets and `caddyfile.NewTestDispenser`.
They call parser functions, unpack generated JSON into maps, and compare with
`cmp.Diff`. Whitespace in inline `want` JSON is not semantically important.
Add or update these tests when directive parsing behavior changes:

- `caddyfile_authn_test.go`: authentication portal parsing.
- `caddyfile_authn_oidc_test.go`: provider grammar, forward/imported application
  references, disabled validation, and JSON restoration. `oidc_config_test.go`
  covers conflicts across portal issuers. `TestCaddyOIDCProviderE2E` in
  `oidc_e2e_test.go` covers actual TLS provisioning, discovery, two selected local
  realms and an unselected realm, realm identity and session revocation when
  switching realms in one browser, independent issuers/cookies, signed token
  exchanges, refresh alignment, and continued service after rejected reloads.
- `plugin_authn_test.go`: `TestAuthnOIDCDelegation` compares the middleware's
  response and canonical URL with direct portal dispatch. `oidc_rp_test.go`
  checks the independent RSA relying-party verifier against corrupted signatures,
  claims and public key sets. `oidc_rp_response_test.go` checks the RP's callback
  and form parsing against ambiguous parameters, incorrect POST forms and
  weakened CSP; the E2E client submits the returned consent action and controls.
- `TestCaddyOIDCRelyingPartyE2E`: bounded real Caddy TLS at root/nested mounts,
  discovery, password/TOTP, consent, client authentication, prompts/max_age,
  code+S256, form-post CSP, UserInfo, replay, revocation/logout, token purposes,
  CORS and unsigned request objects. `oidc_loopback_e2e_test.go` is exercised
  by this parent and requires actual IPv4/IPv6 ephemeral callback listeners.
  `TestCaddyRegistrationE2E` covers process restart at the same issuer URL,
  stable client/key identity, secret rotation and retained rollover verification.
  Use the [OIDC validation map](../configuration-oauth-applications/references/oidc-provider.md#validation-surfaces)
  for the full test group and limits; local E2E is not Foundation certification.
- `caddyfile_authn_token_refresh_test.go`: complete readable refresh grammar,
  opt-out/defaults, imports/duplicates, placeholders and native/deferred JSON.
  `TestCaddyTokenRefreshE2E` verifies real TLS password login and rotation at
  parsed root/nested mounts, realm participation, cookie overrides, lifetime
  caps, native opt-in/off, capacity/replay/rotation limits and rejected mounts.
  Its adaptation/resolution fixture is `testcase_authenticate_with_token_refresh`.
  See [portal refresh](../configuration-authentication/references/token-refresh.md#validation).
- `TestAuthnTokenRefreshDelegation` covers strict HTTP dispatch, protected APIs,
  the exact embedded refresh asset and continuation pages. The normal Go suite
  also runs `TestCaddyTokenRefreshBrowserE2E` with real Chrome/Chromium and Node 24;
  `TestCaddyRefreshBrowserStartup` covers process readiness/cleanup failures.
  See [browser validation](../authentication-portal-api/references/browser-refresh.md#validation-in-this-repository)
  for two-tab coordination, committed-response loss and prerequisite overrides.
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
Use this path for every Caddyfile directive change, including syntax, defaults,
validation, and config mapping.

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
and reusable workflow calls. It selects Ubuntu 24.04 and Go `1.26.8` with
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

Use [release-and-versioning](../release-and-versioning/SKILL.md) for release CI,
tag selection, artifact naming, packaging checks, and publication scope. The
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
and failed offline reports. Version fixtures exercise the public artifact
command and validated `GITHUB_OUTPUT` values without publishing remotely.
Archive-checker unit fixtures cover missing targets, checksum failures, mixed
binaries, incorrect documents and Unix executable permissions. For GoReleaser
packaging changes, also run a real snapshot release and the archive checker per
the [packaging workflow](../release-and-versioning/references/ci-and-packaging.md#toolchain-and-packaging-checks);
fixture tests cannot establish cross-compilation or actual archive assembly.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.

## Generated Artifacts

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
