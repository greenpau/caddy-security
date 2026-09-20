---
name: scripts-and-automation
description: caddy-security repository automation, Makefile targets, build/test/report workflows, CodeQL scans, caddy-authenticator profile login, and security local CLI administration. Use for standalone portal authentication, local-user, password, and API-key commands; repository scripts; local go-authcrunch replacement workflows; generated artifacts; or routing release tasks to release-and-versioning.
---

# Scripts and Automation

## Browser automation default

Use headless Chrome for browser automation and screenshot/network evidence.
Avoid Firefox unless explicitly requested for a browser-specific task. Follow
[the testing browser guidance](../testing-and-ci/SKILL.md#browser-choice) for
private profiles, reproducible tool pins and strict TLS trust. Keep all downloaded
browser tools and generated data in this repository's `tmp/`; do not install
browser packages or trust roots system-wide for a test run.

## Overview

Use the Makefile as the primary automation surface for this Go module. This
repository builds a Caddy command binary at `bin/authcrunch` from
`cmd/authcrunch/main.go`; the binary registers the `security` app, the
`authenticate` and `authorize` integrations, Caddy standard modules, and
`caddy-trace`.

For the independently installable `cmd/caddy-authenticator`, use the
[standalone authenticator reference](references/caddy-authenticator.md). It owns
profile-based portal login, private credentials/token/log storage, and the
command's user guide. Its implementation reuses `go-authcrunch/pkg/authclient`;
it does not load Caddy server modules or require the portal admin API.

Use [release-and-versioning](../release-and-versioning/SKILL.md) for version
authority, release target side effects, release CI, and publication. Use
[skill-authoring-patterns](../skill-authoring-patterns/SKILL.md) when creating
or updating the skills that document a workflow.

Prefer narrow `go test` commands for quick validation while editing. Use the
Makefile targets when the user asks for the repository workflow, reports,
release preparation, fixture formatting, or CI-like behavior.

## Command Selection

Follow the [repository scope](../coding-directives/SKILL.md#repository-scope),
including its sole exception for `../xcaddy-caddy-security`. Inspect working
directories, script side effects, cleanup paths, and output overrides before
execution. Run this module's automation; sibling source-module build, test,
formatting, license, dependency, and cleanup workflows remain out of scope.

- Use `go test ./...` for a fast all-package check without coverage reports.
- Use `go test -run <TestName> ./...` for focused validation.
- Use `make build` to validate `VERSION` and the authenticator fallback, compile
  `cmd/authcrunch` and `cmd/caddy-authenticator` into their corresponding `bin/`
  executables with `-mod=readonly -trimpath`, and print both versions. It injects
  `VERSION` into the authenticator's `main.appVersion` linker variable.
- Use `make` when the user asks for the default build; it runs `info` and
  `build`.
- Use `make test` for uncached, race-enabled Go tests and complete reports
  through pinned `go tool tested`. `TEST` is a regex, `TEST_DIR` accepts package
  patterns, and `TEST_TIMEOUT` is a quoted per-package duration (default `45m`).
  `MINIMUM_COVERAGE=1` checks for nonzero coverage; it is not a coverage goal.
- Use `make qtest` for the root package (`.`) by default, or set
  `QUICK_TEST_DIR` and `TEST` for another scope. Reports go to `.coverage/quick`.
- Use `make run-reports` to rebuild presentations from recorded tested evidence.
  It preserves failure status. `make coverage` is an alias for this operation;
  it does not rerun tests.
- Use `make test-automation` for verbose Python fixture tests of artifact
  identity, build metadata, and the real Make/tested lifecycle.
- Use `make scan-codeql` for a local Go scan, or set `CODEQL_LANGUAGE` to
  `javascript-typescript`, `python` or `actions` for the other CI languages.
  Use `make test-codeql` for real CLI regression fixtures in the selected
  language. Read the
  [CodeQL workflow](references/codeql.md) for CLI prerequisites, evidence,
  approved suppression policy, and findings review.
- Use `make oidc-conformance-prepare` and `make oidc-conformance-test` for the opt-in
  official Foundation plans against a fresh Caddy binary. Follow the
  [conformance workflow](../configuration-oauth-applications/references/oidc-conformance.md)
  for pinned local prerequisites, private evidence, strict TLS trust and
  preserved nonzero results. Conformance units/E2E and their artifacts are
  separate from regular testing; existing local OIDC regressions remain default.
  Set `CONFORMANCE_RESULTS` to a new directory below this checkout's `tmp/`;
  open its private `index.html` for explanations and links to all run evidence.
  Missing downloaded prerequisites require `make oidc-conformance-prepare`.
  Use `make oidc-conformance-help` for local tool locations and removal commands
  that preserve result bundles; it does not install or remove anything.
- Use the manual-only `OIDC conformance` Actions workflow for a downloadable
  report from a hosted runner. Its [setup and artifact reference](../configuration-oauth-applications/references/oidc-conformance-actions.md)
  explains the readable summary, complete report after one ZIP extraction,
  original runner status and failed-run uploads. This never joins regular CI.
- Use `make oidc-conformance-cleanup` to remove all identified OIDC result
  bundles under `tmp/`, including custom destinations and top-level supplemental
  `oidc-*` logs, audits and browser reports, plus `audit_oidc_*.py`/`check_oidc_*.py`
  helpers. Reserve these temporary names for generated OIDC output; prefer
  keeping new diagnostics inside their run bundle. Cleanup retains the prepared
  workspace, dependencies and caches, records custom dependency locations for
  repeated cleanup, and refuses active runs/preparation. It does not clean
  ordinary `.coverage/` or unrelated temporary files. See the
  [cleanup scope](../configuration-oauth-applications/references/oidc-conformance.md#remove-test-output-keep-prerequisites).
- Use `make ci-check` for sequential version, automation, full Go test/report,
  and build gates, including under `make -j`.
- Use `make version-check` for read-only version validation and
  `make artifact-id` for version/timestamp/commit identity and CI outputs.
  After an explicit VERSION edit, `make version-sync` updates the authenticator's
  Go install fallback without bumping or staging a release.
- Use `make fmtcfg` to format Caddyfile fixtures under
  `testdata/caddyfile_adapt` and `assets/config`; it requires an existing
  `bin/authcrunch`.
- Use `make clean` only when cleanup is requested; it removes generated
  `.coverage/` and `bin/` directories.

If documentation mentions `make ctest`, treat it as stale in this repository and
choose `make test`, `make qtest`, or direct `go test` instead.

## Tooling and Dependencies

Read the module's Go minimum and Caddy dependency from `go.mod`; inspect
`Makefile` separately for the Caddy version used by `devbuild`. CI explicitly
selects Go `1.26.8` with `GOTOOLCHAIN=local` and Node 24; Python 3.9+ runs
automation. The default Go suite requires Chrome/Chromium for Caddy browser
refresh E2E. Set `AUTHCRUNCH_TEST_BROWSER` when autodetection cannot find the
executable. Missing browser/Node prerequisites fail the test; no sibling UI
build or npm dependency installation is needed. See
[browser validation](../authentication-portal-api/references/browser-refresh.md#validation-in-this-repository).

`go.mod` and `go.sum` pin `github.com/greenpau/tested` and the release tool
`github.com/greenpau/versioned/cmd/versioned`; use `go tool tested` and
`go tool versioned`. `make dep` downloads/verifies module
dependencies and resolves tested. `make install-test-tools` runs its version
command without global installs or module edits. The other maintenance tools,
such as `xcaddy` for `devbuild` and `versioned` for the license
recipes, must already be on `PATH`; `make dep` does not install them.
`make license` selects tracked and nonignored new Go files through Git. It must
not traverse ignored `tmp/`, suite checkouts, tool caches or vendored modules;
rewriting those files would invalidate the unmodified dependency evidence.

Module/tool downloads and `xcaddy` can need network access. Tests and builds
do not run module tidy, license rewrites, download-link regeneration, or
Caddyfile formatting. Use explicit maintenance targets when those changes are
intended.

## Development Builds

`make devbuild` uses the explicitly permitted `../xcaddy-caddy-security`
workspace. It removes files there, changes into that directory, and runs
`xcaddy` to build Caddy with this module, the static secrets manager,
`caddy-trace`, and a local go-authcrunch replacement. The final binary is
`bin/authcrunch` in this repository.

Use this target when an integrated xcaddy build is needed. Check the actual
workspace and cleanup paths before running it, including whether a symlink
redirects them. The exception is limited to `../xcaddy-caddy-security`;
overriding `PLUGIN_NAME` must not redirect writes to another sibling. The
Makefile hard-codes the go-authcrunch replacement path in a `--with ...=...`
argument; verify it selects the intended existing checkout, and keep that
checkout read-only. Use `make build` when the normal Caddy wrapper meets the
task.

## Local go-authcrunch Development

For an explicitly requested published version, use a targeted upgrade from this
repository, for example `go get github.com/greenpau/go-authcrunch@v1.2.6`, then
`go mod tidy` and `go mod verify`. Inspect the dependency diff and keep the
versioned replacement examples in `CONTRIBUTING.md` and the xcaddy argument in
`Makefile` aligned. Do not use `make upgrade` for a single-module request: it
updates all dependencies. `make sync` takes its version from the sibling's
`VERSION`, which may differ from the requested release. Confirm the selected
module's `Dir` and absence of an unintended `Replace` before validation.

For official OIDC qualification of newer committed work, select its exact
published commit with `go get github.com/greenpau/go-authcrunch@<commit>`.
The resulting immutable pseudo-version must match the intended sibling revision;
the conformance harness rejects local replacements. Record the selected module
checksum and origin, and keep sibling source and Git state read-only.

Development in `caddy-security` often connects this module to a local
`github.com/greenpau/go-authcrunch` checkout that sits next to the
`caddy-security` directory in the filesystem tree. If `caddy-security` is at
`<parent>/caddy-security`, assume `go-authcrunch` is at
`<parent>/go-authcrunch`; from this repository, that path is
`../go-authcrunch`.

Use a Go module replacement when the task requires consuming existing local
`go-authcrunch` changes. Edit only this repository's `go.mod` and validate this
module; do not develop, format, tidy, or test the sibling checkout. Read the
currently required `go-authcrunch` version from this repository's `go.mod`:

```bash
go list -m -f '{{.Version}}' github.com/greenpau/go-authcrunch
```

Then use that required version in the replacement command:

```bash
go mod edit -replace github.com/greenpau/go-authcrunch@<go-authcrunch-version-from-go.mod>=../go-authcrunch
```

Keep the replacement while this module intentionally depends on existing
unreleased upstream changes. Upstream implementation and publication happen
as separate work. Once the required version is available, update this
repository's dependency, remove its local replacement, and test here.
`make sync` removes local go-authcrunch replacements after updating references;
it must not be used as a reason to edit or release the sibling first.

After changing the selected Caddy or go-authcrunch version, audit delegated
Caddyfile grammar and examples using
[Syntax maintenance](../configuration/references/syntax-maintenance.md).
A dependency update can change accepted directives even when no local parser
switch changes. Refresh the owning configuration skills and syntax comments.

## Asset and Documentation Scripts

`assets/scripts/generate_downloads.sh` rewrites Caddy download links in
`README.md`. See [release-and-versioning](../release-and-versioning/SKILL.md)
for version inputs and regeneration requirements. It is called by
`make release`, `make minor-release`, their `fast-` variants, and `make license`.

`assets/scripts/update_doc_refs.sh` reads `../go-authcrunch/VERSION`, updates
go-authcrunch references in `CONTRIBUTING.md`, `Makefile`, and `go.mod`, removes
local go-authcrunch replace directives from `go.mod`, then runs `go mod tidy`,
`go mod verify`, `make`, and `make test`. `make sync` invokes this script.

Use `make sync` only for an explicit go-authcrunch reference refresh. The script
assumes a sibling `../go-authcrunch` checkout and uses BSD/macOS `sed -i ''`
syntax. The sibling `VERSION` is an input only; all reference updates, module
commands, builds, and tests run in `caddy-security`.

## Other Targets

- `make upgrade` runs `go get -u ./...` and `go mod tidy`; use it only for an
  explicit dependency upgrade.
- `make license` applies the repository license header to every Go file with
  `versioned` and regenerates download links; expect broad source changes.
- `make logo` requires GraphicsMagick `gm` and rewrites
  `assets/docs/images/logo.png`.
- `make linter` is currently a placeholder and does not run `golint`.

## Generated Artifacts

Do not treat generated outputs as source changes unless the user explicitly asks
to update or commit them.

- `bin/authcrunch` is produced by build/devbuild targets; `make build` also
  produces `bin/caddy-authenticator`.
- `.coverage/` contains the tested HTML/JSON/JUnit reports, raw test output,
  coverage profile, stderr, run metadata, and generation manifest. Start at
  `.coverage/index.html`; see `testing-and-ci` for the complete evidence layout.
- `.coverage/codeql/` holds local scan databases, raw and reviewed SARIF/CSV,
  suppression audits, logs, and retained regression fixtures.
  Its evidence is separate from tested's report bundle;
  `make clean` removes both. Local CodeQL does not upload or dismiss alerts.
- `../xcaddy-caddy-security` is the permitted devbuild workspace. Only that
  sibling workspace may be created, refreshed, or cleaned for xcaddy builds.

Formatted Caddyfiles, README download links, `VERSION`, `go.mod`, and
`go.sum` can be intentional source changes depending on the target. Review the
diff before deciding whether to keep them.

`COVERAGE_DIR` selects the report directory. Keep overrides inside this checkout;
independent concurrent runs need separate directories. Let tested refresh only
its managed artifacts: do not recursively delete report directories in test
targets. Full, quick, and custom bundles and unrelated investigation files must
survive one another's runs.
Whole-directory cleanup belongs to the explicitly requested `make clean`.

Normal coverage reports include the root test executable's E2E subprocesses
through Go's native coverage merge. See
[subprocess coverage](../testing-and-ci/SKILL.md#subprocess-coverage) for the
bootstrap, regression tests and limits. Keep merging before tested evaluates
coverage and writes reports; never patch a finished bundle's coverage percentage.

## CI Notes

The reusable `.github/workflows/build.yml` runs `make dep` and `make ci-check`,
checks source remains unchanged, and uploads the complete `.coverage/` bundle
after an attempted gate, including failure evidence. Release CI requires this
same gate. Follow `testing-and-ci` for local reproduction and
`release-and-versioning` for artifact identities and tag requirements.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.

## Security Dependency Version

Run `bin/authcrunch security version` to print the go-authcrunch module linked
into the executable, for example `go-authcrunch v1.2.6`. This uses
`runtime/debug.ReadBuildInfo` and works without a config, server, credentials,
Go installation or source checkout. Do not substitute the caddy-security
`VERSION`, a working-directory go.mod, or the authdb package's version banner.
`bin/authcrunch version` continues to report Caddy's version.

Preserve pseudo-versions and module replacements in diagnostics. A replacement
prints `go-authcrunch <required-version> => <replacement-path> <replacement-version>`;
an unversioned local replacement uses `(devel)`, so the required release is not
mistaken for the actual checkout. Missing build metadata prints
`go-authcrunch unknown`. `command_security.go` owns registration and formatting;
its unit tests and `TestCaddySecurityVersionE2E` cover the command contract.

## Local OAuth Provisioning

The built binary registers the `security` command group through Caddy's command
extension API. It is separate from adapt, validate, run, reload, and Make maintenance.
Use nested command words for the domain, action, and resource, such as
`bin/authcrunch security oauth create application`. Follow this pattern for future
security commands.
Use `oauth init provisioning store` for storage of OAuth application credentials and
OIDC provider signing keys; reserve user-registration terminology for user sign-up.
Use [Private provisioning and activation](../configuration-oauth-applications/references/private-provisioning.md)
for the private input grammar and `oauth init provisioning store`,
`oauth create application`, `oauth rotate secret`, and `oidc create signing key`
subcommands, explicit revision activation, and interrupted-writer recovery.
Each provisioning command prints only the resulting path; it never prints client
secrets or private keys.

## Local User Administration

Use [Local user commands](references/local-user-commands.md) for
`security local` client configuration, login, local realm/user inspection,
account creation/deletion, password resets, roles/challenges, realm reload,
and offline password/API-key generation. Remote operations use the portal's
admin API; generators work offline and never modify database files.
