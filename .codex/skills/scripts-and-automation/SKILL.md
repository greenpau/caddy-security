---
name: scripts-and-automation
description: caddy-security repository automation, Makefile target selection, local build/test/report/coverage commands, local go-authcrunch go.mod replacement shim workflow, asset and documentation update scripts, release/version workflows, generated artifact handling, and guardrails for dependency, devbuild, cleanup, and release actions. Use when choosing, running, documenting, or updating repository scripts and Make targets; troubleshooting CI/build/test automation; coordinating caddy-security development with local go-authcrunch changes; refreshing Caddyfile/config fixtures; deciding whether generated outputs belong in a change; or preparing releases for this Go/Caddy module.
---

# Scripts and Automation

## Overview

Use the Makefile as the primary automation surface for this Go module. This
repository builds a Caddy command binary at `bin/authcrunch` from
`cmd/authcrunch/main.go`; the binary registers the `security` app, the
`authenticate` and `authorize` integrations, Caddy standard modules, and
`caddy-trace`.

Prefer narrow `go test` commands for quick validation while editing. Use the
Makefile targets when the user asks for the repository workflow, reports,
release preparation, fixture formatting, or CI-like behavior.

## Command Selection

- Use `go test ./...` for a fast all-package check without coverage reports.
- Use `go test -run <TestName> ./...` for focused validation.
- Use `make build` to compile `cmd/authcrunch/main.go` into `bin/authcrunch`,
  print the binary version, and format `assets/**/Caddyfile` files.
- Use `make` when the user asks for the default build; it runs `info` and
  `build`.
- Use `make test` for the full local workflow: create `.coverage`, install test
  report tools if missing, run `go test -json -v ./...`, write
  `.coverage/test_output.jsonl`, generate coverage and test-output reports, and
  fail if any JSON test action failed. Review the resulting
  `.coverage/coverage.html` and `.coverage/test_output.html` files in a browser
  for easy coverage and test-output inspection.
- Use `make qtest` only when the Makefile's current `QUICK_TEST_PATTERN` is the
  desired scope. Prefer direct `go test -run ... ./...` instead of editing the
  Makefile just to run a different quick test.
- Use `make run-reports` only after `.coverage/test_output.jsonl` and
  `.coverage/coverage.out` exist.
- Use `make coverage` after a previous coverage run or `make test`; the target
  reads `.coverage/coverage.out` before it refreshes coverage.
- Use `make fmtcfg` to format Caddyfile fixtures under
  `testdata/caddyfile_adapt` and `assets/config`; it requires an existing
  `bin/authcrunch`.
- Use `make clean` only when cleanup is requested; it removes generated
  `.coverage/` and `bin/` directories.

If documentation mentions `make ctest`, treat it as stale in this repository and
choose `make test`, `make qtest`, or direct `go test` instead.

## Tooling and Dependencies

The module declares Go `1.25.0` and Caddy `v2.11.2`.

- `make dep` installs developer tools with `go install`, including `golint`,
  `xcaddy`, `versioned`, and `richgo`.
- `make install-test-tools` installs `richgo`, `tparse`, and
  `go-test-report` if they are missing.
- `go mod tidy`, `go mod verify`, `go mod download`, `go install`, and `xcaddy`
  may require network access.

When a dependency or module command fails because of sandboxed network access,
rerun it with the normal escalation flow instead of replacing the repository
workflow with an ad hoc workaround.

## Development Builds

`make devbuild` uses `xcaddy` to build Caddy into `bin/authcrunch` with this
module, `caddy-security-secrets-static-secrets-manager`, `caddy-trace`, and a
local `go-authcrunch` replacement. It also writes to the sibling directory
`../xcaddy-caddy-security` and assumes `go-authcrunch` is checked out next to
`caddy-security` as `../go-authcrunch`.

Run `make devbuild` only when the user explicitly wants that integrated local
Caddy build and the sibling checkout/path assumptions are acceptable.

## Local go-authcrunch Development

Development in `caddy-security` often connects this module to a local
`github.com/greenpau/go-authcrunch` checkout that sits next to the
`caddy-security` directory in the filesystem tree. If `caddy-security` is at
`<parent>/caddy-security`, assume `go-authcrunch` is at
`<parent>/go-authcrunch`, such as `~/dev/src/github.com/greenpau/caddy-security`
paired with `~/dev/src/github.com/greenpau/go-authcrunch`, or
`~/foo/caddy-security` paired with `~/foo/go-authcrunch`.

Use a Go module replacement when the user is aligning `caddy-security` changes
with parallel local `go-authcrunch` work. Read the currently required
`go-authcrunch` version from this repository's `go.mod`:

```bash
go list -m -f '{{.Version}}' github.com/greenpau/go-authcrunch
```

Then use that required version in the replacement command:

```bash
go mod edit -replace github.com/greenpau/go-authcrunch@<go-authcrunch-version-from-go.mod>=../go-authcrunch
```

The replacement shim in `go.mod` should generally stay while `caddy-security`
depends on local `go-authcrunch` changes that are still in progress.

In the normal sequence, `go-authcrunch` changes first, such as implementing a
new feature, and then `caddy-security` changes to use that feature through the
local replacement. After there are no more `go-authcrunch` changes, and the
target `go-authcrunch` version has been updated, remove the local `replace`
directive, sync `caddy-security` to the new `go-authcrunch` version, and test.
`make sync` removes local go-authcrunch replacements after updating references.

## Asset and Documentation Scripts

`assets/scripts/generate_downloads.sh` rewrites Caddy download links in
`README.md` using `VERSION`, `github.com/greenpau/caddy-security`, and the
hard-coded `github.com/greenpau/caddy-trace` version. It is called by
`make release-update-version` and `make license`.

`assets/scripts/update_doc_refs.sh` reads `../go-authcrunch/VERSION`, updates
go-authcrunch references in `CONTRIBUTING.md`, `Makefile`, and `go.mod`, removes
local go-authcrunch replace directives from `go.mod`, then runs `go mod tidy`,
`go mod verify`, `make`, and `make test`. `make sync` invokes this script.

Use `make sync` only for an explicit go-authcrunch reference refresh. The script
assumes a sibling `../go-authcrunch` checkout and uses BSD/macOS `sed -i ''`
syntax.

## Release and Version Targets

Treat release targets as human-operator actions unless the user explicitly asks
for a release workflow.

- `make release-git-check` runs `go mod tidy`, `go mod verify`, requires the
  current branch to be `main`, and requires a clean git worktree.
- `make release-update-version` runs `versioned -patch`, refreshes README
  download links, and stages `VERSION`, `README.md`, `CONTRIBUTING.md`, and
  `Makefile`.
- `make release-git-commit` creates a release commit, creates an annotated tag,
  pushes commits, and pushes tags.
- `make release` chains `release-git-check`, `build`, `release-update-version`,
  and `release-git-commit`.
- `.github/workflows/release.yml` runs GoReleaser on `v*` tags or manual
  dispatch. `.goreleaser.yaml` builds `cmd/authcrunch` for Linux, Windows, and
  Darwin on `amd64` and `arm64`.

Never push commits or tags, create release tags, or run the chained release
target unless the user has explicitly requested that action.

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

- `bin/authcrunch` is produced by build/devbuild targets.
- `.coverage/coverage.html`, `.coverage/coverage.out`,
  `.coverage/test_output.jsonl`, and `.coverage/test_output.html` are produced
  by `make test` and report targets. They contain coverage stats and test output
  reports; the HTML files are browser-friendly review artifacts.
- `../xcaddy-caddy-security` is produced by `make devbuild` outside the repo.

Formatted Caddyfiles, README download links, `VERSION`, `go.mod`, and
`go.sum` can be intentional source changes depending on the target. Review the
diff before deciding whether to keep them.

## CI Notes

The build workflow runs on Ubuntu with Go `1.25.x`. It installs `make` and
`libnss3-tools`, runs `make dep`, `go mod tidy`, `go mod verify`,
`go mod download`, `make test || true`, `make test`, then `make coverage`, and
uploads `.coverage/coverage.html`.

The CLA workflow may update `assets/cla/signatures.json` through GitHub
automation. Do not edit CLA signatures or consent files unless the user asks.
