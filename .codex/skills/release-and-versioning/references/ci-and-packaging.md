# Release CI and Packaging

Read this reference when reviewing release workflows, qualifying a packaged
binary, or changing artifact/changelog generation. The sources of truth are
`.github/workflows/release.yml`, `.github/workflows/build.yml`,
`.goreleaser.yaml`, and `assets/scripts/generate_go_authcrunch_changelog.sh`.

## Workflow and Artifact Identity

The release workflow triggers on pushed `v*` tags and `workflow_dispatch`.
Both paths must target the exact annotated `v<VERSION>` tag. Manual dispatch on
a branch fails the publication check; it does not switch to a different tag.
The checked revision is therefore the same revision qualified by the reusable
test workflow. Checkout retrieves full history for release notes and tag checks.

The `validate` job calls `.github/workflows/build.yml`; GoReleaser requires its
success. That gate runs `make ci-check` and uploads tested reports. The
publication job also validates `VERSION`, exact tag equality, and annotated tag
type before generating release notes or publishing. Test/build actions use
immutable revisions, checkout does not persist credentials, and
`contents: write` is confined to the publishing job.

GoReleaser uses the pinned v6.3.0 action with tool version `v2.18.1` and
`release --clean --timeout 60m`, matching the sibling's tool selection. The
configuration declares schema version 2. Keep action and tool upgrades explicit
and qualify the config against the selected version.

`.goreleaser.yaml` uses project name `authcrunch` and publishes both commands to
`greenpau/caddy-security`. Both build IDs target Linux, Windows and Darwin on
`amd64` and `arm64`, with `CGO_ENABLED=0`, `-mod=readonly`, trimpath and `-s -w`:

- `authcrunch` builds `./cmd/authcrunch` as `./bin/authcrunch`. Its archive keeps
  the existing GoReleaser name/format defaults and includes only this build.
  The `nfpms` configuration is also explicitly scoped to this build. No nFPM
  output formats are configured, so it currently produces no Linux packages.
- `caddy-authenticator` builds `./cmd/caddy-authenticator` as
  `caddy-authenticator` (with `.exe` on Windows). Its six standalone archives are
  `caddy-authenticator_<Version>_<Os>_<Arch>.tar.gz`, using `.zip` for Windows.
  They contain the executable, LICENSE and the CLI's README at the archive root.
  Preserve the separate build/archive IDs and explicit archive `ids` selectors;
  omitting selectors bundles both binaries together. The CLI does not belong in
  the existing Caddy nFPM package.

Both archive sets share `authcrunch_<Version>_SHA256SUMS`. The authenticator's
linker flags set `main.appVersion`, `main.gitCommit`, `main.buildUser` and
`main.buildDate` from GoReleaser metadata. Snapshots must report their snapshot
version, not the source fallback. The Caddy wrapper has no custom version linker
flags. Do not change release tags or bump VERSION merely to add a build.
Keep the [CLI download guide](../../../../cmd/caddy-authenticator/README.md#download-a-release)
aligned with the archive names, target matrix and checksum filename.
GoReleaser's [archive documentation](https://goreleaser.com/customization/package/archives/)
describes build selectors, file placement and Windows format overrides.

Coverage is a separate diagnostic artifact. The reusable build workflow uploads
the complete `.coverage/` bundle as `caddy-security_coverage_<artifact-id>`,
including hidden files, with 14-day retention. Upload runs even after a failed
quality gate; missing files fail the upload and test failures remain failures.
Version/tag identity comes from `make artifact-id`. README Caddy download URLs
are another distribution surface and are not the GoReleaser asset inventory.

## go-authcrunch Release Notes

`assets/scripts/generate_go_authcrunch_changelog.sh` supplies the release footer
through `GO_AUTHCRUNCH_CHANGELOG`. It compares go-authcrunch versions in the
previous caddy-security release's `go.mod` and the current working tree's
`go.mod`. `CURRENT_REF` controls previous-release discovery, not the current
module file; use a checkout of the intended release revision.

The script exits without output when no previous release/version is found or
the dependency version is unchanged. For a changed version it emits an upstream
comparison link, then includes commit subjects only when both upstream tags are
available. It uses `GO_AUTHCRUNCH_REPO` when supplied, otherwise the sibling
`../go-authcrunch` checkout if it has a `.git` directory, otherwise a temporary
GitHub clone under `RUNNER_TEMP` or `/tmp`. A missing commit list can mean local
tags are unavailable; it does not prove there were no upstream changes.

Treat a sibling selected by `GO_AUTHCRUNCH_REPO` as read-only. Do not fetch tags
into it to complete the changelog. If more history is required, use a separate
copy under this repository's `tmp/` and point `GO_AUTHCRUNCH_REPO` there. For a
local fallback clone, set `RUNNER_TEMP` to an existing directory under `tmp/`.

Use `PREVIOUS_REF`, `CURRENT_REF`, `GO_AUTHCRUNCH_PREVIOUS_VERSION`,
`GO_AUTHCRUNCH_CURRENT_VERSION`, and `GO_AUTHCRUNCH_REPO` for controlled fixture
checks. Keep fixture refs and the working tree consistent and use a local
upstream fixture to avoid network-dependent changelog tests.

## Toolchain and Packaging Checks

Inspect `go.mod` for the module minimum and both workflows for their Go
selection. Both workflows select Go `1.26.8` with `GOTOOLCHAIN=local`, matching
the sibling's tested workflow without raising this module's minimum. Record
the effective `go version` and inspect packaged executables with `go version -m`;
the wrapper's Caddy version output is not
enough to establish its toolchain or embedded dependency versions.

When qualifying binaries for publication, verify the selected Go release is
supported and patched using official Go release/security sources. A local Go
upgrade does not update CI selection. Keep an explicit toolchain's `GOROOT`,
`PATH`, and `GOTOOLCHAIN` consistent; do not change the module minimum merely to
work around a mismatched local Go environment.

For packaging changes, use the workflow's pinned GoReleaser version, run its
`check`, then `build --snapshot --clean` with an isolated ignored distribution
directory and no publishing token. Check required
template environment values, including `GOPATH` and `GO_AUTHCRUNCH_CHANGELOG`.
Report any schema incompatibility before changing configuration or the selected
tool.
Snapshot builds validate compilation. For archive changes, run
`goreleaser release --snapshot --skip=publish --clean --config <snapshot-config>`
using a copy of the repository configuration with only `dist` changed to a chosen
ignored directory. Snapshot mode disables publication; remove publishing tokens
from the test environment as well. Avoid replacing any unrelated `dist/` output.

Run `python3 assets/scripts/check_authenticator_archives.py <snapshot-dist>` to
verify all six standalone archives, executable names/permissions, the exact
usage guide/license, separation from the Caddy binary and SHA-256 entries.
`make test-automation` covers missing targets, corruption, mixed contents,
incorrect documents and non-executable Unix binaries. Inspect each generated
executable with `go version -m` for its target and toolchain; run the host-compatible
packaged authenticator's `version` and `--help` to verify release metadata and
command availability. Also inspect the existing authcrunch archives for regressions.
Do not use a live release as a packaging test.
