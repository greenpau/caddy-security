---
name: release-and-versioning
description: Maintain caddy-security VERSION, generated download links, versioned CI artifacts, release Make targets, tags, and GoReleaser publication. Use for version checks, release preparation or execution, release automation changes, and release CI or packaging review.
---

# Release and Versioning

Follow the [repository scope](../coding-directives/SKILL.md#repository-scope).
Version edits, dependency refreshes, commits, tags, and publication apply only
to caddy-security. Read sibling versions/history as inputs; do not bump, sync,
fetch into, tag, or release a sibling to unblock this module. Missing upstream
releases are separate work. Keep chosen snapshot and report destinations here.

## Version Authority

`VERSION` owns the caddy-security release number. Preserve the existing
`1.<minor>.<patch>` release line, with no `v` in the file and `v<VERSION>` for
the Git tag. A feature change or dependency update alone does not request a
version bump or publication. Read current values from the checkout instead of
copying versions from examples or the sibling repository.

Keep these version surfaces distinct:

- `Makefile` reads `VERSION` into `PLUGIN_VERSION`; release recipes read it
  again for the commit subject and annotated tag.
- `assets/scripts/generate_downloads.sh` projects `VERSION` into README Caddy
  download URLs. It separately hard-codes the `caddy-trace` version. Verify its
  `Download Caddy with the plugins enabled` insertion marker exists before
  regenerating links, and inspect their placement afterward. The macOS branch
  requires `gsed` as well as BSD `sed`.
- `go.mod` selects the go-authcrunch dependency version; `../go-authcrunch/VERSION`
  is the sibling library's release number. Neither sets this module's version.
  `make sync` updates dependency references and removes local replacements; it
  is a separate dependency refresh, not caddy-security version synchronization.
- `cmd/authcrunch/main.go` delegates to Caddy. It has no application version
  fallback declarations to synchronize. The Makefile does not inject its
  `PLUGIN_VERSION` with linker flags, so `bin/authcrunch version` alone does not
  establish this module's release identity.
- `bin/authcrunch security version` reads the linked go-authcrunch module from
  embedded Go build metadata. It retains pseudo-versions and shows replacements,
  including `(devel)` for unversioned local paths. This is dependency identity,
  distinct from Caddy's version and this repository's release number; see
  [security dependency version](../scripts-and-automation/SKILL.md#security-dependency-version).
- `cmd/caddy-authenticator/main.go` initializes `*versioned.PackageManager` with
  a literal fallback for ordinary `go install` builds. `make build` injects
  `VERSION` into `main.appVersion`; `caddy-authenticator version` prints its
  banner. GoReleaser builds separate platform archives and injects release/snapshot
  version, commit and build metadata; see [CI and packaging](references/ci-and-packaging.md).
  Keep the fallback synchronized using `make version-sync` after an
  explicit VERSION change. Sync validates VERSION first and changes only the
  existing fallback; it neither bumps the release nor stages files.

`make version-check` validates the fixed-major namespace through
`assets/scripts/version.py` without rewriting files. It accepts a single
optional trailing newline, rejects leading zeros and prerelease/build suffixes,
and bounds components for `versioned`. `check --tag` additionally requires the
exact `v<VERSION>` tag. It does not validate README link placement or contents.
The check also rejects a missing, ambiguous or stale authenticator fallback;
artifact identity validation enforces the same consistency without rewriting it.

`make artifact-id` validates the version and produces
`v<VERSION>_<UTC YYYYMMDDTHHMMSSZ>_<12-character SHA>` for branch/PR/manual builds.
An exact `v<VERSION>` tag produces `v<VERSION>`; another tag fails. `GITHUB_SHA`
provides the checked CI revision (including PR merge commits), with local HEAD
as fallback. Validated `version` and `artifact_id` values go to `GITHUB_OUTPUT`.

`make release` increments the patch; `make minor-release` increments the minor
and resets the patch to zero. Both preserve the major release line.
`assets/scripts/version.py next --kind patch|minor` computes the candidate
without writing files and rejects an increment beyond the supported range.
`version-sync` projects VERSION into the authenticator fallback only.

## Existing Release Targets

Read the current `Makefile` before executing release operations. The targets
have different side effects:

| Target | Actual behavior |
| --- | --- |
| `make release-git-check` | Read-only local check of `main`, a clean worktree/index including untracked files, and synchronized version values. Does not check the remote or run the quality gate. |
| `make release` | Runs `assets/scripts/release.sh patch` for the complete checked patch release. |
| `make minor-release` | Runs the same script with `minor`, resetting the patch to zero. |
| `make release-update-version`, `make release-git-commit` | Fail with instructions to use a complete release target; partial publication paths are disabled. |

The shared script serializes checks, bump, synchronization, download generation,
`make ci-check`, commit, tag, and push even under parallel Make. It requires
`main` with no tracked, staged, or untracked changes, fetches `origin/main`,
rejects behind/diverged history and an existing candidate tag locally or on
origin, and checks the README marker and macOS `gsed` prerequisite before bumping.
The pinned `go tool versioned` command comes from `go.mod`; release operations
do not depend on a globally installed versioned executable.

The gate runs once against the bumped version, including the binary build.
Only `VERSION`, `README.md`, and `cmd/caddy-authenticator/main.go` are staged.
Unexpected staged, other tracked, or untracked changes stop publication.
The commit subject is `ops: released v<VERSION>` and the exact tag is annotated.
One atomic push publishes `HEAD:refs/heads/main` and that tag to origin; unrelated
local tags are excluded. There is no fallback to separate pushes.

## Preparation and Publication

For a status check, start with read-only evidence: `git status --short
--untracked-files=all`, `git branch --show-current`, `git diff`,
`git diff --cached`, `VERSION`, and existing tags. `make release-git-check` adds
the local preflight without modifying files. Release preparation can inspect
and validate without executing a bump or publishing target.

For an actual release, carry forward the user's existing authorization and:

1. Confirm the intended version, `main` checkout, clean index/worktree including
   untracked files, intended remote, remote branch state, and absence of the
   intended tag locally and remotely. Do not rely on stale remote-tracking refs
   or let unrelated staged changes enter the release commit.
2. Verify dependencies resolve to the intended published versions. Resolve any
   local go-authcrunch replacement through the dependency refresh workflow
   before qualifying the release. Run `make dep` to resolve pinned tools and
   dependencies. Review any source changes before proceeding; validation itself
   must not rewrite them.
3. Run the requested `make release` or `make minor-release` once. The script
   bumps, synchronizes projections, runs the complete gate, commits and tags the
   validated contents, and publishes the two explicit refs atomically.
4. Confirm the release commit, annotated tag, VERSION and intended publication
   refer to the same revision. Never force an existing release ref.

Only bump, tag, push, or dispatch a publishing workflow within the user's
requested scope. A request to explain or port release guidance is not a request
to execute a release. Do not ask again for actions already authorized.

If any step fails, inspect the worktree, index, release commit/tag, and remote
refs before continuing. A transport failure can leave the outcome uncertain.
Preserve that evidence and report the last completed step. Do not rerun the
entire release, bump again, reset changes,
delete tags, or retract a version as automatic recovery.

## CI and Automation Validation

For release CI, artifact identity, dependency changelogs, toolchains, and
packaging validation, read
[CI and packaging](references/ci-and-packaging.md). It distinguishes the
current workflow from release gates that would need implementation.
For complete Caddy target builds, source/artifact vulnerability evidence,
stripped-symbol limitations and unresolved official OP outcomes, use
[final integration qualification](references/final-qualification.md).

For automation changes, exercise success and failure paths in disposable
repositories with local bare remotes. Include dirty/untracked state, wrong
branch, an existing tag, unrelated local tags, failed validation, and rejected
pushes as relevant to the change. Never test release automation by publishing
this repository. For skill-only edits, validate skill metadata, links, and
claims against source; no release, version bump, or Go build is needed.
