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
  fallback declarations to synchronize. The Makefile does not inject
  `PLUGIN_VERSION` with linker flags, so `bin/authcrunch version` alone does not
  establish this module's release identity.

`make version-check` validates the fixed-major namespace through
`assets/scripts/version.py` without rewriting files. It accepts a single
optional trailing newline, rejects leading zeros and prerelease/build suffixes,
and bounds components for `versioned`. `check --tag` additionally requires the
exact `v<VERSION>` tag. It does not validate README link placement or contents.

`make artifact-id` validates the version and produces
`v<VERSION>_<UTC YYYYMMDDTHHMMSSZ>_<12-character SHA>` for branch/PR/manual builds.
An exact `v<VERSION>` tag produces `v<VERSION>`; another tag fails. `GITHUB_SHA`
provides the checked CI revision (including PR merge commits), with local HEAD
as fallback. Validated `version` and `artifact_id` values go to `GITHUB_OUTPUT`.

The publishing automation still offers a patch release only. It has no
`minor-release` or `version-sync` target and no Go fallback projections. Do not
infer those facilities from go-authcrunch; implement and validate any requested
addition before documenting it as available.

## Existing Release Targets

Read the current `Makefile` before executing release operations. The targets
have different side effects:

| Target | Actual behavior |
| --- | --- |
| `make release-git-check` | Runs `go mod tidy` and `go mod verify`, checks `main`, then checks tracked changes with `git diff-index --quiet HEAD --`. It can modify module files and does not check untracked files or remote divergence. |
| `make release-update-version` | Runs `versioned -patch`, regenerates README download links, and stages `VERSION`, `README.md`, `CONTRIBUTING.md`, and `Makefile`. It does not commit or publish. |
| `make release-git-commit` | Commits the index with `ops: released v<VERSION>`, creates an annotated tag, runs `git push`, then runs `git push --tags`. These pushes are separate and the latter includes every local tag. |
| `make release` | Declares `release-git-check`, `build`, `release-update-version`, and `release-git-commit` as prerequisites. It includes no test target and builds before bumping. |

`make release` is not ordered safely under parallel Make. Run release operations
sequentially, including when `MAKEFLAGS` supplies parallelism. `make ci-check`
does serialize its gates, but that does not serialize the legacy release target.

The release recipes invoke `versioned` from `PATH`; `make dep` resolves only the
pinned test tool and module dependencies, so versioned must already be installed.
An indirect `versioned` requirement in `go.mod` does not pin that executable.
Inspect `command -v versioned` and `versioned -version` before a bump. A change
to tool pinning is an automation/dependency change, not a documentation fix.

## Preparation and Publication

For a status check, start with read-only evidence: `git status --short
--untracked-files=all`, `git branch --show-current`, `git diff`,
`git diff --cached`, `VERSION`, and existing tags. Do not use
`release-git-check` as a read-only probe. Release preparation can inspect and
validate without executing a bump or publishing target.

For an actual release, carry forward the user's existing authorization and:

1. Confirm the intended version, `main` checkout, clean index/worktree including
   untracked files, intended remote, remote branch state, and absence of the
   intended tag locally and remotely. Do not rely on stale remote-tracking refs
   or let unrelated staged changes enter the release commit.
2. Verify dependencies resolve to the intended published versions. Resolve any
   local go-authcrunch replacement through the dependency refresh workflow
   before qualifying the release. Run `make dep` and `make ci-check` for version,
   automation, full tested reports, and build evidence. Review any module or
   source changes before proceeding; validation itself must not rewrite them.
3. Perform the requested bump once, review the version/download-link diff and
   staged file set, and validate the resulting tree. Keep the release commit,
   annotated tag, `VERSION`, and intended publication tied to the same revision.
4. Publish only the intended branch and exact tag to the verified remote. Prefer
   one atomic push with explicit refs when supported. The existing
   `release-git-commit` target cannot provide that scope; use explicit Git steps
   instead of its broad tag push. Do not silently fall back from atomic to
   separate pushes or force an existing release ref.

Only bump, tag, push, or dispatch a publishing workflow within the user's
requested scope. A request to explain or port release guidance is not a request
to execute a release. Do not ask again for actions already authorized.

If any step fails, inspect the worktree, index, release commit/tag, and remote
refs before continuing. Separate pushes can partially publish; a transport
failure can leave the outcome uncertain. Preserve that evidence and report the
last completed step. Do not rerun the entire release, bump again, reset changes,
delete tags, or apply the Makefile's printed deletion/retraction suggestions as
automatic recovery.

## CI and Automation Validation

For release CI, artifact identity, dependency changelogs, toolchains, and
packaging validation, read
[CI and packaging](references/ci-and-packaging.md). It distinguishes the
current workflow from release gates that would need implementation.

For automation changes, exercise success and failure paths in disposable
repositories with local bare remotes. Include dirty/untracked state, wrong
branch, an existing tag, unrelated local tags, failed validation, and rejected
pushes as relevant to the change. Never test release automation by publishing
this repository. For skill-only edits, validate skill metadata, links, and
claims against source; no release, version bump, or Go build is needed.
