# Manual OIDC conformance in GitHub Actions

The **OIDC conformance** workflow in `.github/workflows/oidc-conformance.yml`
runs the same `make oidc-conformance-prepare` and `make oidc-conformance-test`
commands as the [local workflow](oidc-conformance.md). Its only event is
`workflow_dispatch`; pushes, pull requests, schedules and regular CI do not
run the official plans. It builds the actual Caddy deployment with the selected
published go-authcrunch dependency and the unchanged pinned Foundation suite.
The Basic OP, Config OP and Form Post OP selection is unchanged.

## Artifact contents

The workflow uploads a readable HTML summary and the complete report directory
directly into one GitHub artifact ZIP. Unzip the download once, open `index.html`,
and follow **Open complete report and screenshots**. There is no nested evidence
archive to extract. It requires no recipient input, repository variable,
encryption key or age installation. Credentials, client registrations,
TLS and signing keys are generated for the disposable loopback test deployment;
keep this workflow limited to synthetic test data.

The download preserves the linked HTML report, Chrome screenshots and network
timelines, signed exports, raw logs/configuration, source snapshot and every
recorded outcome. GitHub users with repository read access can
[download its artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts).
The summary remains concise and only includes selected status fields; complete
original evidence lives in `private/`. Signatures and checksums are retained.

The artifact keeps the existing `private/` directory name to preserve report
paths and evidence bytes. That name and its restrictive local file permissions
do not imply the uploaded test bundle is confidential. Local Make runs keep
their existing report layout and permissions.

Older workflow revisions produced `evidence.tar.gz.age`; those existing artifacts
still need their original private key. The current workflow no longer reads
`OIDC_CONFORMANCE_AGE_RECIPIENT`, so a previously configured variable is unused.
Intermediate revisions produced `evidence.tar.gz`; new downloads include the
report files directly.

## Run and download

After the workflow is committed to the repository's default branch, choose
**Actions → OIDC conformance → Run workflow**, then select the desired branch.
GitHub requires the workflow on the default branch to expose manual dispatch;
see [manual workflow instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
Authoring this workflow does not itself push code or dispatch a remote job.

The CLI equivalent requires no inputs:

```sh
gh workflow run oidc-conformance.yml --ref main
```

Download `caddy-security-oidc-conformance-<YYYYMMDD>-<HHMMSS>-<short-commit>.zip`
from the run's **Artifacts** section, unzip it once, and open `index.html`. The prefix is
`caddy-security`. The timestamp is UTC, recorded immediately after
checkout, and the commit is Git's 12-character short hash of the checked-out HEAD
(extended only if needed for uniqueness). The upload action receives the name
without `.zip`; GitHub supplies that extension when downloading the artifact.
The artifact is retained for 14 days. It contains:

- `index.html`: readable summary, outcome explanations and a direct full-report link.
- `summary.json`: allowlisted outcomes, stage statuses, runner exit and revisions.
- `sha256.json`: checksums for every uploaded file except this manifest itself.
- `private/evidence/index.html`: full report, with linked screenshots and raw evidence.
- `private/`: original test files and preparation/runner diagnostics.
- `filesystem-entries.json`: metadata for symlinks and special filesystem entries.
- `package-error.log`: packaging diagnostics if copying the evidence failed.

The summary links to the full report only when it exists; blocked runs still
provide their original files and diagnostics. Preparation/tool logs live at
`private/*.log`. The actual conformance
bundle, including its unchanged SHA-256 inventory, is under `private/evidence/`.
This artifact is a deployment rehearsal; it does not submit certification materials or confer
OpenID certification. Do not add publishing/submission actions without a
separate user instruction.

## Execution and failure behavior

The job uses Ubuntu 24.04 x86_64, pinned Go 1.26.8, Python 3.12 and headless
Chrome for Testing. It installs host runtime libraries, while downloaded suite,
browser, Java, MongoDB, Maven and Python tools/data stay under
`tmp/oidc-conformance/`. It does not cache run data; only the packaged disposable
test evidence is uploaded.

ChromeDriver and Chrome receive a separate `TMPDIR` pointing to the checkout's
`tmp/` root. Chromium creates private unique temporary directories there;
profiles, trust databases and logs remain in the complete report bundle. Do not
inherit the report's deeply nested runtime path for Chrome: Linux limits Unix
socket addresses to 107 pathname bytes, including Chromium's generated
directory and `SingletonSocket` suffix. The launcher rejects checkout paths
that cannot meet this limit and rejects a temporary-directory symlink escaping
the checkout. Use a shorter checkout path if that prerequisite check fails.
The selected temporary base is recorded in `browser-tls.json`.

Chrome startup and TLS checks can pass before a later image upload fails.
The suite limits decoded screenshots to 500 KiB; Linux rendering can exceed
that limit at a window size that worked on macOS. The browser helper retries
oversized captures at bounded narrower widths, preserves every original PNG
and restores the window. It verifies the page and URL before uploading the
exact selected capture; it never repeats authentication or changes a result.
Inspect the byte counts, window dimensions and hashes in `browser-evidence.json`
and the screenshot timeline. See the
[capture and validation rules](oidc-conformance.md#regression-validation).

Ubuntu can restrict user namespaces for downloaded Chrome binaries. The job
loads a narrowly scoped AppArmor profile for the exact pinned Chrome path,
following [Chromium's documented approach](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md),
then unloads its owned profile at completion. It leaves host-wide restrictions,
Chrome's sandbox and HTTPS certificate validation enabled. No host trust roots,
hosts-file changes, Docker network or hosted-suite account are needed: Caddy,
Chrome, the suite and MongoDB share loopback networking on the runner.

`assets/scripts/oidc_conformance_ci.py` captures preparation/test output in
locally restricted logs that are included in the download. It preserves each
command's original exit, propagates nonzero
results to Actions, and records timeout/interruption separately. The original
official runner exit remains in `execution.json` and both HTML reports; GNU
Make's own failure status can differ from the official runner's status.
REVIEW/WARNING/SKIPPED never become PASSED, including when the runner exits zero.

Preparation has a 30-minute stage limit, testing a 45-minute limit and the job
a 120-minute limit, leaving time for setup, cleanup and packaging/upload. On stage
cancellation or timeout, the wrapper signals its owned process group and allows the harness
to stop its independent Caddy/Java/MongoDB/browser sessions. Preparation handles
SIGTERM too, so its independent Maven/helper sessions unwind. Report packaging
and upload use `always()` and execute after failures. A forcibly terminated or
lost runner can prevent final cleanup/upload; no complete evidence claim is
made for such a run. The action does not automatically retry or overwrite runs.

The upload path is exclusively `tmp/oidc-conformance-ci/artifact/`. Never widen
it to `tmp/`, `private/` or the suite workspace. The artifact includes only the
owned run evidence and copied preparation diagnostics, not tool/cache trees.
Set `include-hidden-files: true` on the pinned upload action to retain hidden
evidence files and directories. Its default excludes them; see the
[upload action inputs](https://github.com/actions/upload-artifact/tree/v4.6.2#inputs).
Copy regular files byte-for-byte. Record symlink paths/targets and special-file
types in `filesystem-entries.json`, without copying live links, following their
targets or opening sockets/FIFOs. This keeps the upload action from traversing
outside the report. The ZIP is for report viewing; it does not preserve executable
modes or recreate a runnable browser profile.
Packaging builds `artifact.partial/` outside the upload path and renames it only
after copying and writing the summary/checksums. A copy failure fails packaging,
removes partial or stale output, and leaves
a readable summary plus packaging diagnostics; incomplete evidence is never
presented as complete. Conformance cleanup removes `tmp/oidc-conformance-ci*` output through
its existing supplemental-output rule and retains downloaded tools.

## Validation

Existing-path rejection cases must use paths guaranteed to exist in their own
checkout. The harness scope test rejects the checkout root and a symlink to it,
so it works without `../go-authcrunch`. Validate boundary-test changes in a
disposable checkout with no sibling repositories; an existing local sibling
can hide a strict path-resolution failure. Preserve symlink-escape rejection
and protection against overwriting existing evidence.

`test_oidc_conformance_ci.py` stays in the isolated conformance test directory.
It checks preservation of every outcome/repeated instance, public-field
selection, private log handling, path boundaries, failed stages, real timeout
cleanup, preparation SIGTERM cleanup and blocked artifacts. Its download E2E
runs the real packaging CLI, creates a single ZIP of the upload directory, and
extracts it once. It checks the summary-to-report link, original bytes and hashes,
hidden files/directories, and symlink/FIFO metadata without following targets.
Failure cases preserve malformed evidence, reject partial/stale files and clear
packaging diagnostics on a successful retry. It never skips official suite
modules for missing prerequisites.

The browser tests include real pinned Chrome/ChromeDriver startup with a long
report path and inherited `TMPDIR`, both untrusted and trusted HTTPS controls,
and a check of the resulting socket address length at the hosted checkout path.
This browser E2E is skipped only when the local pinned browser tools are absent;
the hosted workflow prepares them before invoking these tests. Unit cases also
reject temporary-directory escapes and Linux checkout paths exceeding the
socket budget. Keep these checks in the isolated conformance suite.
The same real-browser E2E serves a deterministic noisy login page whose original
PNG exceeds the upload limit, then verifies a smaller authentic capture, retained
originals and window restoration. Unit cases cover exact-limit acceptance,
exhausted retries without an upload, changed-page/URL rejection, and binding the
selected PNG to the existing official image slot without another form submission.

Validate workflow syntax with `actionlint` and run the isolated conformance tests.
For packaging-only changes, package a copy of an existing actual Caddy rehearsal;
extract a single ZIP and verify report links, original bytes and manifests.
Execution changes also require a new actual Caddy conformance rehearsal through
the CI stage wrapper and `make oidc-conformance-test`.
Local validation on macOS does not prove the hosted Ubuntu job has run; report
that limitation until the committed workflow is dispatched on GitHub.
