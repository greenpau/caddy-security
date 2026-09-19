# Manual OIDC conformance in GitHub Actions

The **OIDC conformance** workflow in `.github/workflows/oidc-conformance.yml`
runs the same `make oidc-conformance-prepare` and `make oidc-conformance-test`
commands as the [local workflow](oidc-conformance.md). Its only event is
`workflow_dispatch`; pushes, pull requests, schedules and regular CI do not
run the official plans. It builds the actual Caddy deployment with the selected
published go-authcrunch dependency and the unchanged pinned Foundation suite.
The Basic OP, Config OP and Form Post OP selection is unchanged.

## Set up artifact privacy once

GitHub permits signed-in repository readers to
[download its Actions artifacts](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts).
The full conformance bundle contains disposable passwords, client secrets,
signing keys and browser/token traces. File permissions inside a ZIP do not
make an uploaded artifact private to its initiator.

This workflow uploads a readable HTML summary and an **age-encrypted complete
evidence archive**. The summary lists every module instance/outcome, explains
non-pass statuses, reports the original runner exit and links to the archive.
Arbitrary logs, configuration, captured pages and condition messages are never
copied into the unencrypted summary. The full linked HTML report, screenshots,
developer-tools timelines, signed exports and private originals are inside the
encrypted archive. Local Make runs retain their usual private, unencrypted
report and need no encryption key.

Create an [age identity](https://github.com/FiloSottile/age/tree/v1.2.1) locally,
using `age-keygen -o /private/path/oidc-evidence-key.txt`. Keep this private key
outside the checkout's temporary/cleanup directories and outside GitHub.
Copy its public `age1...` recipient to the repository Actions **variable**
`OIDC_CONFORMANCE_AGE_RECIPIENT` under Settings → Secrets and variables → Actions
→ Variables. Only the public key is needed by the runner. Alternatively supply
the `evidence_recipient` input when dispatching a particular run.

For repo-local tools, without a global install:

```sh
GOBIN="$PWD/tmp/oidc-conformance/tools/age" go install \
  filippo.io/age/cmd/age@v1.2.1 filippo.io/age/cmd/age-keygen@v1.2.1
# Invoke tmp/oidc-conformance/tools/age/age-keygen and age from here.
```

The workflow pins the same tools, records the encryption binary's version/hash,
and validates the actual recipient before preparing or running the suite.
Missing/invalid recipients stop the run with setup guidance. The artifact still
contains a blocked-run HTML summary, with no plaintext private evidence.

## Run and download

After the workflow is committed to the repository's default branch, choose
**Actions → OIDC conformance → Run workflow**, then select the desired branch.
GitHub requires the workflow on the default branch to expose manual dispatch;
see [manual workflow instructions](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow).
Authoring this workflow does not itself push code or dispatch a remote job.

The CLI equivalent, using the configured public recipient, is:

```sh
gh workflow run oidc-conformance.yml --ref main
```

Download `oidc-conformance_<run-id>_<attempt>` from the run's **Artifacts** section
and open `index.html`. The artifact is retained for 14 days. It contains:

- `index.html`: readable summary, outcome explanations and archive instructions.
- `summary.json`: allowlisted outcomes, stage statuses, runner exit and revisions.
- `sha256.json`: artifact checksums.
- `evidence.tar.gz.age`: encrypted original evidence, when encryption succeeded.

To open the full report, decrypt into a new private directory:

```sh
umask 077
age --decrypt --identity /private/path/oidc-evidence-key.txt \
  --output evidence.tar.gz evidence.tar.gz.age
mkdir extracted
tar -xzf evidence.tar.gz -C extracted
# Open extracted/private/evidence/index.html in Chrome.
```

Preparation/tool logs live at `extracted/private/*.log`. The actual conformance
bundle, including its unchanged SHA-256 inventory, is under `private/evidence/`.
Do not publish the decrypted directory or private key. This artifact is a
deployment rehearsal; it does not submit certification materials or confer
OpenID certification. Do not add publishing/submission actions without a
separate user instruction.

## Execution and failure behavior

The job uses Ubuntu 24.04 x86_64, pinned Go 1.26.8, Python 3.12 and headless
Chrome for Testing. It installs host runtime libraries, while downloaded suite,
browser, Java, MongoDB, Maven, Python and encryption tools/data stay under
`tmp/oidc-conformance/`. It does not cache or upload private run data.

ChromeDriver and Chrome receive a separate `TMPDIR` pointing to the checkout's
`tmp/` root. Chromium creates private unique temporary directories there;
profiles, trust databases and logs remain in the private report bundle. Do not
inherit the report's deeply nested runtime path for Chrome: Linux limits Unix
socket addresses to 107 pathname bytes, including Chromium's generated
directory and `SingletonSocket` suffix. The launcher rejects checkout paths
that cannot meet this limit and rejects a temporary-directory symlink escaping
the checkout. Use a shorter checkout path if that prerequisite check fails.
The selected temporary base is recorded in `browser-tls.json`.

Ubuntu can restrict user namespaces for downloaded Chrome binaries. The job
loads a narrowly scoped AppArmor profile for the exact pinned Chrome path,
following [Chromium's documented approach](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md),
then unloads its owned profile at completion. It leaves host-wide restrictions,
Chrome's sandbox and HTTPS certificate validation enabled. No host trust roots,
hosts-file changes, Docker network or hosted-suite account are needed: Caddy,
Chrome, the suite and MongoDB share loopback networking on the runner.

`assets/scripts/oidc_conformance_ci.py` captures preparation/test output in
private logs. It preserves each command's original exit, propagates nonzero
results to Actions, and records timeout/interruption separately. The original
official runner exit remains in `execution.json` and both HTML reports; GNU
Make's own failure status can differ from the official runner's status.
REVIEW/WARNING/SKIPPED never become PASSED, including when the runner exits zero.

Preparation has a 30-minute stage limit, testing a 45-minute limit and the job
a 120-minute limit, leaving time for setup, cleanup and packaging/upload. On stage cancellation or
timeout, the wrapper signals its owned process group and allows the harness
to stop its independent Caddy/Java/MongoDB/browser sessions. Preparation handles
SIGTERM too, so its independent Maven/helper sessions unwind. Report packaging
and upload use `always()` and execute after failures. A forcibly terminated or
lost runner can prevent final cleanup/upload; no complete evidence claim is
made for such a run. The action does not automatically retry or overwrite runs.

The upload path is exclusively `tmp/oidc-conformance-ci/artifact/`. Never widen
it to `tmp/`, `private/` or the suite workspace. An encryption failure fails
packaging and leaves only the public summary, without falling back to uploading
plaintext. Conformance cleanup removes `tmp/oidc-conformance-ci*` output through
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
cleanup, preparation SIGTERM cleanup and blocked artifacts. With pinned age
tools present it also encrypts/decrypts a real archive and verifies unchanged
report links, private bytes and hashes. Missing age skips only this CI archive
E2E locally; the workflow installs age before these tests and requires it for
packaging. It never skips official suite modules for missing prerequisites.

The browser tests include real pinned Chrome/ChromeDriver startup with a long
report path and inherited `TMPDIR`, both untrusted and trusted HTTPS controls,
and a check of the resulting socket address length at the hosted checkout path.
This browser E2E is skipped only when the local pinned browser tools are absent;
the hosted workflow prepares them before invoking these tests. Unit cases also
reject temporary-directory escapes and Linux checkout paths exceeding the
socket budget. Keep these checks in the isolated conformance suite.

Validate workflow syntax with `actionlint`, run the isolated conformance tests,
and execute an actual Caddy conformance rehearsal through the CI stage wrapper.
Confirm the encrypted archive decrypts to the original report and manifests.
Local validation on macOS does not prove the hosted Ubuntu job has run; report
that limitation until the committed workflow is dispatched on GitHub.
