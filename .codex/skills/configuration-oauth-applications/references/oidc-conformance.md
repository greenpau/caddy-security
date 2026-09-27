# Official OP conformance through Caddy

`assets/scripts/oidc_conformance.py` builds `cmd/authcrunch` from this checkout,
adapts a real Caddyfile, and serves the provider through Caddy's `security` app
and `authenticate` route. It never substitutes the standalone library portal.
The prerequisites implemented by the private registration workflow and Caddy
relying-party E2E coverage are described in [private provisioning](private-provisioning.md)
and [provider validation](oidc-provider.md#validation-surfaces).

This is a local deployment rehearsal, not OpenID certification. Never submit,
publish, freeze certification packages, or use the certification mark as part
of this workflow. The separate library rehearsal is reference evidence only.

Establish the candidate dependency with
`go list -m -json github.com/greenpau/go-authcrunch` and `go.mod`; the selected
published module is v1.3.4. The harness rejects local module replacements and
records downloaded module checksums and Git origin. Reading a sibling checkout
alone does not select it for a Caddy build. A dependency change requires new
candidate evidence; ordinary unit/E2E results and an older official-plan bundle
do not establish conformance outcomes for the changed candidate.

The current provider supplies themed consent, form-post and browser error pages,
including same-origin referrer policy and callback-bound form-action. The Caddy
deployment preserves those headers without importing the older v1.2.6 snippet.
`consent-policy.json` records policy ownership and links to candidate provenance.
Preflight validates CSP directives, nonce-limited styles and same-origin assets,
and still rejects null/cross-origin and forged-CSRF submissions.

## Official instructions and pin

The Foundation's [current OP instructions](https://openid.net/certification/connect_op_testing/)
and [local Build & Run instructions](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-%26-Run)
define the external workflow. Static testing requires independent Basic clients
for code binding, a POST client, and the suite's exact alias callback. The
Foundation requires running each module and retaining warning, skip, review,
failure and interruption outcomes. Some modules request browser evidence.

The selected unmodified [suite revision](https://gitlab.com/openid/conformance-suite/-/tree/e3b5558d6d5e0c17ab578a47b955fd3b405f902b)
is `e3b5558d6d5e0c17ab578a47b955fd3b405f902b`, reporting version **5.2.4**.
This is an immutable commit pin; there is no assumption that `v5.2.4` is a Git
tag or that it is the latest suite. The selected plan classes in
`src/main/java/net/openid/conformance/openid/` are `OIDCCBasicTestPlan`,
`OIDCCConfigTestPlan`, and `OIDCCFormPostBasicTestPlan`:

```text
oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
oidcc-config-certification-test-plan
oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]
```

Basic and Form Post fix response type `code` and select client authentication
variants inside their module lists. Config already fixes discovery/static
variants; do not supply those variants twice. The pinned selection contains
35 + 1 + 35 module instances. Pin updates require reviewing the official
instructions, plan lists, runner exit behavior, and evidence schema again.

## Prepare and execute

For a manual GitHub Actions run with a downloadable report, follow
[manual conformance Actions](oidc-conformance-actions.md). It invokes the same
Make targets and uploads an HTML summary plus the complete disposable test
evidence directly into one artifact ZIP. Unzip once and open `index.html` for
the summary and full-report link. It is separate from regular CI and needs no
encryption key, recipient input or repository variable.

Run from this repository with Go matching `go.mod`, Git, OpenSSL, and Python
3.12+. Preparation downloads a JDK, MongoDB, Maven, Chrome for Testing and ChromeDriver,
plus Maven/Python dependencies. It supports macOS arm64 and Linux x86_64 with the MongoDB Ubuntu
22.04 runtime prerequisites (including libssl3) and Chrome runtime libraries
(GTK/NSS and their dependencies). Other architectures need
manually installed prerequisites and explicit tool paths; a missing loader or
runtime library is a prerequisite blocker, not a conformance result.

```sh
make oidc-conformance-prepare
make oidc-conformance-test CONFORMANCE_RESULTS="$PWD/tmp/oidc-conformance/run-final"
```

If the test reports a missing suite checkout, suite jar, Java, MongoDB, Chrome, ChromeDriver or runner
Python, **run `make oidc-conformance-prepare` first**, then retry the test. These
are setup blockers before the official modules run. The terminal and HTML report
show both commands. Use a fresh result directory when retrying; if you supplied
custom prerequisite overrides, fix those paths or remove the overrides.

`CONFORMANCE_RESULTS` selects the complete artifact destination, including the
HTML entry point, `index.html`. Relative paths are resolved from the repository
root; absolute paths work too. Missing parent directories are created privately.
Paths containing spaces are supported. The official runner starts in the result
directory with relative config/export names because its pinned plan-argument
parser splits whitespace; the suite itself remains unmodified.
For example:

```sh
make oidc-conformance-test CONFORMANCE_RESULTS="tmp/oidc-reports/candidate-1"
open tmp/oidc-reports/candidate-1/index.html  # macOS; use a browser on other systems
```

The command prints the absolute HTML report path even when the official runner
returns nonzero. The result directory must be new and below this checkout's
`tmp/`, which keeps suite tools and data within the repository's temporary area.
Symlink escapes and existing destinations are rejected before writing results.
Never reuse a destination: failed attempts are evidence too.
Preparation pins Temurin 21.0.12.1+1,
Maven 3.9.16, MongoDB 7.0.43, and Chrome for Testing/ChromeDriver
153.0.8010.47 (Chromium revision 1681091), verifies distribution checksums, installs the
runner's pinned Python dependencies from `assets/scripts/oidc-conformance-requirements.txt`,
and builds the suite with its Maven package workflow. Suite unit tests and PMD
are skipped during packaging; protocol validators are unmodified. Sources,
tools and Maven/pip caches stay under `tmp/oidc-conformance`; per-run temporary
files and MongoDB data use the chosen result directory under `tmp/`.
Preparation checks existing tool bytes against their
verified archives instead of overwriting executables in place.
Kotlin compilation runs in the Maven process (`-Dkotlin.compiler.daemon=false`)
using its [documented execution strategy](https://kotlinlang.org/docs/maven-kotlin-compiler.html#choose-execution-strategy).
This prevents an idle compiler daemon outliving preparation. Build commands
also own and stop their process groups.

No Docker, hosts-file edit, system CA installation, production identity, or
hosted-suite account is needed. All listeners bind to `127.0.0.1`: Caddy OP
HTTPS, suite HTTPS through Caddy, the Java HTTP backend, and MongoDB. These
processes share the host network namespace. Moving a component into a container
changes that reachability and requires a separately reviewed deployment; do
not substitute container loopback or advertise an unreachable issuer.

The callback is exactly
`https://127.0.0.1:<suite-port>/test/a/caddy-local/callback` for all three
registrations. The port is selected per run and recorded in the Caddyfile,
plan configuration and TLS evidence. Each isolated suite has its own database,
so the local alias cannot collide with another run. Hosted testing instead
requires a reachable deployment, the hosted suite's callback, and its normal
account/token prerequisites; this harness does not contact it.

Before starting Caddy or the official plans, the harness reads back all three
private registration revisions and checks distinct, nonempty client IDs and
secrets, the two Basic/one POST authentication methods, and a single exact
callback per client. It also checks that consent is required and these fixtures
allow code requests without PKCE. `registration-evidence.json` records these
verified properties without copying credentials. Only these disposable
conformance registrations explicitly set `require_pkce false`; ordinary
application defaults and all public clients retain PKCE.

The execution target is `oidc-conformance-test`. It runs
the isolated harness unit tests, local Caddy E2E preflight, and all three official
plans. It produces its own private bundle, including `unit-tests.log` and
`local-e2e.json`; it does not use or overwrite `.coverage/`. Neither the harness
nor its unit tests are part of regular Go tests, `make test-automation`,
`make test`, or `make ci-check`.

`index.html` is an offline report with plan totals, every module instance,
original non-pass condition messages, explanations of known library gaps,
visual-review links, headless Chrome screenshot timelines with expandable network
records and original suite checks, exact candidate/suite provenance and a complete artifact
index. Its relative links keep working when the whole bundle is moved together.
Raw evidence is linked for download; captured pages are never embedded as active
HTML. No external assets, analytics, scripts or server are required. The report
also describes blocked, interrupted and incomplete runs, without presenting
missing evidence as success. It includes complete disposable test evidence;
the manual CI workflow makes the bundle downloadable as documented above.

For preinstalled local tools, override Make variables with absolute or
repository-relative paths:

```sh
make oidc-conformance-test \
  CONFORMANCE_SUITE="$PWD/tmp/oidc-conformance/suite" \
  CONFORMANCE_JAVA="$PWD/tmp/oidc-conformance/tools/java/bin/java" \
  CONFORMANCE_MONGOD="$PWD/tmp/oidc-conformance/tools/mongodb/bin/mongod" \
  CONFORMANCE_PYTHON="$PWD/tmp/oidc-conformance/venv/bin/python" \
  CONFORMANCE_RESULTS="$PWD/tmp/oidc-conformance/run-next"
```

Java, MongoDB and the runner virtual environment must reside under this
repository's temporary area. System Python/Go/Git/OpenSSL are ordinary build
prerequisites. The suite checkout must be clean, including untracked files;
the jar's embedded Git metadata must identify the pinned clean revision.
The receipt and run evidence preserve the jar hash and tool/build versions.
No sibling checkout is built, run, or modified.

## Remove test output, keep prerequisites

```sh
make oidc-conformance-cleanup
```

This removes all identified OIDC run bundles below this checkout's `tmp/`,
including custom `CONFORMANCE_RESULTS` destinations and failed/local-only runs.
Each entire bundle is removed: HTML reports, signed exports, screenshots,
private logs/configuration, disposable identities/keys/registrations, the test
Caddy binary, browser profiles and per-run MongoDB data. Choose cleanup only
when those private results are no longer needed; it does not reinterpret their
outcomes or run any tests.

Cleanup also removes supplemental output directly under `tmp/`: files and
directories named `oidc-*`, plus `audit_oidc_*.py` and `check_oidc_*.py` helpers.
This includes loose validation logs, audit/adapt JSON, screenshots and the
`oidc-consent-report-ui*` directories with their private Chrome profiles.
The `tmp/oidc-conformance` workspace itself and retained prerequisite paths
are excluded. These names reserve generated OIDC output, so keep unrelated
work outside them. Put new supplemental diagnostics inside the owning run
bundle when possible. Matching names nested inside unrelated directories
are not sufficient to identify output; custom bundles still need their metadata.

The command keeps `tmp/oidc-conformance/suite`, `tools`, `venv`, `m2`, `pip-cache`,
preparation `runtime`/`.config`, `prerequisites.json`, `suite-build.log` and the
workspace lock. A subsequent `make oidc-conformance-test` can reuse the prepared
dependencies without another download/build. Ordinary `.coverage/` reports,
unrelated temporary files and source files are outside this cleanup's ownership.

New bundles have `oidc-conformance-run.json` ownership/dependency metadata.
Older harness bundles are recognized from the OIDC-specific `execution.json`
schema, so names such as `run-*` are not required. The implementation scans
without following directory symlinks, excludes prerequisite directories and
validates the full deletion set before deleting anything. Recorded custom
prerequisites and current Make prerequisite overrides are protected too.
Before removing run metadata, cleanup privately records custom dependency
locations in `tmp/oidc-conformance/oidc-conformance-dependencies.json` so repeated
cleanup retains them even without overrides or surviving run bundles. The
record is retained with the prerequisites. Top-level symlink aliases are left
alone; symlinks inside removed output are unlinked without following targets.
It refuses overlapping prerequisite/result paths and nested new run bundles.

Runs hold a shared workspace lock; preparation and cleanup require exclusive
access. Cleanup also checks for still-running processes using result paths,
including older harness runs. Let active work finish or stop the owned test
normally, then retry; cleanup never kills a process to remove its evidence.
The empty workspace lock is retained so concurrent invocations use the same inode.

To preview candidates without removing evidence:

```sh
python3 assets/scripts/cleanup_oidc_conformance.py --dry-run
```

The Make recipe and safety tests run against disposable repositories during
development. Existing official bundles are not deleted merely to test cleanup.

## Installed prerequisites and removal

`make oidc-conformance-help` prints installation locations and removal commands
without downloading, building or deleting anything. Preparation also prints each
tool's purpose, its local entry path and the resolved versioned directory.
Everything below is relative to `tmp/oidc-conformance/`:

| Path | Purpose |
| --- | --- |
| `tools/java` | Temurin JDK: compiles and runs the official Java suite. |
| `tools/mongodb` | MongoDB server: stores local suite test state and results. |
| `tools/maven` | Apache Maven: builds the suite jar and downloads Java dependencies. |
| `tools/chrome` | Pinned Chrome for Testing: headless browser for real screenshots. |
| `tools/chromedriver` | Matching ChromeDriver: WebDriver actions and BiDi network events. |
| `tools/` | Download archives and versioned extracted directories; the tool entry paths above are links into them. |
| `suite/` | Pinned official sources and the built jar. |
| `venv/` | Isolated Python runner dependencies. |
| `m2/`, `pip-cache/` | Local dependency caches. |
| `runtime/`, `.config/` | Preparation temporary files and tool settings. |

These are local downloads, not system package installations or installed
services. The workflow does not change the global PATH. Test processes are
stopped by the harness; MongoDB's per-run database remains inside that run's
private evidence bundle.

After all preparation and test processes finish, run from the repository root
to remove the downloaded prerequisites and caches:

```sh
rm -rf tmp/oidc-conformance/tools tmp/oidc-conformance/suite \
  tmp/oidc-conformance/venv tmp/oidc-conformance/m2 \
  tmp/oidc-conformance/pip-cache tmp/oidc-conformance/runtime \
  tmp/oidc-conformance/.config
```

This leaves default `run-*` evidence bundles, preparation logs and the checksum
receipt. Keep custom `CONFORMANCE_RESULTS` directories outside those prerequisite
directories. Removing all of `tmp/oidc-conformance/` would also remove any evidence
stored there; archive the private evidence first if choosing that broader cleanup.
Custom artifact destinations elsewhere under `tmp/` are separate. Run
`make oidc-conformance-prepare` again before the next test after removing tools.

## Deployment and trust

The actual Caddy binary runs `security oauth init provisioning store`, three
`security oauth create application` commands, and `security oidc create signing key`.
The deployment loads immutable `v1` application records and the dedicated OP
key. The two Basic clients and the POST client have independent generated
identifiers/secrets, exact redirects, explicit `require_pkce false`, and default
consent. This exception is limited to compatible confidential conformance
registrations. Normal applications still default to PKCE; public clients cannot
disable it. Existing parser/default/public-client rejection tests retain that
contract. The local synthetic user has a real password, name, email and user
role. Caddy validation provisions a disposable file-backed identity database.
Before serving, the harness adds explicit synthetic profile, address and phone
attributes offline, preserving the Caddy-generated identity and password hash.
These are fixture data, not application defaults or verified ownership claims.
Clients register `address phone offline_access` in addition to the original
scopes, and the provider maps `urn:authcrunch:password` to `pwd`. The suite's
ordinary client scope remains `openid profile email`; individual modules request
their own optional scopes. Persisted identities, registrations and keys remain
in the private evidence. The portal access key is independent of the OP
key. Admin API and Caddy admin/autosave are disabled for this test deployment.

Caddy serves a fresh certificate with localhost/IP SANs signed by a private
two-day CA. Readiness and local E2E validate that CA and hostname. A negative
control confirms that ordinary system trust rejects it. Java's private PKCS12
truststore contains the same CA. The Python
runner uses `SSL_CERT_FILE` and a real disposable suite API token. It deliberately
does **not** set `CONFORMANCE_DEV_MODE`, because that official runner setting
disables certificate verification. It removes inherited TLS-bypass/proxy and
runner filtering/retry environment settings. Suite server development mode is
separate: it provides the local suite operator and development export key;
it does not authenticate the Caddy user.

The official suite's `AbstractCondition` uses its own permissive outbound HTTP
client internally. Its pinned `htmlunit3-driver` 4.36.1 also defaults to accepting
insecure certificates in `HtmlUnitDriverOptions`; `BrowserControl` does not
override that default. These upstream behaviors are retained without
modification. The Java truststore alone does not establish that these clients
enforce certificate validation. No harness setting disables TLS verification.
These three plans are not a complete TLS qualification. Independent trusted
HTTPS and negative trust checks establish this harness's certificate setup;
do not infer public Web PKI trust or complete cipher/certificate validation
from the Config OP result.

The suite's supported HtmlUnit commands submit actual username, password and
consent forms for ordinary modules. The three visual-review module names use
`browser: []` overrides, so the unmodified suite exposes its documented manual
browser URLs. `oidc_conformance_browser.py` visits those URLs using headless Chrome,
submits real forms, and uses the official image API to attach the exact PNG to
its matching pending slot. It never fabricates callbacks or success pages.
A fresh profile is used for each module; both authorizations in a reauthentication
module share the same profile and cookies. The second-login slot cannot receive
a first-login capture. A redirect-error slot cannot receive a login page.
The Request Object redirect-precedence case still follows its valid callback
without filling its optional error slot with unrelated evidence.

Chrome uses `acceptInsecureCerts: false`, with no TLS or web-security bypass
flags. The disposable CA is installed offline into each **new private profile's**
`Default/ServerCertificate` database. This is real custom-root trust, using the
pinned Chromium [schema](https://chromium.googlesource.com/chromium/src/+/refs/tags/153.0.8010.47/components/server_certificate_database/server_certificate_database.cc)
and [trust protobuf](https://chromium.googlesource.com/chromium/src/+/refs/tags/153.0.8010.47/components/server_certificate_database/server_certificate_database.proto),
not a certificate-error exception. A separate untrusted profile must report
`net::ERR_CERT_AUTHORITY_INVALID`; the trusted profile must receive Caddy's
actual discovery. `browser-tls.json` retains both controls, exact capabilities,
browser/driver version, process IDs and binary hash. No OS/keychain trust or
existing browser profile is changed. A browser-pin update requires reviewing
the schema and rerunning both controls. Follow the repository's
[headless Chrome preference](../../testing-and-ci/SKILL.md#browser-choice).

If the real provider UI blocks an interaction, preserve the screenshots and
network events, record the reason, and use the official cancellation API for
that instance. This records an **INTERRUPTED** status while allowing independent
modules to execute. Do not attach an unrelated screenshot, rewrite `Origin`,
disable consent/CSRF checks, or count interruption as pass. A browser-controller
or transport failure stops the runner; its original exit and partial evidence
remain recorded. There is no expected-failure list.

## Evidence, interruption, and interpretation

Preserve the entire result directory privately. Directories use `0700`, data
files `0600`, and the owned Caddy executable `0700`. Logs, tokens, database,
registrations, captured pages and config are sensitive even for synthetic users.
For local runs, share only reviewed material; full exports and raw
`summary.json` can contain credentials. The separate
[manual Actions workflow](oidc-conformance-actions.md) deliberately uploads the
complete synthetic deployment evidence to repository readers. Do not use
production identities or credentials in that workflow.

- `candidate.json`, `source-manifest.json`, `candidate.patch`, `build.txt` and
  the binary identify the Caddy candidate, untracked additions, Go build and
  exact Caddy/authcrunch module versions, sums and origin revisions. `source.tar.gz`
  retains the actual tracked and untracked sources, including harness scripts.
- `suite-build.properties`, `suite-server.json`, `tools.json` and preparation
  receipt identify the clean suite revision and jar/tool builds.
- `Caddyfile`, adapted `deployment.private.json`, their redacted copies,
  discovery, OP/suite JWKS, TLS certificate/CA and truststore preserve the
  actual deployment. The JSON runner command and private plan/token files
  preserve the exact invocation and credentials.
- `runner.log` retains the original output. `execution.json` records the
  original runner exit separately from harness/evidence errors and timeouts.
  A normal nonzero exit is returned unchanged by Python; Make also fails.
  Signal exits retain the subprocess's negative status plus shell-style return.
- `exports/` retains the official signed plan ZIPs and per-instance ZIPs.
  Plan exports select the latest instance, so the collector also enumerates
  **every** module instance, preserving earlier failed attempts if any exist.
  Detached RSA/SHA-256 signatures are independently verified against the
  suite's public key. This local development key is not Foundation attestation.
- Raw plans, per-instance records and `summary.json` preserve status, outcome,
  every non-pass condition, and unrun modules. Counts never promote warnings,
  skips, reviews, unknown states, or interrupted attempts to PASSED.
- `visual-evidence.json` indexes real PNGs and any HtmlUnit source captures from
  the signed logs. Original PNGs, page source and raw WebDriver BiDi events are
  under `browser/<instance>/`; `browser-evidence.json` records actions, first/second
  authorization, timestamps, URLs, image-slot IDs and screenshot hashes.
  `browser-export-verification.json` confirms byte identity with the signed PNG.
- `review-<instance>.html` provides a screenshot filmstrip and chronological
  steps beside request/response headers, redirect hops, status codes and console
  events. A separate section shows the original signed suite conditions and
  back-channel HTTP, including token and UserInfo responses. Browser response
  bodies not supplied by BiDi are not invented. Captured HTML remains text-only.
  REVIEW outcomes remain open for a human; screenshots do not approve them.
  Blocked interactions and unfilled slots are visible, including partial runs.
- `processes.json` records stopped/reaped owned processes;
  `evidence-sha256.json` inventories the final private bundle, including
  `index.html`. HTML generation failure is recorded separately in
  `report.private.log` and `execution.json`; it fails an otherwise successful
  command and preserves any original nonzero runner result.

The runner deadline defaults to 20 minutes. The harness stops/reaps its own
runner, Chrome/ChromeDriver, Java, MongoDB and Caddy processes, preserving partial results and the
database on failure. Missing prerequisites produce an exact blocker. A hard
machine kill cannot guarantee cleanup; retained process IDs and private data
allow diagnosis. Do not delete evidence or rerun only passing modules to clear
the workflow. It does not call certification package or publishing endpoints.

## Review criteria and known boundaries

Determine a run's result from its `execution.json`, every signed module
instance and the exact `candidate.json` provenance. Keep validation summaries
with their run bundles. Dated totals, old dependency results and ignored local
report paths are not current compatibility contracts. A new rehearsal must
preserve failed or blocked earlier attempts in their original destinations.

The pinned plans can require visual review for these modules in both code-flow
plans; use the actual outcome of each instance rather than assuming a count:

| Module | Required evidence |
| --- | --- |
| `oidcc-prompt-login` | Actual second login screen and completed password/consent/callback interaction after `prompt=login`. |
| `oidcc-max-age-1` | Actual reauthentication after the suite's age limit, using the same browser profile for both authorizations. |
| `oidcc-ensure-registered-redirect-uri` | Provider rejection page and network evidence that the browser did not navigate to an unregistered redirect. |

REVIEW remains REVIEW until the external review process resolves it. Runner exit
zero, a screenshot upload and matching module totals are not certification.
The Request Object redirect-precedence case may validate its callback and pass
while retaining an unused optional error-page slot or a placeholder REVIEW
event in its signed logs. Preserve both the final instance outcome and its
original conditions; never attach a login page as rejection evidence.

Read current supported capabilities and exclusions in the
[provider contract](oidc-provider.md#http-mount-and-protocol-contract). Optional
profile claims require explicit fixture attributes; do not fabricate user data
to remove a warning. Qualify a new capability through both local Caddy journeys
and a new official-plan run before describing its conformance result. Library
rehearsals alone do not establish the Caddy integration's result.

HtmlUnit success does not prove that Chrome completes consent. Verify actual
browser-generated Origin, response Referrer-Policy and callback-bound
form-action, including cross-origin/forged-CSRF rejection. The selected provider
owns these headers; the current harness does not import a compatibility snippet.
For a reported v1.2.6 deployment only, consult the
[version-scoped consent response policy](oidc-provider.md#consent-response-policy-for-v126).
Do not accept null Origin, rewrite request headers or weaken consent/CSRF checks.

Use `suite-access.private.jsonl` to confirm the suite's received callback
headers. Chrome BiDi redirect events can retain headers from an earlier request
even when the redirected wire request omits them. Distinguish Chrome navigations
from HtmlUnit requests and same-origin callback-page JavaScript; retain raw BiDi
events alongside server observations. Independently verify signed screenshot
bytes, export signatures, evidence hashes, source manifests, report links and
owned-process shutdown. Never edit an immutable run bundle to make a later fix
appear to have passed in that earlier run.

## Regression validation

The explicit Make target first runs harness units, then a fresh Caddy binary,
CLI registration, Caddy adaptation, trusted TLS, real password/consent and
confidential-client exchange/replay E2E preflight before the official plans.
The preflight itself needs no suite/Java/MongoDB. Existing
`TestCaddyOIDCRelyingPartyE2E`, `TestCaddyOIDCProviderE2E`, application-parser and
registration tests cover independent ID-token verification, default/public
PKCE, form-post, code binding and provider deployment behavior.

`assets/scripts/oidc_certification_conformance_tests/test_oidc_conformance_harness.py` checks nonzero/timeout propagation,
process cleanup, scope boundaries, redaction, inherited TLS settings, all outcome
categories, multiple attempts, conflicting results, and real signed-export
verification/tampering, including cleanup of compiler helpers whose launcher
has already exited. It runs only within the explicit conformance workflow.
It also verifies module-specific capture routing, real login/consent commands,
optional client scopes and preservation of identity/password data during
disposable profile seeding.
`test_oidc_conformance_report.py` covers all outcome categories and attempts, safe HTML escaping
and relative evidence links, incomplete/interrupted reports, private artifact
hashes, report-generation failure, and literal Make destination arguments.
Validate report integration by running the actual Make target with a new nested
`CONFORMANCE_RESULTS` destination and checking its report, links, original runner
exit, private modes and SHA-256 manifest. Check a missing-prerequisite run too.
`test_oidc_conformance_setup.py` checks preparation guidance for every missing downloaded
prerequisite, read-only help, and executes the documented removal command in a
disposable fixture to verify that evidence bundles survive.
There is no Go test wrapper or environment switch that adds official plans to
regular testing. Existing local OIDC regression E2E remains enabled.

The isolated `test_oidc_conformance_browser.py` covers exact screenshot-slot binding, second-login
selection, strict TLS capabilities, private Chrome CA storage, safe archive
extraction, redirect-hop preservation, signed PNG identity and HTML/path safety.
Chrome starts with a 1280×900 window. PNG sizes differ across platforms and
themes; that window does not guarantee the pinned suite's 500 KiB decoded image
upload limit (`logging/ImageAPI.java`). Before filling a screenshot slot, an
oversized PNG triggers fresh captures of the same page at window widths of
1024 and then 800 pixels, keeping the height and restoring the original window
afterward. The helper checks the URL and page kind, never repeats a login or
authorization request, and retains every capture with its byte count, window
dimensions and hash. Upload the exact selected Chrome PNG bytes and retain the
private upload response. If the page changes or all attempts exceed the limit,
fail before uploading. Do not edit the image, omit the evidence or modify the
suite's limit. The browser E2E uses a deterministic noisy page to force the
oversized-image path on macOS as well as Linux. Themed errors are recognized
from the real OP error-page heading/alert; login/password/consent forms take
precedence and must never fill a redirect-error evidence slot.
Changes to browser execution require a real Chrome conformance run in addition
to these units; documentation-only updates do not launch the official plans.

`test_oidc_conformance_cleanup.py` covers default/custom/legacy/blocked bundles,
loose logs/audits/helpers and browser-report profiles, retained prerequisites
across repeated cleanup, symlink boundaries, dry-run/idempotent behavior, active
processes and shared/exclusive locks. Its real Make/CLI E2E creates disposable
bundles and supplemental output, deletes them through `make oidc-conformance-cleanup`,
and reuses the retained executable and workspace afterward. These tests also
remain opt-in.

All owned conformance Python test filenames contain `oidc_conformance`; the
directory is `assets/scripts/oidc_certification_conformance_tests/`. Browser
workers, installers and renderers use explicit `oidc_conformance_*` module names.
The Foundation checkout and its own filenames remain unmodified. Historical
signed bundles keep their original filenames and source snapshots.
