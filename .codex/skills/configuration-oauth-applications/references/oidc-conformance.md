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

The current Caddy dependency pin is
`go-authcrunch v1.3.2`, whose published tag resolves to
commit `709b1845bd917967dda828092da83316e4a71b09`. Use an immutable published
commit pin when qualifying newer upstream work; this harness rejects local
module replacements and records the downloaded module checksums and Git origin.
Reading a sibling checkout alone does not select it for a Caddy build.

The current provider supplies themed consent, form-post and browser error pages,
including same-origin referrer policy and callback-bound form-action. The Caddy
deployment preserves those headers without importing the older v1.2.6 snippet.
`consent-policy.json` records policy ownership and links to candidate provenance.
Preflight validates CSP directives, nonce-limited styles and same-origin assets,
and still rejects null/cross-origin and forged-CSRF submissions.

## Verified v1.3.2 Caddy rehearsal

The 2026-09-18 run at
`tmp/oidc-conformance-ci-v1.3.2-final/private/evidence/index.html` completed all
71 instances with **65 PASSED, 6 REVIEW, zero WARNING/SKIPPED/FAILED/INTERRUPTED**
and original runner exit **0**. It used published go-authcrunch v1.3.2, Caddy
v2.11.4, the pinned Chrome and unchanged suite below. The six REVIEW instances
are `oidcc-prompt-login`, `oidcc-max-age-1` and
`oidcc-ensure-registered-redirect-uri`, once in each code-flow plan. Their actual
Chrome screenshots, repeated authentication journeys and redirect rejection
remain available for human review; these labels were not promoted to PASSED.

The [manual Actions artifact workflow](oidc-conformance-actions.md) was exercised
locally through its stage wrapper. Its artifact is at
`tmp/oidc-conformance-ci-v1.3.2-final/artifact/index.html`. Decryption verified all
1,701 archived files against their original bytes, all 1,692 evidence hashes,
and six signed screenshot slots. Both reports passed actual Chrome desktop and
390-pixel mobile layout checks. This local macOS execution does not claim that
the new hosted Ubuntu workflow has been dispatched.

The earlier `tmp/oidc-conformance-ci-v1.3.2/` attempt remains a blocked run:
a new CI timeout-cleanup unit exposed a transient macOS process-group probe
error before official modules started. Its original failure and encrypted
artifact remain intact. Cleanup now waits for the owned child to be reaped;
preparation also unwinds independent helper sessions on SIGTERM. The final
isolated harness/CI validation passes 63 tests, including real encryption,
cancellation, private-output and original-exit checks.

The v1.3.2 normal race-enabled `make test` run at
`.coverage/authcrunch-v1.3.2/index.html` passed 1,827 tests with 21 intentional
subprocess-helper skips, zero failures and 83.31% merged coverage (3,060/3,673
statements). Regular automation passed 16 tests; the build, module verification,
workflow lint and all 42 Caddyfile audit classifications also passed. Compared
with the prior published commit pin, delegated parsers and provider runtime are
unchanged; the production library diff updates the embedded authdb version.

## Official instructions and pin

The Foundation's [current OP instructions](https://openid.net/certification/connect_op_testing/)
and [local Build & Run instructions](https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-%26-Run)
were inspected on 2026-09-18. Static testing requires independent Basic clients
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
Make targets and uploads an HTML summary plus encrypted complete private evidence.
It is separate from regular CI and needs an age public recipient configured once.

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
missing evidence as success. It is private evidence, not a publishable report.

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
The cleanup/naming change passed 44 isolated harness tests, 12 regular automation
tests and the actual Caddy local preflight. Its full opt-in rerun at
`tmp/oidc-conformance/oidc-cleanup-conformance-e2e/index.html` finished all 71
instances with 65 PASSED, 6 REVIEW, no interruptions and original runner exit 0.

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
| `tools/` | Download archives and versioned extracted directories; the three paths above are links into them. |
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
Only reviewed redacted material is suitable for sharing; neither a full export
nor `summary.json` is a public report.

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

## Current upstream qualification (2026-09-18)

The `authcrunch-3e28980-complete` run tested Caddy v2.11.4 with the immutable
go-authcrunch revision selected above, Go 1.26.8 and headless Chrome
153.0.8010.47. All 71 official module instances finished, with original runner
exit **0**, **65 PASSED and 6 REVIEW**, and no WARNING, SKIPPED, FAILED or
INTERRUPTED modules. This is not an all-pass result or certification.

| Plan | PASSED | REVIEW |
| --- | ---: | ---: |
| Basic OP code | 32 | 3 |
| Config OP | 1 | 0 |
| Form Post OP code | 32 | 3 |

Every remaining REVIEW is an explicit visual check, once in each code plan:

- `oidcc-prompt-login`: inspect the second login screen and subsequent password
  interaction after `prompt=login`.
- `oidcc-max-age-1`: inspect reauthentication after the suite's age limit.
- `oidcc-ensure-registered-redirect-uri`: inspect the provider's error page and
  confirm no navigation to the unregistered redirect URI.

The private HTML entry point is
`tmp/oidc-conformance/authcrunch-3e28980-complete/index.html`. Each review links
the original Chrome screenshot, browser/network timeline and official checks.
All six uploaded screenshots match their signed exports byte for byte; all
142 detached export signatures verify. Evidence hashes and offline report
links were checked, and all owned processes were reaped. The provider supplies
its own consent headers; no Caddy header override is active.

The preceding `authcrunch-3e28980-initial` attempt stopped at preflight because
the harness expected the old unstyled CSP. `authcrunch-3e28980-browser` then
stopped on the official 500 KiB screenshot limit. Both attempts and their
original outcomes remain in separate bundles. The correction validates the
themed policy and captures a smaller, unmodified Chrome viewport; it does not
change suite checks or reinterpret incomplete attempts as passes. The first
successful run, `authcrunch-3e28980-viewport`, has the same totals. A subsequent
`authcrunch-3e28980-final` attempt stopped in harness unit tests after a callback
variable was mistakenly removed during cleanup; it ran no official modules.
The variable was restored before the complete run, whose 52 isolated harness
unit tests also passed.

The final regular unit/race/E2E run also passed:
`.coverage/authcrunch-3e28980-validated/index.html`, **1,787 PASSED**, 21 skipped
subprocess entry points exercised by their parent E2E tests, zero failures,
all four packages passed, and **82.68% coverage**. It qualified real TOTP replay
protection, canonical profile isolation, credential invalidation after role
changes, all nine cookie roles, provider-owned themed page policies, HTTPS
Origin rejection and TCP/QUIC port selection. Regular automation passed all 12
tests; all 42 standalone Caddyfile audits matched their expected behavior.
Build, module verification, license and skill metadata/link checks passed.
The private overview at `tmp/oidc-upstream-3e28980-diagnostics/index.html` links
the final and intermediate results without replacing their recorded outcomes.

## Historical Caddy rehearsals and non-pass modules

The first full Caddy run on 2026-09-17 used Caddy **v2.11.4** and authcrunch
**v1.2.5**, not a sibling replacement. All 71 modules completed, with the
following original outcomes and a nonzero official runner result:

| Plan | PASSED | WARNING | SKIPPED | REVIEW | FAILED | INTERRUPTED |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Basic OP | 24 | 3 | 4 | 4 | 0 | 0 |
| Config OP | 0 | 1 | 0 | 0 | 0 | 0 |
| Form Post OP code | 24 | 3 | 4 | 4 | 0 | 0 |
| Total | 48 | 7 | 8 | 8 | 0 | 0 |

The following accounts for every non-pass result in that historical v1.2.5 run.
Except the single Config
module, each row occurs once in Basic and once in Form Post:

| Module | Result | Explanation / ownership |
| --- | --- | --- |
| `oidcc-scope-profile` | WARNING | Library/local identity model does not supply every optional profile claim. Do not fabricate attributes. |
| `oidcc-ensure-request-with-acr-values-succeeds` | WARNING | Library does not advertise/assert an authentication-context vocabulary or return `acr`; `amr` is separate. |
| `oidcc-claims-essential` | WARNING | Library advertises `claims_parameter_supported=false`; individual `name` requests do not override approved scopes. |
| `oidcc-discovery-endpoint-verification` (Config only) | WARNING | Library supports unsigned by-value Request Objects, not the recommended RS256-signed Request Objects/client verification keys. ID tokens themselves are RS256 signed. |
| `oidcc-scope-address` | SKIPPED | Optional address scope is not advertised. |
| `oidcc-scope-phone` | SKIPPED | Optional phone scope is not advertised. |
| `oidcc-scope-all` | SKIPPED | Required optional scopes are not all advertised. |
| `oidcc-refresh-token` | SKIPPED | OIDC refresh grant is not implemented; portal refresh is a separate protocol. |
| `oidcc-prompt-login` | REVIEW | Captured actual repeated-login page; review remains required. |
| `oidcc-max-age-1` | REVIEW | Captured actual reauthentication page after the suite's wait; review remains required. |
| `oidcc-ensure-registered-redirect-uri` | REVIEW | Captured actual rejection page for an unregistered redirect. |
| `oidcc-ensure-request-object-with-redirect-uri` | REVIEW | The original harness incorrectly attached a login page to an optional error-page slot; callback validation subsequently succeeded. This was not redirect rejection. |

The capability gaps above were addressed upstream in v1.2.6. No Caddy runtime
failure was observed in those modules. Initial harness startup/collection
failures are retained as failed attempts, including a terminated runner that
could not authenticate to the suite API; they are not module passes. Inspect
the latest run's `execution.json` and signed results before reporting a new
candidate's outcome. A matching count from the library run is not evidence
for Caddy, and these counts do not establish OpenID certification.

### Earlier HtmlUnit rehearsal with released go-authcrunch v1.2.6

The September 17 `v1.2.6-caddy` run used the published v1.2.6 module without a
replacement, Caddy v2.11.4, and the same clean suite revision. The actual Make
target completed all 71 modules with original runner exit **0** and Make exit
**0**:

| Plan | PASSED | REVIEW | WARNING | SKIPPED | FAILED | INTERRUPTED |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Basic OP | 32 | 3 | 0 | 0 | 0 | 0 |
| Config OP | 1 | 0 | 0 | 0 | 0 | 0 |
| Form Post OP code | 32 | 3 | 0 | 0 | 0 | 0 |
| Total | 65 | 6 | 0 | 0 | 0 | 0 |

All six remaining non-pass modules require visual review: `oidcc-prompt-login`,
`oidcc-max-age-1`, and `oidcc-ensure-registered-redirect-uri`, once in each
code-flow plan. The first two preserve actual fresh-login page source; the
third preserves the unregistered-redirect `invalid_request` page. Review the
captured behavior and meet any additional Foundation screenshot requirements.
Do not relabel these REVIEW outcomes or infer certification from runner exit 0.

Both `oidcc-ensure-request-object-with-redirect-uri` instances now pass through
real callback validation. Their unused optional error-page slots and original
placeholder REVIEW events remain in the exports; neither is a failed module or
a reason to attach unrelated evidence. All original v1.2.5 bundles remain intact.

Private entry point: `tmp/oidc-conformance/v1.2.6-caddy/index.html`. The collector
verified 142 signatures across the overlapping plan/per-instance ZIPs, covering
all 71 distinct instances. This is Caddy deployment evidence independent of the
earlier library rehearsal; nothing was submitted or published.

The earlier report-validation run at `tmp/oidc-conformance/v1.2.6 final/index.html`
reproduced these exact outcomes and exit 0, using a destination containing a
space. All 23 opt-in harness tests passed. Its six captures were checked against
their requested evidence slots, every HTML link resolved, all 253 artifact
hashes/private modes verified, and every owned process was reaped and exited.
The selected release origin is `ba3696f476bcc99650df7c523e583679272589b5`;
Caddy v2.11.4's origin is `e2eee6a7fce366321294c9c2a79f3146891dcbdf`.
Candidate commit `deeac190d49426ab16ec6587aec946763d5df5e9` plus the retained
patch, source manifest and binary identify the uncommitted Caddy candidate.
The HTML explains why an unused optional error-page slot and a placeholder
REVIEW event can coexist with a PASSED Request Object module.

### Original headless Chrome run exposed a consent blocker

The real-browser rehearsal of the same released v1.2.6 produced **65 PASSED,
2 REVIEW, 4 INTERRUPTED**, original runner exit **1**. All 71 instances executed;
all 142 overlapping plan/per-instance signatures verified. The two remaining
REVIEW instances are `oidcc-ensure-registered-redirect-uri`, one per code plan.
Each has a real Chrome PNG in its exact signed evidence slot. The four interrupted
instances are `oidcc-prompt-login` and `oidcc-max-age-1` in both code plans.

Those four reach password authentication and consent on their first authorization,
but the consent POST returns `403 invalid_request`. The screenshot timeline and
BiDi records show the actual chain: consent GET response `Referrer-Policy:
no-referrer`, Chrome form POST `Origin: null`, then 403. This matches the
[Fetch Origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header).
In go-authcrunch v1.2.6, `pkg/oidc/http.go:oidcHeaders` sets that policy;
`pkg/oidc/authorization.go` requires `sameOrigin` for consent, and
`pkg/oidc/provider.go:sameOrigin` rejects the resulting null origin. The same
browser conflict was seen in an earlier diagnostic before the Chrome preference
was established. No provider/security checks were disabled.

This is **upstream work**: serve consent with a policy that preserves the
same-origin form Origin (for example `same-origin` on that page), retain the
origin and CSRF-token checks, and add real headless Chrome consent/reauthentication
regressions. Validate cross-origin rejection and lack of cross-origin referrer
leakage before releasing. Do not accept null Origin as a workaround. Caddy-owned
harness fixes do not authorize editing the sibling repository.

The original headless Chrome report was recorded at
`tmp/oidc-conformance/chrome-evidence/index.html`; the `chrome-3` diagnostic and
all earlier attempts are retained. The final run records all 71 instances,
18 real screenshots, two signed official PNG uploads, original runner exit 1,
and four explicit consent blockers. All 33 opt-in harness units passed. The
independent audit verified 142 export signatures, 1,542 private artifact hashes,
360 archived source files, 1,828 HTML/image links and stopped owned processes.
The final HTML also passed real Chrome desktop/mobile checks for image loading,
expandable network records, blocker explanations and layout. The audit and UI
check outputs are under `tmp/oidc-chrome-evidence-audit.json` and
`tmp/oidc-chrome-viewer-final/`, outside the immutable evidence bundle. Earlier HtmlUnit counts above are
historical and do not prove successful real-browser consent. A subsequent
deployment or released upstream fix must be rerun through this exact Caddy workflow before
claiming that the interrupted cases complete. Screenshots cannot complete
second-login review while the first consent is blocked.

### Caddy deployment correction

The harness now includes the reusable
[v1.2.6 consent response policy](oidc-provider.md#consent-response-policy-for-v126)
in its actual adapted Caddy deployment. It uses standard Caddy response-header
matching to emit `Referrer-Policy: same-origin` only on successful consent HTML.
The same responses retain restrictive CSP with form-action limited to `'self'`
and the registered suite callback's exact HTTPS origin. Chrome checks that
policy on the post-consent redirect as well; the original self-only value
aborts the valid cross-origin callback. No wildcard or scheme-wide source is used.
It leaves `authenticate` delegation and all provider security checks intact.
The library and suite remain unmodified. Other Caddy deployments need to import
the documented snippet explicitly; this does not change the library default.

`consent-policy.json` records the exact paths, callback origin, scope and snippet hash. The HTML
report explains the deployment policy and links its Caddyfile and local E2E
evidence. Before starting the official plans, each of the three clients must
reject `Origin: null`, a different Origin and a forged CSRF token, then complete
consent with the correct Origin/CSRF and reject code replay. Actual Chrome
submits its own headers during the official password/consent/reauthentication
flows. Preserve the earlier interrupted runs as historical evidence; never
reinterpret those outcomes after changing deployment configuration.

The referrer-only diagnostic at `tmp/oidc-conformance/chrome-consent-fixed`
preserves 14 PASSED and one unfinished UNKNOWN instance, with the remaining
modules not run. Chrome emitted the correct Origin but aborted the consent
redirect under the original self-only CSP. The browser worker stopped, the
owned runner was terminated (original exit `-15`, shell result 143), and the
report records `EVIDENCE_ERROR`. This attempt is not a complete plan result.
The combined referrer/form-action deployment uses a separate destination.

`suite-access.private.jsonl` records Caddy's incoming suite requests privately.
Use it to verify actual callback headers: Chrome BiDi redirect events can retain
headers from an earlier request even when the redirected wire request omits
them. In particular, inspect headless Chrome callback navigations separately
from the suite's HtmlUnit traffic and same-origin callback-page JavaScript.
The raw BiDi events remain unchanged, alongside the server's observations.

### Verified combined-policy rehearsal

The completed `make oidc-conformance-test` run at
`tmp/oidc-conformance/chrome-consent-final/index.html` records **65 PASSED,
6 REVIEW, zero WARNING/SKIPPED/FAILED/INTERRUPTED**, with original runner exit
**0**. All 71 instances finished. It used the published go-authcrunch v1.2.6,
Caddy v2.11.4, pinned Chrome 153.0.8010.47 and the unchanged suite revision above.
The preceding `chrome-consent-complete` run also completed with 65 PASSED and
6 REVIEW; the final run adds private server access evidence and the corrected
mobile report layout. Each bundle retains its own exact source/build evidence.

| Plan | PASSED | REVIEW | INTERRUPTED |
| --- | ---: | ---: | ---: |
| Basic OP | 32 | 3 | 0 |
| Config OP | 1 | 0 | 0 |
| Form Post OP | 32 | 3 | 0 |

The six remaining outcomes are `oidcc-prompt-login`, `oidcc-max-age-1`, and
`oidcc-ensure-registered-redirect-uri`, once in each code-flow plan. The first
two now complete both password/consent/callback sequences using the same Chrome
profile and attach the actual second-login screenshot. The redirect case
attaches the provider's actual rejection page. These are the suite's visual
review requirements, not hidden failures or automatic PASSED results. Review
their linked timelines, network records and signed conditions; do not change
the recorded REVIEW labels or claim certification.

The independent audit in `tmp/oidc-consent-final-audit.json` verified 142 export
signatures, all 1,668 private artifact hashes, 361 archived source files, 2,033
HTML/image links, 34 screenshots and all six PNGs in their signed evidence slots.
All eight real Chrome consent submissions carried the correct Origin, and
Caddy received all eight Chrome callback navigations without cross-origin
Referer. Thirteen recorded owned PIDs were stopped. Seven final HTML pages
passed actual Chrome desktop and 390-pixel mobile checks, including image
loading, expanded details and overflow. UI evidence is outside the immutable
bundle at `tmp/oidc-consent-report-ui-final/`.

Validation for this correction passed 35 isolated harness/report units and
50 focused Go tests, including adaptation/delegation units and the actual
Caddy TLS RP E2E at both mounts. Its report is
`.coverage/oidc-consent-redirect/index.html`. The regular testing targets still
do not launch official conformance.

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
Chrome uses a 1280×900 window so the themed login fits the pinned suite's
500 KiB decoded image upload limit (`logging/ImageAPI.java`). Upload the exact
Chrome PNG bytes, retain the original and the private upload response, and fail
explicitly before uploading if the size limit is exceeded. Do not edit the
image, omit the evidence or modify the suite's limit. Themed errors are recognized
from the real OP error-page heading/alert; login/password/consent forms take
precedence and must never fill a redirect-error evidence slot.
A real Chrome conformance execution is required in addition to these units.

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

The v1.2.6 upgrade also passed the full normal `make test` unit/E2E workflow
(`.coverage/authcrunch-v1.2.6-final/index.html`): zero failures, 81.7% coverage,
and 21 subprocess-helper entry points skipped in the parent run and exercised
through their E2E parents. Regular automation passed all 12 tests. Restrictive
umask coverage exposed two nonprivate-key rejection fixtures that now explicitly
set their intended `0644` mode; the production permission check remains intact.
The earlier failed test log is retained under `tmp/` alongside the successful rerun.
