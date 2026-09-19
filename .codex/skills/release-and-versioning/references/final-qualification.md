# Caddy integration release qualification

Use this workflow to qualify this repository's complete Caddy executable without
bumping, tagging, publishing, or submitting certification materials. The selected
module graph, actual build toolchain, HTTP host and packaging flags all matter.
A library test report or library binary scan cannot qualify the Caddy artifact.
See [qualified operator inputs](../../configuration/references/operator-examples.md)
for complete Caddyfile/native-JSON journeys and operational limits.

## Reproducible evidence

Create a new private directory under this repository's `tmp/`, with `umask 077`.
Preserve HEAD, dirty status, source-file SHA-256 manifest, a source archive and
working-tree patch; a commit ID alone does not identify an uncommitted candidate.
Record `VERSION` separately from the embedded main-module pseudo-version. Keep
commands, target environment, original exit codes, stdout/stderr and failures.
Record dependency module sums/origin revisions and `go mod verify`, Go/Node/browser
versions, scanner revision and vulnerability database timestamp. Never export the
whole process environment: it may contain service or publication credentials.

Run the required gate from this checkout with bounded concurrency:

```sh
GOMAXPROCS=4 GOTOOLCHAIN=local make ci-check
```

`ci-check` fixes the full test destination to `.coverage/`; a caller's
`COVERAGE_DIR` does not override that recursive invocation. Preserve that report
bundle after completion before a subsequent run replaces its primary files.
The gate includes automation tests, race-enabled Go tests (browser, native,
composed and lifecycle E2E) and host command builds. Count genuine helper/platform
skips separately. A successful local gate is not an official OP all-pass result.
Use [the conformance workflow](../../configuration-oauth-applications/references/oidc-conformance.md)
only through its separate Make target, and retain all non-pass module outcomes.

Read `.goreleaser.yaml` for the actual release target matrix and build flags.
Cross-build `./cmd/authcrunch` for each declared OS/architecture, keeping the same
Go release, module graph, `CGO_ENABLED=0`, `-mod=readonly`, `-trimpath`,
`-asmflags all=-trimpath=<GOPATH>` and `-gcflags all=-trimpath=<GOPATH>` settings.
For every target retain both the release-style `-ldflags '-s -w'` artifact and a
matching build omitting only those stripping flags. Hash and inspect each with
`go version -m`. Cross-compilation and binary analysis do not execute foreign
platforms or establish runtime support for Unix-only private storage on Windows.

For the host binary, independently run `adapt` and `validate` against all six
operator Caddyfiles and their full generated JSON. Run the actual TLS journeys
through `TestCaddyOperatorExamplesE2E`, and retain its native configurations with
`CADDY_SECURITY_EXAMPLE_EVIDENCE` pointing at a new directory under `tmp/`.
Registrations, local identities, keys, fixture environment and full logs stay
private. Defaults retain PKCE; conformance-only registrations are a separate
explicit exception. Do not reuse suite credentials as public examples.

## Vulnerability analysis and interpretation

Pin `golang.org/x/vuln/cmd/govulncheck` explicitly and install it into the private
evidence directory. Use the same effective Go toolchain as the artifact. The
2026-09-19 run used v1.8.0; a later qualification must deliberately select and
record its scanner and current database rather than inherit a clean claim.
With `SCAN` set to that executable and `ARTIFACT` to each final binary, preserve:

```sh
"$SCAN" -json -scan module > "$PRIVATE/module-scan.json" 2> "$PRIVATE/module-scan.stderr"
"$SCAN" -json ./... > "$PRIVATE/source-scan.json" 2> "$PRIVATE/source-scan.stderr"
"$SCAN" -json -mode binary "$ARTIFACT" > "$PRIVATE/binary-scan.json" 2> "$PRIVATE/binary-scan.stderr"
"$SCAN" -mode extract "$ARTIFACT" > "$PRIVATE/binary-extract.json" 2> "$PRIVATE/binary-extract.stderr"
"$SCAN" -mode convert < "$PRIVATE/binary-scan.json" > "$PRIVATE/binary-scan.txt" 2> "$PRIVATE/binary-convert.stderr"
```

Use distinct output names for every artifact and record each original status;
do not let shell error handling discard later evidence after a finding. JSON
mode can exit zero while reporting findings. Preserve converted/text-mode
statuses too. Count `finding` events, not every downloaded OSV advisory in the
JSON stream. Source mode excludes tests by default and its unversioned main
module may not match advisories that the versioned final executable does.

Classify each advisory by module, imported package and affected symbol evidence.
Check extraction before interpreting binary frames: when package/symbol
extraction is empty, govulncheck conservatively substitutes advisory symbols for
installed modules. A wildcard **or a named function** in this fallback is not
proof of linkage. Supplement stripped executables with the matching symbol build,
and preserve both results. Record production `go list -deps ./cmd/authcrunch`
under every target environment when distinguishing unused vulnerable packages
from used modules. Binary symbol presence alone does not prove exploitability;
source analysis also has reflection/dynamic-dispatch limits. Do not suppress an
advisory because a narrower feature regression passes or a source scan exits zero.

Primary references are the [govulncheck documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
and [Go release history](https://go.dev/doc/devel/release). Preserve the scanner's
raw advisory descriptions and fixed ranges with the report, since the database
can change independently of source.

## Recorded candidate: 2026-09-19

The private bundle is `tmp/release-qualification-20260919/`. Its source snapshot
identifies dirty HEAD `127e8df10616a0d0f77b183b08021e91aa5fb066`, repository
`VERSION` 1.1.64, Caddy v2.11.4 and go-authcrunch v1.3.2, without replacements.
Go 1.26.8 built all six Caddy release targets (Darwin/Linux/Windows, amd64/arm64)
with stripped and matching symbol variants. All twelve builds succeeded; every
artifact has a SHA-256, build metadata and raw scan. The embedded main module is
`v1.1.65-0.20260919015759-127e8df10616+dirty`; this is not a VERSION bump.

The final local `make ci-check` returned zero: 33 automation tests passed,
1,840 Go tests passed, 22 subprocess helper entry points skipped in the parent
run, no failures, and 83.31% statement coverage. It included the actual browser,
native, composed, lifecycle and operator-example journeys under race detection.
The finalized tested report is preserved in the private bundle's `ci-report/`.

The gate's actual host `bin/authcrunch` was separately copied and scanned. Its
SHA-256 is `a2ad8b936dc3fc815698c609a68fff4740893c310c4d1bc43e634a0de17e6659`,
identical to both official conformance rehearsal executables. Its JSON scan
returned zero and converted report returned 3, retaining the same advisory
findings below. This host build uses CGO=1; the six release-style target builds
use CGO=0. The conformance binary identity does not imply execution of the
foreign or differently flagged artifacts.

All twelve Caddyfile/native-JSON operator journeys passed under the race detector.
The host release-style executable also passed eighteen separate commands:
adaptation and Caddyfile/native-JSON validation for each of the six profiles.
An initial test assertion incorrectly expected a cookie for access-only JSON
login; the test was corrected to use its returned access token. The original
failed run is retained alongside the successful run, not relabeled as passed.

The vulnerability database timestamp was `2026-09-16T18:00:43Z`. Original JSON
scan statuses were zero; converted module and binary reports returned 3. The
source report returned zero at symbol level while retaining package/module
findings. These are **not clean scans**:

| Finding | Evidence and remaining work |
| --- | --- |
| [GO-2024-2549](https://pkg.go.dev/vuln/GO-2024-2549) | Reflected XSS advisory against this module; unresolved release triage. |
| [GO-2024-2557](https://pkg.go.dev/vuln/GO-2024-2557) | Session expiration advisory; unresolved release triage. |
| [GO-2024-2558](https://pkg.go.dev/vuln/GO-2024-2558) | Authentication bypass/spoofing advisory; unresolved release triage. |
| [GO-2024-2559](https://pkg.go.dev/vuln/GO-2024-2559) | XSS advisory; unresolved release triage. |
| [GO-2024-2560](https://pkg.go.dev/vuln/GO-2024-2560) | Open redirect advisory; unresolved release triage. |
| [GO-2024-2561](https://pkg.go.dev/vuln/GO-2024-2561) | SSRF advisory; unresolved release triage. |
| [GO-2024-2562](https://pkg.go.dev/vuln/GO-2024-2562) | HTTP header neutralization advisory; unresolved release triage. |
| [GO-2024-2563](https://pkg.go.dev/vuln/GO-2024-2563) | Excessive authentication attempts advisory; unresolved release triage. |
| [GO-2024-2564](https://pkg.go.dev/vuln/GO-2024-2564) | Array-index validation advisory; unresolved release triage. |
| [GO-2024-2565](https://pkg.go.dev/vuln/GO-2024-2565) | Insufficient randomness advisory; unresolved release triage. |
| [GO-2026-6094](https://pkg.go.dev/vuln/GO-2026-6094) | cel-go v0.28.1; fixed v0.30.0. `ext` is imported, but source analysis found no affected call and matching binaries found no affected symbol. Retain the package finding for dependency remediation. |
| [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | x/crypto v0.57.0 contains obsolete OpenPGP packages with no fixed version. Module-only finding in source/full-symbol analysis; no production target imports OpenPGP. Stripped wildcard frames are fallback, not package linkage. |

The ten caddy-security advisories have no fixed range in the recorded database.
All six symbol builds matched three packages and 22 symbols for each of these
broadly scoped advisories. Those matches do not establish ten exploitable paths,
but neither the feature suite nor the unversioned source scan closes them.
Advisory-specific security triage/remediation is an explicit release blocker.
No suppressions or dependency substitutions were applied.

Every stripped artifact had zero extractable package symbols. The matching
builds retained 77,694–78,287 symbols. Stripped CEL function names and OpenPGP
wildcards must therefore remain labeled as conservative module fallback.

## Official conformance findings retained

The two actual Caddy rehearsals are retained at
`tmp/oidc-conformance/caddy-rehearsal-20260919/` and its `-repeat` sibling under
the same repository temporary area. Both used unmodified suite v5.2.4,
`e3b5558d6d5e0c17ab578a47b955fd3b405f902b`, with Basic OP, Config OP and Form Post
OP code-flow plans. Each recorded **65 PASSED and 6 REVIEW**, zero other outcomes,
runner status zero, and `all_passed: false`. This supersedes neither the suite's
review decisions nor any library-only rehearsal.

| Remaining module | Basic OP | Form Post OP | Required assessment |
| --- | --- | --- | --- |
| `oidcc-prompt-login` | REVIEW | REVIEW | Human review of the actual reauthentication interaction and screenshots. |
| `oidcc-max-age-1` | REVIEW | REVIEW | Human review that the expired authentication age caused the required interaction. |
| `oidcc-ensure-registered-redirect-uri` | REVIEW | REVIEW | Human review of the displayed rejection for the unregistered callback. |

The report retains all 71 module outcomes, browser evidence, signed exports,
142 verified signatures and six matched signed screenshots per run. No review
was turned into an expected pass. Browser and harness TLS trust controls passed;
the unmodified suite's own permissive internal HTTPS client is a separate limit,
so do not present this as comprehensive suite-side TLS validation. There is no
certification or submission. The remaining reviews are release-readiness findings
and prevent an all-pass conformance claim.

Preserve the [composition limitations](../../testing-and-ci/references/composition-qualification.md):
single-process volatile grants, no active/active OP/refresh support, nontransactional
cross-component completion, persistent identity-file reload restrictions, and
INFO-level upstream OAuth logging. Two library-owned gaps remain separate work:
DEBUG OAuth logging can disclose callback/token credentials, and the forwarded
address parser mishandles some IPv6 representations outside the tested compressed
case. Do not expand the tested INFO/edge guarantees to those cases. Security
findings and protocol reviews belong
in the release decision even when the required local gate succeeds. Publication
requires a separate instruction; this qualification performs none.
