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
evidence directory. Use the same effective Go toolchain as the artifact.
Record the scanner version and database timestamp for each qualification;
a previous candidate's result cannot establish that this candidate is clean.
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

## Qualification decision and retained findings

Evaluate the exact candidate against its own evidence. Keep dated run totals,
source hashes, credentials, scanner output, screenshot IDs, and temporary paths
in the private qualification bundle rather than this workflow. A prior passing
build, local gate, or zero scanner status does not qualify a new dependency
selection or close an unresolved finding.

Carry forward unresolved advisory assessments from previous reports until there
is a recorded, source-backed disposition. Prior reports identified this module's
GO-2024-2549 and GO-2024-2557 through GO-2024-2565 advisories; do not infer a fixed
range or remediation from a version bump, a feature test, or an unversioned source
scan. Recheck the actual affected ranges and code paths with current official
advisory data during release qualification. Preserve upstream dependency findings
and distinguish affected modules, linked packages, affected symbols, and proven
exploitability. This workflow does not itself declare any advisory resolved.

Official conformance requires the actual Caddy candidate and its original runner
status, complete module outcomes, signed exports, hashes, and browser evidence.
A `REVIEW`, `WARNING`, `SKIPPED`, `UNKNOWN`, interruption, or failure remains
visible even when the runner exits zero. In particular, inspect actual browser
reauthentication, expired authentication age, and unregistered callback rejection
when the suite requires human review. A library run or an older candidate is
not evidence for the current Caddy artifact. Follow the
[conformance review criteria](../../configuration-oauth-applications/references/oidc-conformance.md)
for the selected suite and retain incomplete attempts.

Apply the [composition limits](../../testing-and-ci/references/composition-qualification.md)
and distinguish the default in-memory runtime from explicitly configured
[persistent state](../../configuration-state/SKILL.md). Neither mode promises
active/active sharing or a transaction across every component. Validate the
chosen stop/start or reload boundary, current identity policy, and logging/edge
trust limits for the candidate being qualified.

## Acceptance evidence

- A report identifies the precise dirty or clean source, selected modules,
  toolchain, target flags, and hashes for every artifact. Cross-built artifacts
  are not described as executed on foreign platforms.
- A stripped binary with no extractable symbols retains conservative findings
  and the matching symbol build; it is not declared clean from missing frames.
- A zero runner status with unresolved conformance reviews remains a non-all-pass
  result. Release readiness states each unresolved assessment and its owner.
- Qualification leaves VERSION, tags, remote refs, and certification submission
  unchanged. Publication is a separate requested operation.
