# Parallel GitHub validation

Read this reference when changing `.github/workflows/build.yml`,
`assets/scripts/ci_tests.py`, the timing inventory, or the `ci-quality`/`ci-prepare`/`ci-test-shard` Make targets.

## Execution and selection

The planning job resolves a shared versioned artifact identity. Repository
quality gates and shared Go build preparation run concurrently. Preparation
emits a 44-entry Go matrix from the discovered root test inventory. Both jobs
must succeed before any Go shard starts; a quality failure skips the matrix.
`make ci-check` retains its sequential local/release-script behavior.

Forty-three shards split the root package and one `packages` shard discovers
every other package. The split preserves every top-level test and its subtests:

| Workload | Split |
| --- | --- |
| Runtime | 24 numbered groups, longest recorded journeys assigned first |
| Local identity | Separate password, MFA, mutation/public-key parents |
| Authentication client | Legacy and native parent tests |
| CLI | Authenticator journeys, SQLite identity commands, other commands |
| Direct OAuth | Normal journeys and a dedicated pending-expiration parent |
| OIDC | Provider, relying party, JWKS, access signers, signer persistence |
| Refresh | Protocol/provider, SQLite, browser |
| Cross-device | Normal journeys and dedicated real-time expiration |
| Other | Existing core, browser and non-root package groups |

Runtime planning uses the recorded per-test durations in
`assets/scripts/ci_runtime_timings.json` with deterministic longest-first
assignment and lexical tie breaks. Preserve the source run/revision with timing
updates. New E2E parents use a conservative 90-second fallback; other unrecorded
app tests use two seconds. The three new local-identity parents initially share
an equal estimate from the former combined parent; replace those estimates with
separate hosted measurements. New names and packages remain exhaustively selected.

Aim for less than five minutes per ordinary shard and less than seven minutes
including setup/reporting. Confirm this with subsequent hosted timing evidence;
these are targets, not replacement deadlines or guaranteed runner performance.
The direct OAuth and cross-device expiration parents must still wait the real
five-minute protocol lifetime. Keep each on its own runner with prepared builds;
do not shorten or mock expiry to meet a timing target. Do not add `t.Parallel`
to Caddy lifecycle journeys to obtain cross-runner concurrency.

Each shard discovers this module's package graph with read-only `go list`.
Root shards list runnable tests, examples and fuzz targets with matching
race/coverage flags under the existing resource guard. Listing honors build
constraints and external test packages. All root shards must agree on the
inventory. Exact selectors escape the final dollar sign for Make; inherited
filters cannot narrow the selected tests. Empty groups, graph/discovery errors
and invalid shard names fail rather than silently skipping validation.

`make ci-test-shard CI_SHARD=root-refresh` runs that full group locally when
explicitly needed; it is not a change-based development filter. `COVERAGE_DIR`
must resolve inside this checkout. Shards use separate runner checkouts because
the resource lock serializes guarded work within one checkout.

## Caches and runner setup

Module caches are shared by OS, architecture, compiler version and `go.sum`.
Per-shard build caches also include the shard and commit, with older shard/root
fallbacks. A separate preparation job runs `make ci-prepare` under the resource
guard: it lists the instrumented root tests, warms the trimpath Caddy fixture
build and race-enabled authenticator build, and publishes a common build cache.
Listing/building does not run test bodies. Its evidence is `.coverage/prepare/`;
binaries stay under ignored `tmp/ci-prepare/`.

Each shard first restores its own build cache, then overlays the prepared cache
for the same compiler, dependency hash and commit. This preserves nested build
reuse while avoiding repeated cold compilation of the instrumented root package.
A cache miss still allows guarded Go discovery/builds to reconstruct the cache;
a preparation/build error fails validation. Never reuse cache presence as proof
that a test ran or skip the fresh tested invocation.

The build workflow pins checkout and Go setup to Node 24 action runtimes.
Keep these action runtimes distinct from the Go compiler and browser Node
version pins. Review action metadata and supported inputs before upgrading;
checkout still disables persisted credentials and Go setup leaves caching to
the explicit cache steps.

Preparation derives each matrix row's browser prerequisite from its selected
test names, including parents that call browser helpers without `Browser` in
their names. Keep `BROWSER_TESTS` aligned with those callers. Only those rows
install Node 24/NSS and verify Chrome. Preparation and quality avoid browser
setup; standalone expiration rows also avoid it.
All Go shards retain race detection, fresh execution and whole-process-tree
guards. Individual shards use a zero coverage minimum because a separately built
command can exercise the real integration without parent-binary counters. The
complete merged profile still enforces the existing 1-percent nonempty policy;
manifest/source-block checks reject incomplete root profiles. Normal local Make
coverage defaults remain unchanged. Read
[resource controls](../../scripts-and-automation/references/test-resources.md)
before changing hosted budgets; local defaults remain unchanged.

## Completion and failure evidence

Quality failures prevent the whole Go matrix from starting. Within a started
matrix, `fail-fast` is disabled so one shard failure does not cancel other evidence.
Each attempted shard writes selection status, tested reports, raw events,
resource evidence and a timing summary under `.coverage/shards/<name>/`.
GitHub step summaries show package durations, elapsed time and peak memory;
`timing.json` also retains the slowest top-level tests for rebalancing after
actual hosted runs. A failed discovery or rerun invalidates the prior selection
before it can reuse old successful reports.

Each attempted shard uploads its bundle even on failure. The final `core` job,
still named `Tests and coverage`, requires successful planning, quality, preparation and Go
matrix results. It downloads available shard bundles when the matrix was
attempted; a matrix skipped after a prerequisite failure does not trigger artifact
download or upload. It retains failures and cannot turn an omitted, failed or
cancelled gate into success. The release-main
push skip applies to planning and its dependents; reusable release-tag validation
still runs the complete matrix before publishing.

Successful completion checks every tested manifest's file sizes and SHA-256
hashes, successful guard/capture status, matching package plans and discovery
inventories, and exactly one terminal event per selected package/root test.
Ordinary Go skips remain skips in raw evidence. Coverage must be atomic with
identical root source blocks; only the intentionally shared root package may
overlap. Sum its counters and count each statement once. Preserve each shard's
original reports/manifests and keep the aggregate separate from a tested run.

The combined artifact retains the existing
`caddy-security_coverage_<artifact-id>` name. Open `.coverage/index.html` after
extracting it; `.coverage/combined/` contains the execution summary and standard
merged `coverage.out`. Individual artifacts append `_shard_<name>`. All include
hidden files, fail on missing files, retain evidence for 14 days, and replace
matching names on reruns. Failed runs can have only partial per-shard evidence
and no successful aggregate index/profile.

## Regression validation

`assets/scripts/tests/ci_shards_test.py` contains focused partition tests and a
real Make/Go/tested fixture in a disposable directory inside this checkout.
It exercises new-name fallback, weighted runtime balancing, browser prerequisite
selection, guarded preparation, discovery, exact filtering, real shards with
honest zero-counter external-command coverage, comparison with an unsplit profile,
standard Go coverage tools,
failure gates, failed reruns, corrupted/missing evidence and bundle isolation.
The quality job discovers it through `make test-automation`. When local tests
are authorized, use a focused automation selection while iterating:

```sh
python3 -m unittest discover -s assets/scripts/tests -p 'ci_shards_test.py' -v
```

`assets/scripts/tests/test_timeout_test.py` verifies deadline arguments through
the real Make/guard boundary. Its workflow budget check must select the named
`go` job, independently of job order or nested step timeouts; planning, quality
and aggregate jobs have separate, shorter budgets. Keep its Go-job selection
regression when changing the workflow layout.

Run `make test-automation` when validating the complete changed Make/tested
lifecycle. Static syntax and metadata checks do not establish runtime success;
when tests are deferred to GitHub, state that limitation explicitly.
