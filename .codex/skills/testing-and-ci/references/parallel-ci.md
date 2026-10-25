# Parallel GitHub validation

Read this reference when changing `.github/workflows/build.yml`,
`assets/scripts/ci_tests.py`, or the `ci-quality`/`ci-test-shard` Make targets.

## Execution and selection

The planning job resolves a shared versioned artifact identity and emits a
ten-entry matrix without compiling Go. `make ci-quality` runs version checks,
Python automation fixtures and both binary builds on one runner, concurrently
with the Go matrix. `make ci-check` retains its sequential local/release-script
behavior and is not invoked by the hosted workflow.

Nine shards split the root package by top-level test name, in priority order:
cross-device, direct OAuth, authentication client, CLI/credential commands,
refresh, OIDC/JWKS/access signers, remaining browser tests, app/Caddy runtime,
then core. New tests fall into an existing group, including the core fallback;
new non-root packages automatically join the tenth `packages` shard. Keep parent
tests and their subtests together. Do not add `t.Parallel` to Caddy lifecycle
journeys to obtain cross-runner concurrency.

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
Build caches additionally include the shard and commit, with earlier shard/root
cache fallbacks for reuse. Distinct commit keys allow changed source to refresh
the cache instead of indefinitely reusing an immutable cache entry.

Only refresh, browser and cross-device shards install Node 24 and NSS tooling
and verify the runner's Google Chrome. Keep that prerequisite mapping aligned
with test ownership. The quality job and other Go shards avoid browser setup.
All Go shards retain race detection, fresh execution, the 1-percent nonempty
coverage policy and whole-process-tree guards. Read
[resource controls](../../scripts-and-automation/references/test-resources.md)
before changing hosted budgets; local defaults remain unchanged.

## Completion and failure evidence

Matrix `fail-fast` is disabled so one failure does not cancel other evidence.
Each attempted shard writes selection status, tested reports, raw events,
resource evidence and a timing summary under `.coverage/shards/<name>/`.
GitHub step summaries show package durations, elapsed time and peak memory;
`timing.json` also retains the slowest top-level tests for rebalancing after
actual hosted runs. A failed discovery or rerun invalidates the prior selection
before it can reuse old successful reports.

Each attempted shard uploads its bundle even on failure. The final `core` job,
still named `Tests and coverage`, requires successful planning, quality and Go
matrix results. It downloads available shard bundles, retains failures, and
cannot turn an omitted, failed or cancelled gate into success. The release-main
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
It exercises new-name fallback, priority, discovery, exact filtering, real
shards, comparison with an unsplit coverage profile, standard Go coverage tools,
failure gates, failed reruns, corrupted/missing evidence and bundle isolation.
The quality job discovers it through `make test-automation`. When local tests
are authorized, use a focused automation selection while iterating:

```sh
python3 -m unittest discover -s assets/scripts/tests -p 'ci_shards_test.py' -v
```

Run `make test-automation` when validating the complete changed Make/tested
lifecycle. Static syntax and metadata checks do not establish runtime success;
when tests are deferred to GitHub, state that limitation explicitly.
