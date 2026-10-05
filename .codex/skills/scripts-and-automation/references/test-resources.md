# Test resource controls

`make test`, `run-tests`, `qtest`, `run-quick-tests` and `run-reports` invoke
`assets/scripts/test_guard.py` around pinned tested. Python 3.9+, `ps`, and
macOS or Linux are required. The guard includes the tool build, Go compiler,
tests, browser/CLI subprocesses and report generation. It never terminates
VS Code or other unrelated applications.

| Setting | Default | Scope |
| --- | --- | --- |
| `TEST_PACKAGE_PARALLELISM` | `1` | Go package builds/tests; inherited by nested Go commands through `GOFLAGS` |
| `TEST_PARALLELISM` | `2` | Go tests using `t.Parallel` |
| `TEST_GOMAXPROCS` | `2` | Go execution threads per process |
| `TEST_GO_MEMORY_MB` | `512` | Go's soft memory target per process, in MiB |
| `TEST_MEMORY_MB` | smaller of `3072` and three-eighths of physical RAM | Aggregate sampled test process memory, in MiB |
| `TEST_WALL_TIMEOUT` | `4200` | Entire workflow duration in seconds, including build/report phases |
| `TEST_MAX_PROCESSES` | `128` | Observed processes in the owned tree |
| `TEST_ARTIFACT_MB` | `256` | Regular files directly inside the selected output directory, in MiB |
| `TEST_TIMEOUT` | `60m` | Existing Go timeout per package |

All numeric guard settings must be positive integers; zero never disables a
guard. `TEST_MEMORY_MB` may not exceed half of physical RAM. Make arguments
override environment values and survive recursive quick runs. The guard sets
`GOMAXPROCS` and `GOMEMLIMIT` from its `TEST_` settings; use those settings rather
than relying on unrelated inherited Go environment values. Race detection,
uncached execution, test selection and tested's authoritative exit status remain
enabled. On an 8 GiB host the default aggregate budget is 3 GiB, leaving 5 GiB
outside the test budget. Smaller hosts can legitimately refuse large fixtures.

The full suite runs Caddy journeys sequentially; cross-device expiration alone
waits five minutes. Keep the 60-minute package budget inside the 70-minute guard
budget and the 75-minute CI job budget, leaving time for compilation, reports,
setup, builds and uploads. Individual E2E subprocess deadlines remain shorter.
For browser scenarios, dispose completed contexts before opening unrelated
devices; Chrome retains renderer and window processes while contexts stay live.
Check the resource evidence with the unchanged memory limit after such changes.

Authentication E2E requires a stable wall clock. Host suspension or clock changes
can expire a login proof, cookie or token while monotonic test/guard durations
show little elapsed time. Compare `run.json` start/end timestamps with
`duration_ns` and inspect the failing request timestamps before diagnosing a
timeout regression. Preserve the failed bundle and rerun after stabilizing the
host; do not relax expiry checks or automatically retry a failed assertion.
On macOS with AC power, `caffeinate -is make test` holds temporary idle and
system-sleep assertions for the command's lifetime. The `-s` assertion only
applies on AC power; an idle-only assertion can still allow a return to deep idle
after a maintenance wake. Check `pmset -g assertions` when sleep continues.
These assertions do not change persistent power settings or prevent clock
adjustments or forced sleep.

## Monitoring and cleanup

The guard samples every 200 ms. macOS accounting takes the larger of RSS and
physical footprint, including compressed memory; Linux accounting adds swap to
RSS. Shared pages may be counted multiple times. Once per second it checks host
pressure: macOS critical pressure stops the tests, as does Linux available RAM
below the larger of 256 MiB and ten percent of total RAM. Pressure is checked
before launch too. Failures to monitor stop work rather than silently continuing.
Preflight failures record an aborted attempt before launching a tool, invalidating any
older success record for offline reporting.
Process exit during a sample is expected: Linux `/proc/<pid>/status` can raise
`ENOENT` or `ESRCH` after the `ps` snapshot, including if the process exits between
opening and reading the file. Both contribute zero memory for that process;
permission, I/O and malformed accounting errors still stop the workflow.

The supervisor follows parent/child relationships and remembers process start
times, including observed children that create another process group/session
or become reparented. Budget violations, a disappearing launcher, and
SIGINT/SIGTERM/SIGHUP freeze and kill owned work, returning nonzero status.
Cleanup also removes observed leftover children after normal completion. Do not use an address-space ulimit
for Go race binaries: their virtual mappings differ greatly from committed RAM.

These are sampled safeguards, not kernel-enforced memory isolation. Brief
overshoots, descendants that daemonize between samples, killing the supervisor
with SIGKILL, or unrelated editor/agent allocations cannot be fully contained.
Linux container/cgroup quotas are not detected; this workflow targets local
macOS/Linux hosts and the CI runner. Strict isolation requires an appropriately
limited VM or container. Do not claim an arbitrary application can never exhaust
the machine because this wrapper is enabled.

Only one guarded workflow can hold `.coverage/test-resource.lock` in a checkout,
even when output directories differ. The OS releases the advisory lock after
exit; an existing file alone is not a stale lock. Do not delete the lock or run
`make clean` during validation. Separate checkouts and direct unguarded commands
do not share this lock. Agents must serialize other expensive work too.

## Output and evidence

The guard prints elapsed time, current aggregate memory and process count every
10 seconds, including during compilation and report generation. Pinned tested
v1.1.0 also streams test activity and bounded log previews, identifies reporting
stages, and prints a heartbeat during quiet work. Keep its default live output
enabled; `--quiet` and `--format json` suppress it. Forwarded child output has a
256 KiB per-second burst limit, with a fresh allowance each second; there is no
lifetime console cutoff. A burst that exceeds the allowance emits a notice and
later forwarded output resumes automatically. Tested itself caps detailed live
previews at 4 MiB per run while retaining stages, heartbeats and the final
summary. Guard heartbeats bypass the burst allowance and continue every ten
seconds. Writes remain nonblocking: a slow or disconnected terminal may drop
presentation bytes rather than block resource checks or
workflow completion. This includes the startup banner, stderr diagnostics and
final summary: an already-full pipe must not prevent launch, cleanup or lock
release. Diagnostics use unbuffered best-effort writes and restore the caller's
descriptor mode; they must not leave a buffered write for interpreter shutdown.
Resource evidence is still written when the terminal cannot display it. A caller
such as Make can block on its own output before or after running the guard;
the guard cannot control that caller. Full Go output remains in
tested's raw evidence until an artifact or other resource budget is reached.

`resource-usage.json` records execution status, budget, peak memory/process
counts, recent largest process IDs, elapsed time and stop reason.
`console_dropped_bytes` counts child-output bytes omitted by throttling or a
blocked terminal; the guard reports that count at completion. Reporting uses
`resource-report-usage.json`. These files supplement tested's evidence; a killed
run can lack `run.json` or a completed manifest. Offline reporting refuses a
previous `running` or `aborted` guard record, including a supervisor interrupted
before finalization. Keep the evidence and rerun into a fresh output directory.
An ordinary test/build/coverage failure remains a failure in live and offline
reports. The guard does not remove unrelated files or other report bundles.
Artifact limits are checked before launch, during sampling and after tool exit
so a short-lived producer cannot pass with an oversized final bundle. Nested quick
reports are outside the direct-file artifact budget. Disappearing files during
report replacement are tolerated; other filesystem errors still abort.

For investigation, start with a selected package/test under `make test`. For a
narrow command outside the report lifecycle, retain the same guard:

```sh
COVERAGE_DIR=.coverage/debug python3 assets/scripts/test_guard.py run go test -race -count=1 . -run '^TestAuthzResponseContract$'
```

Check active processes and the recorded peak before changing any budget. A
capacity fixture may serialize many large snapshots; a package's elapsed time
and output size alone do not reveal its memory demand. The macOS Force Quit
application grouping does not establish which test, editor extension or agent
caused a historical spike. Preserve the original incident evidence.

Caddy's main E2E journeys already use bounded subprocesses or standalone Caddy
binaries. Preserve their isolation, race instrumentation and failure propagation.
Use the existing [subprocess coverage contract](../../testing-and-ci/references/test-surfaces.md#subprocess-coverage)
when adding a child of the instrumented test executable: each child receives a
private counter directory, collected before the parent report is finalized.
Do not import upstream capacity helpers or run upstream tests to qualify Caddy.

Validate guard changes with `make test-automation`. Its unit tests cover resource
accounting, output throttling and process identity; Make E2E fixtures cover real
cleanup, limit overrides, interruption and lock contention. Linux proc-read
error injection verifies vanished processes on either host, while permission
and I/O failures still abort and clean up. The real tested fixture requires a
live Go test log to cross tested, the guard and Make before releasing the test,
then verifies assertion/build/timeout failures, report regeneration and bundle
isolation. The subprocess-coverage fixture checks exact descendant counters
through the guarded Make targets.

Run the real Caddy unit/E2E suite under the guard as well:

```sh
make test COVERAGE_DIR=.coverage/guard-validation
```

This includes browser refresh, persistent runtime capacity/restarts, CLI builds
and composed authentication/authorization. Synthetic resource fixtures alone do
not establish that these workflows fit the default budgets. Official OP
conformance remains opt-in and separate.
