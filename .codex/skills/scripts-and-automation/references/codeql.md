# CodeQL scans and findings review

## Configuration and ownership

`.github/workflows/codeql.yml` follows go-authcrunch's advanced workflow:
immutable action revisions, explicit Go setup/build, per-language analysis,
regression verification before SARIF upload, and manual dispatch alongside
main-branch push, pull request and weekly runs. This repository analyzes Go,
JavaScript/TypeScript, Python and GitHub Actions. JavaScript includes the
CommonJS (`.cjs`) browser E2E harness and HTML assets; inventory `.cjs`/`.mjs`
and HTML as well as `.js`/`.ts` before deciding which languages apply.
JavaScript embedded in Go/Python strings is not a separate scanned program.

All four languages load `.github/codeql/codeql-config.yml`. Every default query
remains enabled. `assets/scripts/filter_codeql_results.py` applies the reviewed
policy in `.github/codeql/suppressions.json` after analysis, both locally and
before CI uploads. The original SARIF/CSV and an audit remain available. No
query is disabled, no source is sanitized, and no sibling logging exception
applies automatically.

## Approved findings

The owner approved these exceptions in the initial findings review:

| Review ID | Exact rule and file | Accepted rationale |
| --- | --- | --- |
| CQ-001 | `go/weak-sensitive-data-hashing`, `command_local_client.go` | Generated secret length is sufficient for this cache-identity hash. |
| CQ-002 | `py/clear-text-storage-sensitive-data`, `assets/scripts/oidc_conformance.py` | The private credentials are generated for testing. |
| CQ-004 | `js/user-controlled-bypass`, `testdata/browser/token_refresh_browser_e2e.cjs` | The Chrome event check belongs to the test harness. |
| CQ-005 | `js/file-access-to-http`, the same CommonJS file | Synthetic password delivery belongs to the local browser test. |

Each entry also requires the exact `primaryLocationLineHash` from the reviewed
SARIF. Line-number movement does not invalidate a matching fingerprint. A
changed/missing fingerprint, another rule, another file or an unknown source
base remains reportable. Do not refresh fingerprints automatically after an
alert returns; inspect the change and determine whether the accepted scope
still applies. An unmatched approval in an audit is expected when its query
is absent from the selected suite or there is no corresponding finding.

These rationales document the owner's accepted assumptions; matching a
fingerprint does not itself prove key entropy, private storage or local-only
execution. Do not generalize the approvals to all hashes, testing code,
WebSocket messages or credential storage. New findings need separate review.

CQ-003 was remediated by pinning `contributor-assistant/github-action` to
`a895a435fcce79ecf28fbce61a4ef0f0dabc9853`, verified as the upstream `v2.3.1`
commit. `actions/unpinned-tag` has no suppression. Verify an intended release's
commit in the upstream repository when updating that pin.

`paths-ignore` excludes generated working areas and downloaded tools for the
interpreted languages. It does not exclude application source, fixtures or
test directories. Go extraction follows `go build -mod=readonly ./...`;
`paths-ignore` does not restrict that traced build. This is a production build,
not a test execution or a complete analysis of every build tag/platform.
Dependencies support the database's models; this scan does not replace an
independent scan of go-authcrunch or another dependency.

## Local execution

Provide a compatible CodeQL CLI on PATH or set `CODEQL` to its absolute path.
CodeQL 2.27.0 and Go 1.26.8 were used for the initial local validation. Keep
downloaded tools under this checkout's `tmp/`; do not run sibling maintenance
or scan scripts. Python 3.9+ and Bash run the helper. Query pack downloads may
require network access and use the CLI's package cache. No module manifests
or global Go tools are changed.

```sh
CODEQL=/absolute/path/to/codeql make scan-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=javascript-typescript make scan-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=python make scan-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=actions make scan-codeql
```

The helper derives its source root from its own checkout, independent of the
caller's directory. Each invocation creates a fresh
`.coverage/codeql/<language>-scan.*` directory. `CODEQL_OUTPUT_DIR` can select
a new or empty directory strictly inside this checkout. Relative paths are
relative to the checkout. Physical resolution rejects symlinks escaping it,
including symlinks in the default output location. Existing evidence is never
overwritten; retain failed bundles and use another directory for a retry.

Each completed scan contains:

- `database/`: extracted source, query results and detailed CLI logs.
- `raw/results.sarif` and `raw/results.csv`: unmodified CLI findings.
- `results.sarif`: reviewed findings for upload, with only approved matches removed.
- `results.csv`: reviewed rows with rule, level, path, line, column and message.
- `results.suppressions.json`: input/policy hashes, counts, matched approval
  IDs, reasons, locations and unmatched approval IDs.
- `codeql-version.json`: exact CLI identity.
- `scan.log`: stage output, including failures and extraction warnings.

Analysis uses two query threads and 5922 MB, matching the sibling helper.
Default query packs are downloaded, not pinned by this repository; the Action
chooses its compatible tool bundle. The same configuration does not promise
identical pack versions across time or machines. Record the actual pack
versions from the SARIF extensions and CLI logs when reporting findings.
Review an upstream query/version change before comparing alert counts.

The script stops on the original failing stage, including through its log
pipeline, including a filtering failure. A nonzero scan or partial output is
not a clean result. A zero exit status means analysis completed, even when the
reviewed SARIF contains alerts. Always distinguish raw, suppressed and remaining
counts. Local execution never uploads results or changes GitHub alert state.

For a broader local review, reuse a completed database with an explicitly
selected suite and a separate output file. Set `scan_dir` to the completed
scan directory printed by the helper:

```sh
scan_dir=.coverage/codeql/go-scan.REPLACE_WITH_YOUR_RUN
codeql database analyze "$scan_dir/database" \
  codeql/go-queries:codeql-suites/go-security-extended.qls \
  --threads=2 --ram=5922 --format=sarif-latest \
  --output="$scan_dir/raw/security-extended.sarif"
python3 assets/scripts/filter_codeql_results.py \
  --input "$scan_dir/raw/security-extended.sarif" --output-dir "$scan_dir"
```

Use the corresponding `python`, `actions` or `javascript` pack/suite prefix for
the other databases (the CLI language name remains `javascript-typescript`).
This does not change the default CI suite. Compare results by rule and location
so repeated baseline findings are not counted twice.

The filter accepts a SARIF file or a directory of `.sarif` files via `--input`.
Its output must stay inside this checkout, including after symlink resolution;
existing evidence is never overwritten. Invalid policy, missing inputs or
unsuccessful analysis metadata fail before publication. Unknown location
representations are retained rather than guessed. CI keeps unmodified output
in `.coverage/codeql-analysis/`, filters into `.coverage/codeql-reviewed/`, and
uploads only the latter to code scanning. Both directories and the regression
bundles are retained as artifacts. This is an explicit SARIF filtering policy,
not a GitHub API dismissal or a reliance on source suppression comments.

## Regression validation

```sh
make test-automation
CODEQL=/absolute/path/to/codeql make test-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=javascript-typescript make test-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=python make test-codeql
CODEQL=/absolute/path/to/codeql CODEQL_LANGUAGE=actions make test-codeql
```

The fake-CLI automation verifies shell/filter failure propagation and output
isolation. Filter unit/CLI tests exercise exact matching, moved lines, changed
fingerprints, neighboring rules/files, unknown bases, absent fingerprints,
multiple locations, CSV/audit consistency and overwrite/escape rejection.
`.github/codeql/test_scan.py` adds real extraction, default/extended query
execution and SARIF verification. Go fixtures use the repository's Go/Zap
versions, the actual approved cache expression, an unapproved neighboring
file and another password hash in the approved file. Python and JavaScript
fixtures copy the actual approved harnesses as static inputs and retain
equivalent findings in neighboring files. Python also retains a different
password write in the approved file. These harnesses, Express/Flask fixtures
and synthetic Actions workflows are never executed or deployed.

The fixture first compares raw default rule IDs and alert locations against
the complete upstream suite on the same database. It then verifies only the
approved matches disappear, all rule descriptors survive, and known negative
cases remain in both default and extended scans. Go logging at every tested
level and SQL injection remain visible; all other languages retain code
injection, and Actions retains an unpinned-action finding. A missing CLI,
missing suppression/retained case, changed rule coverage or unsuccessful
analysis fails the regression.

Fixture sources, logs, SARIF and databases stay in
`.coverage/codeql/<language>-e2e-*`, including on failure. Each CI language job
verifies its fixture after primary analysis and before uploading the primary
SARIF to code scanning. Synthetic regression alerts are only retained as
artifacts; they are never uploaded as repository code-scanning alerts. The
artifact upload runs after attempted analysis even when validation fails and
retains evidence for 14 days. CodeQL remains separate from `make ci-check`.

When the user approves additional exceptions, preserve the unfiltered report
and update the narrow policy with positive and negative real CodeQL fixtures.
Keep every unrelated rule and sink covered. A broad rule exclusion, filename
substring match or field-name-only sanitizer can hide unrelated vulnerabilities.
Source annotations alone do not establish that hosted alerts were suppressed.

## Reporting and GitHub activation

Create investigation reports inside the scan bundle, not as canonical source
documentation. Include source revision and working-tree state, tool and pack
versions, language/suite coverage, completion status, extraction limitations,
and links to the original SARIF/CSV/logs. Give every result a review identifier,
rule/severity, source location, dataflow evidence where present, concrete
exposure conditions, and a recommended next action. Distinguish observed
static-analysis facts from reachability or exploitability assessments. Preserve
the original review report; create a follow-up disposition report for approved
suppressions and remediations. Include raw, suppressed and remaining counts,
reasons, regression evidence and the pinned action identity. Supplemental
security-extended results must be labeled separately from the default CI suite.

This checkout already contains an advanced workflow. Repository-only changes
do not activate a hosted run or dismiss existing alerts. After landing the
workflow and configuration together, verify all four language jobs and
uploaded analyses. If GitHub default setup is enabled, it must be switched
to advanced setup to use the checked-in configuration; inspect actual hosted
settings before changing anything. See GitHub's
[advanced setup instructions](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configuring-advanced-setup-for-code-scanning).
Do not disable an existing scan before its replacement is ready. Historical
alerts can have instances from other configurations; review them separately.

For CLI semantics, see
[database create](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-create)
and [workflow configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options).
