# Test surfaces and qualification evidence

Read the sections matching the behavior being changed. These are existing test
surfaces and their limits; names alone do not establish coverage for a new change.
Source and fixture paths below are relative to the repository root.

## Contents

- Conditional authentication coverage
- Shared test mechanics: CodeQL and subprocess coverage
- Feature suites and Caddyfile adaptation/runtime resolution

## Caddy v2.11.7 compatibility

`TestCaddyfileOAuthApplicationQuotedBraces` and
`TestPortalQuotedBraceArguments` preserve literal opening/closing brace values,
following declarations, disabled settings and deferred runtime resolution.
The OAuth application fixture carries literal brace client names through
`TestCaddyOAuthApplicationsE2E` provisioning, TLS login and replacement.
Incomplete enclosing-block fixtures omit an owned closing delimiter; policy
boundary tests retain contextual errors for quoted delimiters. Do not restore
the older host parser's treatment of quoted argument values as structural braces.

The lifecycle, logging, cookie and authorization response/redirect suites cover
the existing app/plugin boundaries against this host. Caddy's new HTTP header
and idle-transfer defaults remain enabled during these checks. Official OP
conformance stays a separate opt-in workflow.

## Typed custom authorization fields

`TestAuthorizationACLFields`, `TestAuthorizationACLFieldRejects` and
`TestAuthorizationACLFieldLiteralResolution` cover typed adaptation and errors;
`TestAuthorizationACLFieldNames` covers valid identifier boundaries. Failed
policies must preserve the whole app, including deferred OAuth statements.
`TestAuthorizationACLFieldPolicyBoundaries` rejects quoted policy braces before
publication; `TestAuthorizationACLFieldImports` checks imported literals,
duplicate aliases and no inheritance from another policy. Validation diagnostics
retain their underlying error identity and source location.
`testcase_authorize_acl_fields` and its duplicate/extra-block/quoted-policy-brace
rejection fixtures join the public adapt suite. The lifecycle malformed JSON
matrix includes null fields.
`TestCaddyAuthorizationFieldsE2E` adds default-suite Caddy TLS, an actual counted
upstream, independent JWT signing, all eight guardians, cache observation,
malformed values, identity headers, concurrent isolation and native JSON reloads.
Upstream receipts are correlated per request, so unexpected grants and denials
cannot cancel in an aggregate count, even during concurrent policy checks.
Two path-claim-only guardian combinations use native JSON: Caddyfile
`validate path acl` also sets method/path validation. The test checks options
both after adaptation and after provisioning to establish eight distinct cases.
It also checks imported declarations, adaptation failure before startup/reload
(including quoted enclosing policy braces), and source-address
enforcement when one cached token arrives from different trusted client addresses.
Keep its default-rule ordering regression visible: selected v1.3.11 evaluates
unconditional rules over normalized users without `exp`, so a default deny
overrides a compact non-stopping allow. See
[typed ACL fields](../../configuration-authorization/references/typed-acl-fields.md)
for both ordering assertions and malformed-claim denial.

## Conditional authentication coverage

`TestPortalTransformSharedParser`, `TestPortalTransformRejects`, the transform
runtime tests, and local-store parser tests cover v1.3.3 grammar and rejection
boundaries. The `testcase_authenticate_with_challenges` pair exercises adapted
JSON and runtime resolution, including mixed environment/claim templates.
`TestCaddyAuthenticationChallengesE2E` runs isolated actual Caddy TLS journeys
for HTML/JSON and native conditional login, signed WebAuthn, AMR claims and
resource authorization, portal refresh/OIDC, Basic/API-key rejection, policy failure,
static-user creation/replacement/omission and profile rule mutations.
`TestPortalTransformMatchAnyIdentityContext` checks unconditional matching
without timestamps in the selected v1.3.11 library. Its resolution fixtures and
TLS E2E qualify Caddy refresh/OIDC/System API usage. Quoted and runtime-resolved
native JSON matchers exercise the same policy and claims. System API E2E also
checks encrypted assertions and rejection of unsatisfied factor policy. Its LDAPS
peer requires real service/user binds and verifies all fallback role values.
Multiline instructions remain rejected before CSV decoding can discard a second
record; reload E2E verifies continued access through the previous runtime.
Test credentials are seeded before Caddy owns the database; runtime profile
mutations cross HTTP. Changed local-store configuration restarts explicitly,
respecting the existing prohibition on overlapping file-backed runtimes.

## Argon2 passwords

`password_import_test.go` and `testcase_authenticate_with_argon2` cover exact
quoted values, adapt-time and runtime environment replacement, native JSON,
and malformed Argon2/bcrypt provisioning with redacted diagnostics and no stored
user. `command_password_argon2_test.go` covers shared generation options,
exact algorithm names (including trailing tabs/Unicode spaces), random salts,
long plaintext, invalid settings, private inputs, independent
password policy and write failures.

`TestCaddyPasswordArgon2E2E` builds `cmd/authcrunch` and starts isolated, bounded
Caddy processes with verified TLS and temporary identity files. It covers
CLI-generated Argon2 and bcrypt HTML/native/Basic login, independently verified
JWTs and protected routes, wrong/missing/serialized-hash rejection, raw reserved
prefix plaintext login, restart/history/overwrite semantics, public profile
imports and refresh preservation/revocation, and public registration imports
with a local file-message positive control. Rate limiting remains enabled;
independent protocol fixtures and successful controls avoid masked failures.
Log redaction checks include rejected password attempts, serialized imports,
native sandbox secrets and Basic credentials. Shutdown uses Caddy's local admin
endpoint and waits for process exit; exceeding its graceful deadline fails the
test even if forced termination succeeds. Each waiter captures its own process
and completion channel, independent of later fixture restarts. The new
binary is not the instrumented Go test helper; its code does not contribute to
parent coverage. Unit and existing instrumented command tests cover the host code.

Run the focused `TestPasswordImport|TestSecurityCredentialArgon2|TestCaddyPasswordArgon2E2E`
selection, then `make ci-check`. See
[password hashing](../../configuration-users/references/password-hashing.md)
for the supported formats and security boundary. Algorithm vectors and padded
work counts remain the library's responsibility; no wall-clock equivalence is
asserted here. Registration confirmation/approval and live SMTP remain separate.

## Authorization login redirects

`TestAuthzRedirectRequestTargets` tests both redirect renderers through the Caddy
authorization handler, including origin-form, absolute-form and quic-go's
absolute-URL/origin-target representation. JavaScript runs in Node rather than
being inferred from template strings. Requests must remain unchanged and a
handled redirect must never call the protected handler.

The Go harness parses redirect HTML with `golang.org/x/net/html` and passes
exactly one inline script to Node. Keep HTML extraction out of regular
expressions. `TestAuthorizationRedirectScriptHTML` covers tag casing,
attributes, permissive closing tags, comment/textarea decoys and literal script
text; `TestAuthorizationRedirectScriptRejectsUnexpectedPrograms` rejects missing,
multiple or external scripts before execution.

`TestCaddyAuthorizationRedirectE2E` runs a bounded real Caddy subprocess with
separate TLS app/portal hostnames, exact app-authority redirect trust, shared
access-cookie scope and signing/verification material. Each HTTP version runs
HEAD and GET probes and cookie-preserving local password and synthetic OAuth
callback journeys for root, nested, escaped/raw-query, authority-looking and
empty-query targets. Only a completed login may reach the protected resource.
It checks custom/disabled redirect queries, configured status, untrusted return
destinations, and a TLS proxy before/after Caddy proxy trust is configured.
Forwarded host/proto use Caddy's last-field rule; independent port/prefix hints
cannot change the returned origin or mount.

The HTTP/3 client uses UDP/QUIC with no TCP fallback and verifies both client
and Caddy protocol evidence. Chrome independently completes local, OAuth and
JavaScript-fragment journeys over each protocol, using private certificate
trust and rejecting an untrusted certificate and a wrong hostname first.
Missing Chrome/Node or failed HTTP/3 negotiation fails the suite. Do not call
HTTP/2 fallback HTTP/3 coverage; inspect `curl --version` before using manual
`--http3-only` probes. The synthetic provider itself uses verified HTTP/1.1;
the selected protocol is asserted on all app and portal exchanges.

The Chrome driver retries only read-only DOM observations that lose their
execution context during navigation. Retry only recognized `Runtime.evaluate`
context-unavailable errors, within the original polling deadline. Login/form
actions are issued once; DOM exceptions, closed targets, command timeouts and
unrelated protocol errors must still fail. Diagnostics identify the command,
code and journey phase without printing evaluated expressions, arguments or
raw protocol error data.
`TestAuthorizationRedirectBrowserPolling` runs the Node unit cases in the
default Go suite. The real browser journey also navigates while a read is pending,
requires actual context destruction, and observes the replacement page before
continuing the unchanged TLS, login, redirect and protocol assertions.

Repeat the isolated `TestCaddyAuthorizationRedirectE2E` parent when investigating
intermittent failures. Repeating its process helper in one Go process can carry
Caddy's global TLS/runtime state between runs and is not equivalent evidence.

Run `make qtest TEST='TestAuthzRedirectRequestTargets|TestAuthorizationRedirectBrowserPolling|TestCaddyAuthorizationRedirectE2E'`
for race-enabled regression reports, then the normal `make ci-check` gate.

## Shared test mechanics

Automation fixtures must create their own generated parent directories before
calling `TemporaryDirectory` or `mkdtemp`. A fresh checkout has no ignored
`tmp/` directory; another test must not be responsible for creating it. When
fixing fixture setup, run the affected test alone in a disposable checkout
without `tmp/`, then run `make test-automation`. Preserve existing workspaces
and report bundles while checking this condition.

### CodeQL scanning

The separate `.github/workflows/codeql.yml` analyzes Go, JavaScript/TypeScript,
Python and Actions with the complete default suites. Local `make scan-codeql`
uses the same checked-in configuration; `CODEQL_LANGUAGE` defaults to `go`.
`.github/codeql/suppressions.json` records the five owner-approved findings.
The shared SARIF filter matches exact rules, paths and CodeQL fingerprints,
preserving raw evidence and an audit. No sibling logging exception applies
automatically. Follow the [CodeQL workflow](../../scripts-and-automation/references/codeql.md)
for tool selection, output boundaries, report review and GitHub activation.

`assets/scripts/tests/codeql_test.py` exercises the actual shell helper with a
fake CLI to verify stage failure propagation, per-language build selection,
source-root isolation, quoted paths, fresh evidence and rejected output escapes.
It runs in `make test-automation`, alongside `codeql_filter_test.py`, which
checks approval matching, negative boundaries, retained CSV results, audit
identity, failed-analysis refusal and evidence preservation. `make test-codeql`
runs the real CLI against isolated sources under `.coverage/codeql/`. It
compares raw default results to the unmodified upstream suite, then verifies
approved suppressions and retained neighboring findings in both default and
extended suites. The actual Python and CommonJS test harnesses are copied as
static fixture inputs; they are not executed. Go cases retain debug/ordinary
sensitive logging, SQL injection and other password hashes. JavaScript, Python
and Actions retain code injection, and Actions retains an unpinned-action case.

Run automation tests and real fixtures for all four languages when changing
shared scanning behavior. CLI absence is a failure, not a skipped test. The
CodeQL matrix verifies its own language and applies the shared filter before
uploading reviewed primary SARIF; raw results and suppression audits are
retained as artifacts even after failure. `make ci-check` keeps its existing tool
requirements and does not invoke CodeQL. A successful scan can contain alerts;
do not describe a successful scanner invocation as a vulnerability-free result.

### Subprocess coverage

`subprocess_coverage_test.go` owns the root package's `TestMain`. When Go enables
coverage, it connects inherited `GOCOVERDIR` to `-test.gocoverdir`.
`collectSubprocessCoverage(t, cmd)` assigns each child a private temporary
directory and collects its completed files during parent test cleanup, before
Go's native profile writer merges counters from the parent and descendants
running the same instrumented test executable,
including nested E2E helpers and CLI helpers that exit through `os.Exit`.
Call the collector after setting `cmd.Env` and before starting every copy of the
test executable, including PTY brokers that launch it. Always wait for the child
before returning from its parent test. Cleanup publishes files atomically on
the destination filesystem, so parallel children cannot race Go's metadata
writes. Do not share a writable coverage directory between children or forward
the parent's `-test.coverprofile` flag. Preserve process deadlines, exit status
checks and isolation; never reuse a persistent counter directory across runs.

This applies automatically to `go test -coverprofile=...`, `make test` and
`make qtest`. The merged profile reaches tested before its coverage threshold,
HTML/JSON/JUnit generation and manifest creation; `make run-reports` reuses that
profile. There is no report rewrite or extra postprocessing step. Ordinary
`go test` without coverage is unchanged. The `Test*Process` entries still skip
in normal discovery because their parent tests run them in isolated processes;
keep these truthful skip outcomes visible.

Coverage is limited to the selected instrumented packages and executable.
Separately built CLI binaries are not instrumented by this hook. Killed or
panicking processes can lose unflushed counters; do not alter interruption tests
or suppress their failures to obtain coverage. Official OIDC conformance remains
separate and opt-in.

`TestConfigureSubprocessCoverage` covers flag/environment precedence and inactive
coverage. `TestCollectCoverageFiles` verifies concurrent publication, partial-file
exclusion and collection failures. The automation test
`assets/scripts/tests/subprocess_coverage_test.py` copies the actual bootstrap
into a disposable module under `tmp/` and checks exact parent, parallel
child, grandchild and CLI counters through Go and Make/tested. It also checks
failed-child evidence, coverage thresholds, untouched code, set/count/atomic
modes, fresh filtered runs, custom paths and quick/report regeneration. Run it
with `make test-automation`, then use the real Caddy E2E report to validate the
integrated change.

### Feature suites

`TestCaddyLoggingE2E` builds the actual race-enabled Caddy command, captures JSON
logs and qualifies diagnostic rules through real TLS login, legacy/current
authorization, counted protected handlers, replacements/removal, independent
processes and persistent-session restarts. It explicitly proves that the private
Caddy authentication middleware logger remains unfiltered in v2.11.7; a passing
suite is not an issue #280 host-suppression fix. See
[logging validation](../../configuration-logging/SKILL.md#validation) for focused
unit/adaptation coverage and the upstream acceptance criteria.

`TestCaddyRuntimeStateE2E` builds a real Caddy executable with production modules
and an isolated TLS-root fixture. It tests SIGKILL/restart at the same origin,
direct OAuth without a portal, sessions/JWKS, refresh/OIDC replay, identity
rollback, storage failures, actual snapshot capacity and controlled reload
rejection under in-flight callbacks and protected traffic. Read
[configuration-state](../../configuration-state/SKILL.md#validation) for its scope
and focused unit/adaptation companions. Never substitute upstream library tests
or a reload-only test for process restart evidence.

`TestCaddyOperatorExamplesE2E` qualifies every complete input under
`assets/config/integration/` through Caddy adaptation, validation, provisioning
and TLS journeys, then reloads generated native JSON independently. The
[operator example reference](../../configuration/references/operator-examples.md)
describes private artifact retention and the exact scenario coverage. Keep
those examples in the default gate and test their behavior, not just JSON shape.

Official OP conformance runs only through `make oidc-conformance-test`, with its
own private artifacts. The harness and its unit tests are excluded from regular
Go tests, `make test-automation`, and `make ci-check`. Existing local OIDC
regressions stay in regular testing. The official runner's original nonzero
outcome remains a failure; warnings, skips and reviews are never an all-pass claim.
See [official OP conformance](../../configuration-oauth-applications/references/oidc-conformance.md)
for prerequisites, isolated artifacts and all remaining non-pass modules.
The separate `OIDC conformance` GitHub workflow is manual-only and invokes these
same Make targets. Follow [conformance Actions](../../configuration-oauth-applications/references/oidc-conformance-actions.md)
for the report artifact and failure-preserving upload. The workflow publishes
the complete disposable test evidence directly in its artifact ZIP, retaining
signed exports and hashes. Unzip once and open `index.html`; no nested archive,
encryption key or recipient is needed. Keep its inputs
synthetic and conformance separate from regular CI.
OIDC conformance units live in `assets/scripts/oidc_certification_conformance_tests/`
and use `test_oidc_conformance_*.py` filenames. Keep them out of the regular
automation discovery directory. The browser suite tests real pinned Chrome
startup with long evidence paths and strict TLS controls; it checks the Linux
Unix-socket path budget even when validation runs on macOS. It also forces a
real oversized PNG and verifies bounded viewport recapture, original evidence
preservation and window restoration. Follow the
[Chrome temporary-path guidance](../../configuration-oauth-applications/references/oidc-conformance-actions.md#execution-and-failure-behavior)
when changing ChromeDriver's environment or report layout.
`test_oidc_conformance_cleanup.py` exercises
deletion boundaries for bundles and supplemental logs/audits/browser profiles,
retention of custom dependencies across repeated cleanup, active-run guards and
the real Make cleanup recipe in a disposable repository. Never delete
historical official evidence as a unit-test
side effect. `make oidc-conformance-cleanup` is an explicit artifact-deletion
target; it preserves tools, the suite and caches for the next opt-in run.
The default `TestCaddyOIDCRelyingPartyE2E` also covers v1.2.6 claims, ACR,
registered RS256 Request Objects and OIDC refresh rotation/replay through real
Caddy TLS. Its discovery expectations track the selected dependency's capability surface;
these local tests do not launch the official suite.
The same RP E2E preserves the provider-owned themed page headers at root and
nested issuer mounts. It checks the consent referrer/CSP restrictions, unchanged
discovery/callback headers, and rejection of null/cross-origin and forged-CSRF
consent submissions. The official workflow additionally exercises the real
Chrome form Origin, both authentications, and the exact screenshot evidence slots.
`CONFORMANCE_RESULTS` selects a new private destination under this checkout's
`tmp/`; its `index.html` links and explains the full evidence, including blocked
or incomplete runs. Report tests are part of the same opt-in target only.

MFA E2E fixtures use independent identities/databases for separate successful
login journeys. Repeated CLI logins for the same account wait for an unused
real TOTP time step; never clear persisted replay counters or disable MFA to
reuse a code. The authentication-client E2E also rejects TOTP replay through
username-case and email aliases.

HTTPS delegation unit fixtures must model inbound requests: use
`httptest.NewRequest` with an HTTPS target and an origin-form `RequestURI`.
An outbound `http.NewRequest` has no server TLS state; an absolute-form test
target also differs from the ordinary Caddy request. Both can fail upstream
Origin validation before the authentication condition under test. The shared
refresh HTTP matrix checks unauthenticated protected routes and cross-origin
API rejection through unit delegation and actual Caddy TLS.

For cross-feature changes, use the
[composed qualification map](composition-qualification.md).
`TestCaddyCompositionE2E` covers the actual Caddy TLS feature matrix, edge trust,
credential-purpose isolation, replacement failure/recovery, current roles,
reload/disposal and combined Chromium flow. Run it with the existing browser
refresh suite under race detection; preserve its bounded single-process scope.
Include `TestAuthzSourceTrust` for cached source-bound authorization and
`TestCaddyRefreshBrowserTrust` for the fresh-profile trust boundary. Browser
journeys must reject untrusted certificates and hostname mismatches before
testing login; do not replace these controls with certificate-error allowances.

`TestSecurityAuthcrunchVersion` and `TestSecurityVersionCommand` cover embedded
dependency versions, replacements, missing metadata, command dispatch and output
failures. `TestCaddySecurityVersionE2E` compiles the real Caddy wrapper with
trimpath and stripped symbols, compares `security version` with Go's selected
dependency, and runs outside the checkout without Go on PATH or user-state writes.
Run these and the `TestSecurityCommand*`/`TestCaddySecurityCommand*` registration,
help and redacted-error tests when changing `security version`.

`cmd/caddy-authenticator/*_test.go` covers profile/configuration parsing, command
selection, private persistence, logging and transport/input failure behavior.
`TestCaddyAuthenticatorE2E` builds the standalone command and checks password,
MFA, API keys, native metadata, independent authorization and profile isolation
through actual Caddy TLS with admin/profile APIs disabled. On Unix it also runs
the Python 3 PTY broker for pasted setup, hidden input and terminal restoration
at password and TOTP prompts. Regressions cover symlink-sensitive CA paths,
explicit empty home overrides and state preservation when logging rejects an
operation. Unit tests verify the 45s default and overridden command deadlines;
PTY tests verify non-interactive defaults and `--interactive` prompt opt-in.
`TestCaddyAuthenticatorVersionE2E` verifies actual Go install naming, fallback
version and linker metadata without user-state access. Automation fixtures
check Make builds, failure propagation and fallback synchronization. Run these
along with cached-token/expiry/forced-login and native-refresh tests, including
lost committed responses and prevention of replay across commands,
when changing the standalone CLI or the authclient dependency; see the
[command validation map](../../scripts-and-automation/references/caddy-authenticator.md#validation).

`TestAuthzPathDelegation` and `TestCaddyAuthorizationPathE2E` cover the v1.2.5
authorization path contract through the provider and real Caddy TLS. Run them
when changing gatekeeper delegation, bypasses, path claims or the selected
dependency. They check decoded/cleaned paths before and after identity caching,
literal wildcard grants, downstream reachability and unchanged request URIs
over HTTP/1.1 and HTTP/2; see
[authorization behavior](../../configuration-authorization/SKILL.md#policy-options).

`TestAuthenticationClientConfigAdapter` covers the existing outbound YAML adapter
and the dedicated public authclient parser. `TestAuthenticationClientConfigWhitespace`
checks exact credential preservation and prevents silently repaired options;
`TestAuthenticationClientLegacyWire`
checks omission of the refresh extension with a strict legacy schema.
`TestAuthnJSONLoginDelegation` compares native/JSON rejection responses with
direct portal dispatch, checking request headers/URL and response metadata at
root/nested mounts. Its error cases also run through Caddy TLS.
`TestCaddyAuthenticationClientE2E` covers password/MFA and API-key JSON login
through actual Caddy TLS with admin/profile APIs disabled, private credential
reopening, independent resource authorization, explicit native refresh/logout,
and the existing CLI consumer. It includes in-flight HTTP cancellation with
server request counts, cookie-mode MFA metadata-only completion, dropped native
transport at checkpoints, and rejected browser/native mixtures without consuming
the refresh family. See the
[native interoperability test map](../../authentication-portal-api/references/native-client.md#caddy-validation).

Local identity provisioning/reset units are in `local_identity_test.go`.
`profile_public_key_test.go` checks public parser metadata and binary rejection.
`TestCaddyLocalIdentityE2E` covers TLS login identity/realm/MFA combinations,
management/profile credential mutations, reload invalidation, stateless access,
and persisted user public keys. See
[local identity compatibility](../../configuration-identity-stores/references/local-identity.md#caddy-validation).
The default `TestCaddyProfileCanonicalIdentityRegression` verifies transformed
claims cannot select another local account after the upstream fix; see
[profile isolation](../../authentication-portal-api/references/profile-public-keys.md#canonical-profile-identity-regression).

Runtime ownership unit tests live in `app_lifecycle_test.go`.
`TestCaddyLifecycleE2E` in `app_lifecycle_e2e_test.go` launches a bounded child
process with real Caddy listeners and reloads; `TestCaddyLifecycleProcess` is
its subprocess helper. Use these for app/plugin lifecycle changes, including
drain ordering, abandoned candidates, shared providers, and worker disposal.
Read the [runtime lifecycle reference](../../coding-directives/references/runtime-lifecycle.md#validation)
for the precise scenarios and host limitations.

Parser tests use inline Caddyfile snippets and `caddyfile.NewTestDispenser`.
They call parser functions, unpack generated JSON into maps, and compare with
`cmp.Diff`. Whitespace in inline `want` JSON is not semantically important.
Add or update these tests when directive parsing behavior changes:

- `caddyfile_authn_test.go`: authentication portal parsing.
- `caddyfile_authn_oidc_test.go`: provider grammar, forward/imported application
  references, disabled validation, and JSON restoration. `oidc_config_test.go`
  covers conflicts across portal issuers. `TestCaddyOIDCProviderE2E` in
  `oidc_e2e_test.go` covers actual TLS provisioning, discovery, two selected local
  realms and an unselected realm, realm identity and session revocation when
  switching realms in one browser, independent issuers/cookies, signed token
  exchanges, refresh alignment, and continued service after rejected reloads.
- `plugin_authn_test.go`: `TestAuthnOIDCDelegation` compares the middleware's
  response and canonical URL with direct portal dispatch. `oidc_rp_test.go`
  checks the independent RSA relying-party verifier against corrupted signatures,
  claims and public key sets. `oidc_rp_response_test.go` checks the RP's callback
  and form parsing against ambiguous parameters, incorrect POST forms and
  weakened CSP; the E2E client submits the returned consent action and controls.
- `TestCaddyOIDCRelyingPartyE2E`: bounded real Caddy TLS at root/nested mounts,
  discovery, password/TOTP, consent, client authentication, prompts/max_age,
  code+S256, form-post CSP, UserInfo, replay, revocation/logout, token purposes,
  CORS and unsigned request objects. `oidc_loopback_e2e_test.go` is exercised
  by this parent and requires actual IPv4/IPv6 ephemeral callback listeners.
  `TestCaddyRegistrationE2E` covers process restart at the same issuer URL,
  stable client/key identity, secret rotation and retained rollover verification.
  Use the [OIDC validation map](../../configuration-oauth-applications/references/oidc-provider.md#validation-surfaces)
  for the full test group and limits; local E2E is not Foundation certification.
- `caddyfile_authn_token_refresh_test.go`: complete readable refresh grammar,
  opt-out/defaults, imports/duplicates, placeholders and native/deferred JSON.
  `TestCaddyTokenRefreshE2E` verifies real TLS password login and rotation at
  parsed root/nested mounts, realm participation, cookie overrides, lifetime
  caps, native opt-in/off, capacity/replay/rotation limits and rejected mounts.
  Its adaptation/resolution fixture is `testcase_authenticate_with_token_refresh`.
  See [portal refresh](../../configuration-authentication/references/token-refresh.md#validation).
- `TestAuthnTokenRefreshDelegation` covers strict HTTP dispatch, protected APIs,
  the exact embedded refresh asset and continuation pages. The normal Go suite
  also runs `TestCaddyTokenRefreshBrowserE2E` with real Chrome/Chromium and Node 24;
  `TestCaddyRefreshBrowserStartup` covers process readiness/cleanup failures.
  See [browser validation](../../authentication-portal-api/references/browser-refresh.md#validation-in-this-repository)
  for two-tab coordination, committed-response loss and prerequisite overrides.
- `caddyfile_authn_misc_test.go`: authentication misc/cookie/crypto/UI paths.
- `caddyfile_authz_test.go`: authorization policy parsing.
- `caddyfile_identity*_test.go`: identity stores and providers.
- `caddyfile_credentials_test.go`: credential directives.
- `caddyfile_messaging_test.go`: messaging directives.
- `caddyfile_sso_provider_test.go`: SSO provider directives.
- `caddyfile_test.go`: app-level parse coverage.

Adapt tests live in `TestCaddyfileAdaptAuthenticationToJSON` in
`caddyfile_adapt_test.go`. Each case uses
`testdata/caddyfile_adapt/<prefix>.Caddyfile` as input and compares against
`<prefix>.json`. Optional `<prefix>.env` files provide environment variables;
blank lines and comments are ignored, and variables are cleaned up by the test.
Use this path for every Caddyfile directive change, including syntax, defaults,
validation, and config mapping.

Runtime resolution tests live in `TestResolveRuntimeAppConfig` in
`caddyfile_resolve_test.go`. Each case reads `<prefix>.json`, extracts the
`security.config` object, runs `ResolveRuntimeAppConfig`, and compares against
`<prefix>_resolved.json`. The test also fails if unresolved `{env...}` tokens
remain. It writes temporary `*_tmp_input.json` and `*_tmp_output.json` files,
removing them on success and leaving them on failure for debugging.

Expected-error tests set `shouldErr: true` and compare the exact error string
with `cmp.Diff`. Keep expected errors specific. The static secrets manager
fixture currently expects a module-not-registered error because the external
secrets plugin is not registered in this test binary.

## Direct OAuth policies

`TestCaddyDirectOAuthE2E` builds the production Caddy command with a private CA
fixture, runs without a portal, and restores adapted Caddy JSON. A counted TLS
upstream proves handled redirects/callbacks/denials/logout never reach the app or
append `handle_errors` pages. Generic OIDC keeps nonce and S256 enabled and signs
assertions independently. The suite includes a real Chrome cookie journey,
policy ACL/source checks, wrong-origin/browser transplants, replays, provider
failures, capacity, absolute expiry, logout during exchange and volatile reload.
See the [direct OAuth acceptance surface](../../configuration-authorization/references/direct-oauth.md#consumer-validation)
for parser fixtures, admission/draining units and protocol scope. Separate
built commands are outside parent instrumentation. Existing portal, Basic,
API-key and remote-authenticator regressions remain in the normal full suite.
