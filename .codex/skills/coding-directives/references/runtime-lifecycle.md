# AuthCrunch runtime ownership in Caddy

Read this reference when changing security app provisioning, request ownership,
reload behavior, or disposal. Recheck the selected dependency versions and their
lifecycle ordering before changing these contracts.

The `security` app owns one `authcrunch.Server` per Caddy configuration.
`authenticate` and `authorize` borrow its portals and gatekeepers. Route modules
never dispose the server, providers, authenticators, or component caches.
`App.Cleanup` closes admission, waits for admitted AuthCrunch calls to return,
then calls `Server.Close` once. Concurrent cleanup callers wait for the same
result, including cleanup errors.

## Host lifecycle traced

This qualification uses the pinned Caddy v2.11.4 and AuthCrunch v1.3.4.
The relevant Caddy paths are
[`Context.LoadModuleByID` and context cancellation](https://github.com/caddyserver/caddy/blob/v2.11.4/context.go),
[`run`, `provisionContext`, `unsyncedDecodeAndRun`, `unsyncedStop`, and `Validate`](https://github.com/caddyserver/caddy/blob/v2.11.4/caddy.go),
and the [HTTP app's `Stop` and `Cleanup`](https://github.com/caddyserver/caddy/blob/v2.11.4/modules/caddyhttp/app.go).

| Event | Caddy behavior | Security behavior |
| --- | --- | --- |
| Module load | Constructs, decodes, provisions, validates, then records the module for cleanup | Deep copies the declarative AuthCrunch config through JSON before replacement, validation, or construction can mutate it |
| Own provisioning failure | Calls the failed module's `Cleanup` directly | Handles a nil server; `NewServer` already unwinds partial construction |
| Later module provisioning/validation failure | Cancels the candidate context and cleans up successfully loaded modules | Disposes a successful candidate, even though `Start` was never called |
| Validation without running | Provisions and validates, then cancels the context | Disposes volatile validation-only runtimes; persistent configuration has no runtime yet |
| Start failure | Stops apps already started and cancels the candidate context | Disposes the candidate; does not close the old configuration's runtime |
| Successful replacement | Starts new apps, changes the current context, stops all old apps, then cancels the old context | Leaves `Stop` free of disposal; closes the old runtime in `Cleanup` after its AuthCrunch calls drain |

Caddy iterates apps and module cleanup in unspecified order. The HTTP app's
`Stop` begins server shutdown, but waits for completion only when the process is
exiting. During a reload, returning from HTTP `Stop` or canceling the module
context does **not** prove that HTTP requests have finished. HTTP grace-period
expiry is also not proof that a handler has returned.

The host already owns publication and listener replacement, so the security app
does not add its own global active-server pointer or swap runtimes inside an app.
Volatile mode publishes its constructed server during provisioning, before route
modules resolve names. Persistent mode constructs only in `Start`, so validation
does not create keys or state files; routes validate names against the resolved
configuration and acquire runtime objects after startup. Admission is closed
until construction succeeds. Caddy starts the candidate HTTP stack and retires the old stack.
An app instance cannot be reprovisioned or resurrected after cleanup.

Persistent-to-persistent replacement is rejected during provisioning, using
`caddy.ActiveContext().AppIfConfigured("security")` to inspect the host-owned
active app before any candidate apps start. This is intentionally conservative
even for a different directory. It adds no storage lock or snapshot registry;
AuthCrunch alone owns the cross-process directory lock. Stop/drain Caddy fully
before starting a persistent replacement. First startup can briefly have HTTP
listeners before the security app's `Start`; requests then fail closed with
503. See [persistent state](../../configuration-state/SKILL.md) for the operator
contract and built-command restart/reload tests.

Construction success retains AuthCrunch's existing readiness semantics. An
explicitly delayed OAuth provider may still be performing discovery; Caddy does
not reinterpret that configuration as synchronous discovery.

## Request draining and failures

Each `AuthnMiddleware.ServeHTTP` and `AuthzMiddleware.Authenticate` call acquires
one app request reference before touching a borrowed runtime object. Admission
and reference acquisition share the cleanup mutex. Cleanup disables admission
before waiting, which prevents new references from racing the wait. The request
releases its reference on return, including errors and panic unwinding.

Tracking covers the AuthCrunch call. A protected upstream handler that runs
after authorization uses Caddy's copied user metadata and no longer needs the
AuthCrunch runtime. Calls that have not entered AuthCrunch when retirement
starts fail closed. An authentication portal returns a Caddy 503 error. The
authorization provider returns an error and no authenticated user; Caddy's
authentication middleware normally turns that rejection into 401. The route
`AuthorizationHandler` used by current Caddyfiles preserves the 503 and every
other handled gatekeeper response instead of running an error route over it.

Cleanup waits synchronously, so the reload operation can wait while the new
deployment is already serving. It can outlast the HTTP grace period. It never
closes a server underneath a still-running AuthCrunch call. Configure suitable
HTTP read/write and upstream timeouts for the deployment: an indefinitely
blocked handler can indefinitely delay cleanup. Canceling a request alone does
not release its reference; its handler must return. No untracked background
drain goroutine or forced close timer is used.

Provider disposal belongs to `Server.Close`: it cancels and joins delayed
discovery, JWKS requests, retries, and maintenance workers. Caddy does not close
these components a second time. Caddy provisioning is synchronous, and
`NewServer` has no host-context cancellation parameter. A host cannot cancel a
partially constructed server it has not received; synchronous setup follows
AuthCrunch's network timeouts and retry policy. A failed constructor unwinds its
earlier providers before returning.

A failed replacement leaves the old security runtime and its route references
usable. Caddy may have started some candidate apps before another app fails;
its lifecycle does not provide transactional isolation from all possible app
side effects. Cleanup errors are returned to Caddy for logging; they do not
roll back a replacement already serving.

## Persistent identity files: current reload restriction

**Live replacement using the same local identity file or registration dropbox is rejected.** The old
deployment remains active. Stop it before loading another runtime using that
file. This includes validation-only candidates in the same process. Use a
single named identity store across portals; multiple stores pointing at the
same file in one runtime are also rejected. Registration dropboxes use the same
snapshot database and receive the same protection.

The selected AuthCrunch local authenticator loads a private `identity.Database`
snapshot. Its mutex protects that instance only. The root server offers no
public facility to inject a coordinated store or reload all snapshots. A mutex
around HTTP requests cannot fix the problem: a second snapshot can overwrite
the first snapshot's changes even when the writes happen sequentially.
Construction can itself write static users, password overrides, API keys, and
default administrators.
The selected library serializes TOTP consumption with a file lock and reloads
that operation's state. That narrower replay protection does not provide a
shared database lifecycle for all construction and administrative mutations;
it does not lift Caddy's identity-file reservation rule.

The host therefore reserves local identity files before constructing a runtime
and releases them only after request drain and server disposal. Overlap fails
before the candidate can touch the active file. Reservations compare canonical
paths, resolve existing symlink ancestors, and detect existing hard-link aliases.
Resolve symlinks before lexical path cleaning: `link/../users.json` traverses
the symlink target's parent. A dangling symlink is rejected before construction;
ordinary missing files and directories can be reserved before they are created.
Preserve filesystem traversal while trimming redundant trailing separators from
missing parent paths. Before either file exists, case and canonical Unicode
normalization variants conservatively conflict on every platform; once both
exist, filesystem identity distinguishes
separate files even on a case-sensitive filesystem. This avoids admitting two
writers solely because an inode is not available yet.
Reservation of multiple files is atomic within this process; a failed conflict
check leaves no partial reservation. `:memory:` stores are independent and need
no file reservation. Volatile LDAP/OAuth deployments can reload normally.

This safeguard does **not** implement seamless replacement for local files.
That remaining feature needs upstream database coordination: either shared
in-process database state with reference ownership and serialized mutations, or
an equivalent public store-construction/refresh contract. It must cover setup,
login/MFA mutations, refresh revocation, administrative writes, and independent
realms that use the same underlying file. Adding an advisory lock only around
file writes is insufficient. The sibling module remains separate work.

Reservations do not coordinate another process, external file editors, or path
replacement while running. No cross-process transaction or rollback is claimed.
Construction of a candidate using a previously unowned file can create or update
that file even if a later host module fails. Cleanup does not undo those writes
or delete persistent identity data.

Client registrations and signing-key files remain persisted independently of
runtime disposal. Supply the existing registration credentials and key paths to
the next configuration; do not regenerate them on every load. The config copy
preserves those values. Access JWTs can remain valid when verification keys and
policy remain compatible. Without `Config.State`, OIDC sessions, pending
requests, grants and portal refresh state are volatile. With it, completed
authority and generated keys survive a stop/start; pending requests do not.

## Validation

`app_lifecycle_test.go` covers fresh graphs, partial provisioning, repeated and
concurrent cleanup, admission versus drain, shared providers across portals,
cancellation of slow discovery/JWKS requests, and identity-file reservations.
Include direct JSON inputs: unlike Caddyfile constructors, JSON can omit portal
UI/cookie settings or contain null collection entries. Resolve supplied optional
settings without dereferencing omitted objects. Reject null entries throughout
typed component collections before invoking AuthCrunch validation/construction,
and reject mixed object lists in flexible provider parameters. Check parameter
decoding against AuthCrunch's public config types before the dispatch validators;
some of those validators ignore type errors and otherwise allow partially
decoded data to reach construction. Use the typed validators in `app_config.go`
and extend their unit/E2E cases when adding component collections. Validators
that parse raw credential/messaging/registration instructions must run only when raw
instructions are present; preserve already-parsed sections. Test defaults and
restored typed configs through portal requests and login, and malformed
replacements against a still-serving deployment.
Also cover short raw crypto/provider-kind instructions and empty crypto tokens;
guard upstream argument indexing before invoking dispatch parsers. See
[runtime resolution](../../configuration-runtime-resolution/SKILL.md#what-gets-resolved)
for the encoded-instruction boundary.

`app_lifecycle_e2e_test.go` runs a subprocess with actual Caddy HTTP listeners and
calls the public `caddy.Load` reload path. It tests failed construction, later
module `Provision`/`Validate` failures, app `Start` failure, validation-only
cleanup, successful publication with portal and gatekeeper calls still in
flight, and persistent registrations, signing keys, and identity files. The
identity tests include symlink parent traversal, dangling symlinks, missing
directories with redundant separators, case and Unicode variants of missing files, rejected
password-overwrite candidates, and reuse after complete disposal. File checks
must fail on read errors or empty files before comparing persistent contents.
The drain test holds requests beyond a 10ms HTTP grace period and verifies the new
deployment can serve before the old runtime is closed. It bounds request,
reload, worker, and subprocess completion and checks that no AuthCrunch worker
stack survives final cleanup. Response holds must preserve the underlying
writer's implicit/explicit status behavior, and request helpers must detect
truncated bodies. It uses synthetic credentials and local upstreams.

Run the focused suite with:

```sh
go test -mod=readonly -race -count=1 -timeout=3m -run 'TestApp|TestCaddyLifecycleE2E' .
```

The library references for ownership are `server.go`,
`server_lifecycle_test.go`, `server_lifecycle_e2e_test.go`,
`pkg/idp/oauth/shutdown_test.go`, and the coding skill's
`references/embedding-integration.md` in go-authcrunch.
