---
name: configuration-state
description: Configure durable AuthCrunch runtime state in Caddy, including the root state adapter, restart persistence, exclusive ownership, reload rejection, failure handling, and process-level regression tests.
---

# Persistent Runtime State

Use this skill for `security { state { ... } }`, native `config.state` JSON,
restart persistence, and its lifecycle boundary. OAuth client registrations and
identity databases retain their existing owners. Keep changes and test output
in this repository; sibling AuthCrunch source is a read-only reference under
the [repository scope](../coding-directives/SKILL.md#repository-scope).

## Configuration

Add one optional block inside the global security app:

```caddyfile
{
	security {
		state {
			directory /var/lib/authcrunch/runtime
		}
		# Existing providers, portals and/or authorization policies follow.
	}
}
```

This is a fragment: a usable security app also needs a portal or policy.
The JSON field is `apps.security.config.state`, with the library's shape:
`"state":{"directory":"/var/lib/authcrunch/runtime"}`.
Paths must be absolute, non-root and private. Quote spaces. Omission retains
volatile behavior; an empty block, duplicate block/setting, extra arguments,
unknown settings and nested blocks are errors. Closing braces end their lines.
Use `{$VARIABLE}` for adaptation-time substitution. `{env.VARIABLE}` and whole
`secrets:manager:key` references remain declarative until provisioning; an empty
or invalid resolved directory fails instead of disabling persistence.

`caddyfile_state.go` owns traversal and `cfgutil.EncodeArgs` encoding;
`go-authcrunch/pkg/state/parser.NewStateConfigFromDirectives` owns grammar and
normalization. Deferred values use a validation-only stand-in, retain their
original token in `Config.State`, and are resolved/revalidated in the private
configuration copy. Never open the stand-in, choose a process-specific directory,
implement another directory grammar, or copy the library's records, encryption,
session DTOs, replay history or locks into Caddy.

## Lifecycle and operation

Read [operator guidance](references/operations.md) when enabling persistence,
planning deployment/recovery, or explaining its guarantees. Persistent runtimes
are constructed by `App.Start`, not `Provision`, so adaptation and validation
do not initialize keys or state files. Route provisioning validates declared
names; admission stays closed until `NewServer` succeeds.

Caddy v2.11.4 provisions and starts a replacement before retiring the old app.
There is no atomic drain/construct/rollback facility. A candidate persistent
app checks Caddy's active app during provisioning and rejects replacement of a
live persistent runtime before candidate HTTP routes start. This deliberately
also rejects changing directories by reload. Use a complete stop/start.
The library independently enforces exclusive directory ownership across
processes. Do not add a host storage lock or shared runtime/snapshot map.

`App.Cleanup` closes admission, drains every admitted portal/gatekeeper call
(including callbacks, token and profile APIs), then closes the root. A failed
candidate never closes the serving root. Failed construction unwinds its own
resources. Close neither flushes nor deletes committed data. Preserve handled
503/protocol failures and never issue fallback credentials or retry rotations.

Policy-only OAuth needs neither a placeholder portal nor a local database.
Use [direct OAuth policies](../configuration-authorization/SKILL.md#direct-oauth-without-a-portal)
and mount their callback/logout namespace through the same policy.

## Validation

The selected published go-authcrunch v1.3.4 supplies `Config.State` and both
public parsers; no dependency replacement is needed. Recheck the selected module
before changing the contract. Library tests alone do not certify this host.

- `caddyfile_state_test.go`, `caddyfile_authz_oauth_test.go` and the
  `testcase_security_state` adaptation fixture cover grammar, exact paths,
  JSON, placeholders, redacted failures and policy-only configuration.
- `app_state_test.go` covers no-I/O provisioning, single ownership, failed
  initialization, retry, 503 route admission before startup/after cleanup and
  drain before storage release.
- `TestAuthzResponseContract` tests the actual three-outcome route handler.
- `TestCaddyRuntimeStateE2E` builds an actual Caddy command from
  `testdata/runtime_state_caddy`, with standard/production modules and only an
  isolated test CA pool added to the main program. TLS verification remains
  enabled; no machine trust is changed. It uses SIGKILL and the same origin,
  directory and config across fresh processes. It covers direct OAuth, ACLs,
  lost pending callbacks, sessions/JWKS/signatures, browser/native refresh,
  OIDC consent/code/access/refresh and replay, logout, password/DB rollback,
  configuration transitions, competing processes, corrupt/lost storage,
  permissions, write failures, real snapshot capacity and overlapping reload
  under admitted callbacks and application traffic. Deferred state-directory
  resolution preserves its placeholder in autosave. Omitted-state behavior and
  failed persistence activation retaining the volatile deployment's routes and
  sessions remain separate phases. The snapshot-capacity fixture writes tens
  of MiB.

Run the focused unit/adaptation tests and
`go test -mod=readonly -race -count=1 -timeout=8m -run 'TestCaddyRuntimeStateE2E|TestPersistentApp' .`.
Retain the existing OAuth, lifecycle, composition and browser refresh suites.
Use [testing-and-ci](../testing-and-ci/SKILL.md) for full regression/report runs.
