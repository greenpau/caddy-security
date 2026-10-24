---
name: configuration-logging
description: "Configure AuthCrunch diagnostic skip rules, Caddy credential redaction, and logger boundaries. Use for component/message filtering and safe credential diagnostics; authorization outcomes remain unchanged."
---

# Configuration Logging

## Supported Scope

The root `security logging` block configures AuthCrunch component diagnostics.
**The selected Caddy's independent `http.handlers.authentication` logger remains
unfiltered. Issue #280 is not fixed by this adapter.** Read the host boundary
below before recommending the issue's message/error patterns to an operator.
Current `authorize` Caddyfiles use `http.handlers.authorization`; the legacy
JSON authentication-provider chain is still supported and emits the host error.
Do not change that chain's behavior to silence it.

The selected AuthCrunch module supplies `Config.Logging`, `pkg/logging`, the shared
parser, and root logger wrapping. No local replacement or library release is
needed for these interfaces. Recheck `go list -m -json` when dependencies change;
the [dependency workflow](../scripts-and-automation/SKILL.md#local-go-authcrunch-development)
owns selection changes. Sibling source and skills remain read-only references.

## Configuration

Inside the global options block:

```caddyfile
{
	security {
		logging {
			skip exact text "token validation error"
		}
	}
}
```

This suppresses the AuthCrunch gatekeeper's diagnostic message; it leaves its
returned errors, HTTP denial, redirects and authorization decisions unchanged.
Other security declarations and site routes are configured normally.

The complete body grammar is one statement per line:

```text
skip <exact|partial|prefix|suffix|regex> text <value>
```

Every statement has four tokens. Quote multiword values. Repeated rules,
including identical rules and imported rule bodies, append in order and match
with OR. Duplicate logging blocks, header arguments, nested blocks, empty
tokens, malformed keywords/arity, invalid regular expressions, whitespace-only
text and raw newlines are rejected with location-aware errors. Omission or an
empty multiline block suppresses nothing; there are no implicit rules.
The enclosing global `security` option also occurs once; repeating it fails
instead of silently replacing the earlier app and discarding its rules.

Matching is case-sensitive. Exact compares the whole value, partial finds a
substring, prefix/suffix match an edge, and regex uses Go regexp semantics
(unanchored unless the pattern supplies anchors). Spaces, quotes, Unicode and
regex escapes survive Caddy tokenization, argument encoding and JSON. Patterns
are literal during provisioning: `{env.*}` and `secrets:*` are not expanded.
Caddy's normal `{$ENV}` preprocessing still occurs before tokenization.

The library compares the message and individual string, byte-string, error and
Stringer values, including fields bound after wrapping by With/WithLazy. Keys,
logger names, numeric values, arrays and object contents are outside this
selector. In the host error, `reason: no token found` occurs in the `error`
field, not in the message. The component's error field contains `no token found`
without that host prefix; a `partial` rule for that value selectively suppresses
its missing-token diagnostics while retaining malformed-token diagnostics.

Native Caddy JSON stores the library type directly:

```json
{"apps":{"security":{"config":{"logging":{"skip":[
  {"match":"exact","text":"token validation error"}
]}}}}}
```

`caddyfile_logging.go` collects the complete block with Caddy's tokenized
values, rejects empty arguments/unsupported structure, encodes each statement
with `cfgutil.EncodeArgs`, then calls
`logging/parser.NewLoggingConfigFromDirectives`. Do not split or concatenate
tokens manually, implement another matcher, or publish a partial config.
`App.Provision` copies the declarative graph through JSON and invokes the
library's `Config.Validate` before constructing/serving. `NewServer` creates an
immutable filter and wraps its supplied logger before creating components.
The app's original base logger and unrelated host/access logs remain unchanged;
Caddy retains flushing and lifetime ownership.

Reload creates a new app/runtime/filter from the base logger. Replacing/removing
rules cannot mutate the old instance or accumulate wrappers. Logging is excluded
from AuthCrunch's persistent-session binding: logging-only stop/start changes
retain refresh sessions. Existing [runtime restrictions](../coding-directives/references/runtime-lifecycle.md)
still apply: overlapping persistent roots or local identity files are rejected.
Do not relax those restrictions for logging changes.

## Credential header redaction

Caddy's HTTP server clones the request before authorization for its error and
access loggers. AuthCrunch's `enable strip token` affects downstream handling,
not that earlier copy. Caddy's default credential redaction covers standard
Authorization/Cookie headers, not arbitrary API-key headers. Debug HTTP error
logs and enabled access logs can therefore contain a supplied API key.

Configure Caddy `format filter` encoders to delete
`request>headers>X-Api-Key` and every configured custom key header, using
canonical HTTP header spelling, in both global diagnostic and site access logs.
The [SQLite API-key example](../configuration-authorization/references/sqlite-api-keys.md)
includes these host filters and is qualified through the production TLS journey.
This is field redaction; it preserves the HTTP denial and diagnostic entry.
It does not implement the component-level host message suppression below or
resolve issue #280. Keep returned errors and authorization behavior unchanged.

## Credential-bearing request and response URLs

Trusted ticket login carries opaque request identifiers and tickets in query
parameters. Caddy's earlier request clone also retains that URI. Delete
`request>uri` and `resp_headers>Location` with filter encoders in both global
diagnostic and site access logs, as shown in [ticket configuration](../configuration-ticket-providers/SKILL.md).
Caddy records the issuer redirect in response headers even when request URI is
deleted. These filters preserve status and denial entries. An issuer or proxy
needs equivalent protection, including credential-bearing Location headers. Handler query stripping
or AuthCrunch component skip rules do not provide this field redaction. Qualify
malformed URI parsing before substituting a narrower query-only filter.

## Authentication event diagnostics

The portal emits the following structured events at INFO/WARN. Caddy delegates
these calls to AuthCrunch; it does not reconstruct authentication outcomes from
HTTP status or add a second event stream.

| Event | Level and boundary |
| --- | --- |
| `password authentication failed` | WARN after backend password verification fails. Invalid forms and rate limiting can exit earlier. |
| `totp passcode authentication failed` | WARN after the TOTP backend rejects a passcode. |
| `u2f authentication failed` | WARN after backend WebAuthn verification fails. Decoder and origin rejection can exit earlier. |
| `user was successfully authenticated` | INFO after JSON checkpoint login issues its credentials, before writing the final response. |

The three failure events cover JSON and browser checkpoint paths. They include
canonical `username`, `realm`, `portal_name`, numeric `checkpoint_id`,
`checkpoint_name`, `checkpoint_type`, `session_id`, `request_id`, `src_ip` and
`src_conn_ip`. The final JSON event includes the same account/portal attribution
and correlation fields, plus `authentication_flow=api`; it has no checkpoint or
source-address requirement. Account attribution comes from the captured
authenticator, not a submitted email alias or transformed JWT subject.

For connected LDAP accounts, local MFA can run in the attached local account's
realm. The factor event pairs that local username with its local realm; it does
not claim that realm is the original federation issuer. `portal_name` identifies
the configured portal, allowing equal usernames in different realms/portals to
be distinguished. Request IDs and the portal session cookie are correlation
inputs, not identity proofs. Jar-free requests can receive a different
`session_id` on every checkpoint; it is not the sandbox ID or refresh-family ID.
Caddy's trusted-proxy interpretation owns the source-address fields.

These events are diagnostics, not a complete audit ledger. Browser
`user passed all authorization checkpoints` precedes final issuance/session
admission, and the earlier `Successful login` event is not equivalent to the
final JSON event. API-key exchanges, external-provider callbacks and refresh
have separate paths. Even final JSON issuance does not establish that a client
received the response. Check the actual HTTP/credential outcome independently;
for example, a rejected browser TOTP input can render HTML with status 200.

Existing skip rules match these messages and textual field values. For example,
`skip exact text "totp passcode authentication failed"` suppresses that complete
entry while preserving the rejection and other diagnostics. Matching a portal,
realm or username value is still a value-only rule: the filter has no field-name
selector and also matches an identical value in another textual field. Keep
the separate Caddy diagnostic/access-log redaction controls above.

## Missing Caddy Host Extension

Trace the pinned host before attempting integration:

- `modules/caddyhttp/caddyauth/caddyauth.go`: `Authentication.Provision` saves
  `ctx.Logger()` into its private `logger` before loading providers.
  `Authentication.ServeHTTP` calls that logger's `Check` and `Write` on returned
  provider errors, attaching `provider` and `zap.Error(err)`.
- `context.go`: `Context.Logger` calls `Logging.Logger`. There is no supported
  instance logger setter/wrapper. Slog factories do not intercept these Zap calls.
- `logging.go`: `Logging.Logger` assembles configured cores and names the result.
  `BaseLog.provisionCommon` installs `CoreRaw` using
  `zapcore.NewTee(cl.core, core)`; the extension does not receive the existing
  core, so dropping its own copy cannot suppress the original output. Logging
  setup runs before app provisioning. Encoder/writer modules are too late to
  preserve the requested pre-sampling, typed-field, full-entry semantics.

The required upstream change is an instance-owned wrapping hook reached by the
actual authentication logger. A concrete option is an opt-in provider interface
that accepts the middleware's original `*zap.Logger` and returns a wrapped clone
or error during provisioning. Caddy would retain a clone per provider and use
it for that provider's actual error call. The authorizer could then supply
`logging.NewFilter(config.Logging).WrapLogger(base)`. Install it before any
With/WithLazy fields; retain the base logger and existing Sync owner. This is a
proposed upstream contract, not an API available in the selected Caddy host.

A supported scoped core-wrapper hook is another option, provided it wraps the
existing core rather than tees beside it and is isolated to the correct
configuration/module. Use the library wrapper to preserve samplers, tees, hooks,
error output and terminal actions. Do not add global mutable filters, unsafe
private-field access, a Caddy fork, dead-code wrappers, or an alternate
authentication implementation. Never swallow a returned error or permit a
protected handler to avoid a diagnostic.

## Validation

`caddyfile_logging_test.go` covers the issue's exact example, all matchers,
encoding, imports/repetition, malformed grammar/structure, omission/empty blocks,
native JSON validation, public config-file round trips and provisioning.
Adaptation fixtures are `testcase_security_logging`,
`testcase_security_logging_matchers` and `testcase_security_logging_empty`.
`TestAppLoggingInstanceIsolation` checks multiple simultaneous runtime filters,
detached snapshots, the unchanged base logger and rule removal.

`TestCaddyLoggingE2E` builds the actual race-enabled Caddy command and captures
JSON output. It uses verified local TLS, temporary identity databases, both
current and legacy routes, real password login and a counted protected upstream.
It proves baseline noise; error-only/message-only/combined host rules remaining
ineffective; selective component filtering; all matchers, case sensitivity and
OR; unchanged denials/success; unrelated access/app output; two live processes;
replacements, removal and invalid-JSON rollback. Its persistent journey rotates
the same refresh session across logging-only stop/start replacements.

These passing tests certify the consumer/component integration and the known
host limitation. They do **not** satisfy the issue's host-suppression acceptance
criteria. Once the host hook exists, require error-text-only suppression of
missing-token errors while malformed-token errors from the same logger remain,
and message-only suppression of the middleware message, through this real process.

`TestCaddyAuthenticationEventsE2E` qualifies exact INFO/WARN authentication events
through verified Caddy TLS with real password, TOTP and WebAuthn backend failures
in JSON and form flows. It checks canonical account/portal attribution, source
addresses, incomplete-versus-final JSON login, unchanged rejection under message
and field-value suppression, and captured credential redaction in diagnostic and
access output. A separate DEBUG case checks the same local credential boundary.
Its WebAuthn inputs reach signature verification; this HTTP test does not claim
physical-authenticator coverage. `TestAppLoggingInstanceIsolation`
remains the focused unit coverage for root-filter ownership and immutable rules.

```sh
make test TEST='TestParseCaddyfileLogging|TestLogging|TestAppLogging|TestCaddyLoggingE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' TEST_DIR=. COVERAGE_DIR=.coverage/logging
```
