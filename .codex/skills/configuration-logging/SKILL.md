---
name: configuration-logging
description: "Configure and validate root security logging skip rules, AuthCrunch diagnostic filtering, JSON persistence and Caddy logger ownership. Use for noisy authentication logs and issue #280; excludes access-log configuration and authorization behavior changes."
---

# Configuration Logging

## Supported Scope

The root `security logging` block configures AuthCrunch component diagnostics.
**Caddy v2.11.4's independent `http.handlers.authentication` logger remains
unfiltered. Issue #280 is not fixed by this adapter.** Read the host boundary
below before recommending the issue's message/error patterns to an operator.
Current `authorize` Caddyfiles use `http.handlers.authorization`; the legacy
JSON authentication-provider chain is still supported and emits the host error.
Do not change that chain's behavior to silence it.

The selected published AuthCrunch v1.3.4 already contains `Config.Logging`,
`pkg/logging`, the shared parser, and root logger wrapping (feature commit
`8e8e35b66ad1a699e239575e42cbbcd603a2894d`, included in release commit
`a97ff2f0a4429e286c30b9cc0cd6babab109b964`). No local replacement or library
release is required. Recheck `go list -m -json` when dependencies change;
follow [dependency workflow](../scripts-and-automation/SKILL.md#local-go-authcrunch-development).
Sibling source and skills remain read-only references.

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
proposed upstream contract, not an API available in v2.11.4.

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

```sh
make test TEST='TestParseCaddyfileLogging|TestLogging|TestAppLogging|TestCaddyLoggingE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' TEST_DIR=. COVERAGE_DIR=.coverage/logging
```
