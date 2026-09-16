---
name: configuration-oauth-applications
description: Configure and provision named OAuth applications, durable private registration storage, and portal OIDC providers in caddy-security. Use for oauth application blocks, security CLI commands, credential rotation, and provider key rollover; external login providers belong to configuration-oauth-providers.
---

# Configuration OAuth Applications

## Ownership

`oauth application <nickname>` belongs inside global `security`. The Caddy
adapter collects these blocks before parsing other declarations, including
portals and identity providers. `caddyfile_oauth_application.go` encodes the
header separately from each body statement and delegates to
`go-authcrunch/pkg/oidc/parser.NewOAuthApplicationConfigFromDirectives`.
`Config.AddOAuthApplication` validates and copies each registration.
Collect applications directly from the enclosing dispenser: Caddy's
`NextSegment` omits empty blocks, which otherwise turns an empty registration
into a misleading missing-block error. Dispatch errors must also omit raw
tokens; malformed quoted headers can contain misplaced credentials before the
application parser runs.
Check the closing brace before calling `NextBlock`: that helper can skip a
brace followed by another token on the same line and read the following setting
inside the application. Reject this form so misplaced consent, PKCE, and
callback settings cannot change the registration.
Reject unquoted closing braces among header/body arguments too. `RemainingArgs`
accepts them as values, so a missing `client_id` could otherwise become `}` and
shift which enclosing block supplies the application's closing brace.
After collection, also require the enclosing `security` dispenser's nesting
to return to zero. Caddy's initial brace counting treats quoted `"}"` values
as structural, so a child parser can consume the enclosing closing brace;
EOF must not turn that incomplete security block into a valid configuration.
The published go-authcrunch v1.2.4 selected in `go.mod` supports these APIs and
repeated singular `redirect_uri` statements. No local replacement is required;
follow the [dependency workflow](../scripts-and-automation/SKILL.md#local-go-authcrunch-development)
when changing the selected version.
Follow the [repository scope](../coding-directives/SKILL.md#repository-scope)
when consulting or selecting sibling source.

An application declares a client. A portal enables an OpenID Provider (OP) by
selecting those clients in an `oidc provider` block. See
[Portal OpenID Provider](references/oidc-provider.md) for the one-block contract,
all settings/defaults, deferred attachment, realm selection, issuer/cookie
isolation, JSON restoration, and Caddy unit/E2E coverage. See
[Private provisioning and activation](references/private-provisioning.md) for
the tested create/load/rotate workflow, storage security, candidate activation,
and key rollover. External login through `oauth identity provider` uses
[configuration-oauth-providers](../configuration-oauth-providers/SKILL.md).

Keep host storage names scoped to OAuth: `oauth registration store` in Caddyfiles,
`oauth_registration_store` in app JSON, and `oauth_registration_*` source files.
Use `oauth_store.Caddyfile`, `oauth_client.Caddyfile`, and `oauth_rotate.Caddyfile`
for standalone provisioning inputs. User registration remains a separate domain.

## Grammar

This is a catalogue of fields inside `security`; only `redirect_uri` may repeat:

```caddyfile
oauth application <nickname> {
	registration <immutable-revision>
	client_id <id>
	client_name <display_name>
	client_secret <secret>
	token_endpoint_auth_method <client_secret_basic|client_secret_post|none>
	redirect_uri <uri>
	scopes <scope> [<scope>...]
	require_pkce <true|yes|on|1|false|no|off|0>
	skip_consent <true|yes|on|1|false|no|off|0>
}
```

- Optional `registration` selects a previously provisioned revision from the
  single `oauth registration store` in `security`. Without it, credentials are explicit.
  Revisions are 1–64 ASCII letters/digits/hyphens/underscores, starting with a
  letter or digit. Only declared nicknames become registered.
- Nickname identifies the declaration. `client_id` identifies the protocol
  client; `client_name` is its display name and defaults to nickname. Keep
  these separate, including in native JSON and lookup keys.
- Duplicate nicknames fail, even for identical definitions, repeated imports,
  or different protocol IDs. Different nicknames may share a protocol ID at
  registration time; provider validation owns conflicting client-ID references.
- Scalars require exactly one value. Quote display names containing spaces.
  Each `redirect_uri` statement takes exactly one URI and appends it in
  declaration order. `scopes` occupies one statement with one or more values;
  repeated scopes statements fail. The `redirect_uris` directive is rejected,
  including mixed singular/plural input. Nested blocks, spaced field aliases,
  and grouped keywords are unsupported.
- Use unquoted block braces. End the line after the closing brace; following
  settings and declarations belong on a new line.
- Booleans retain the application parser's true/yes/on/1 and false/no/off/0
  spellings. Provider/refresh enabled/disabled state syntax is unsupported here.
- Authentication defaults to `client_secret_basic`; confidential clients may
  choose `client_secret_post`. Both require an explicit or stored client ID and a secret
  of 32–1024 bytes. IDs must be nonempty, at most 256 bytes, and have no leading
  or trailing whitespace, tabs, or newlines.
- Public clients choose `none`, omit the secret, and require PKCE. PKCE defaults
  to true for all clients; only confidential clients may disable it.
- Consent skipping defaults to false; explicitly enabling it grants the
  registered scopes. Scopes default to `openid profile email`; an explicit
  list must be distinct, include `openid`, and use only those supported scopes.
- Callback URIs are required, distinct, and preserved byte-for-byte, including
  case, percent encoding, query ordering, and explicit ports. HTTPS is required
  except for public native clients using HTTP with literal `127.0.0.1` or
  `[::1]`. Hostname loopback and private URI schemes are not supported. The
  provider's native-loopback port exception does not normalize registration
  strings; full protocol exchanges are separate integration work.

## Why One Callback per Statement

Each callback is a separate registration entry, so write it on its own line:

```caddyfile
redirect_uri https://App.example.test:443/a%2Fb?next=%2F&x=+
redirect_uri https://app.example.test/callback
```

Inside `oauth application`, this lets reviewers add, remove, or inspect one
callback without rewriting a packed list. The shared upstream parser owns
append behavior; Caddy forwards each complete statement and preserves exact
URI bytes. Repeated identical URIs remain errors. Retaining no plural alias
keeps one directive form and unambiguous one-value arity. The serialized
`redirect_uris` array retains its name and order for stored-config compatibility.

## Credentials and Snapshots

Normal adaptation never generates or persists credentials. `registration v1`
loads the validated named record from the explicit private store. Only omitted
ID and secret inherit; callbacks, scopes, display name, authentication method,
consent, and PKCE come from the current declaration and parser defaults. Public
clients inherit no secret. Moving to confidential authentication requires an
explicit secret through the provisioning command. Changing IDs never borrows
another ID's secret. Secret rotation retains the ID; use a new nickname to
create a different stored client identity.

An explicit ID/secret in a stored declaration must match its selected durable
revision. First stage any credential change with `security oauth rotate secret`, then
select that revision. A mismatched, missing, corrupt, unreadable, or nonprivate
record fails closed. Changes to a file between adaptation and activation are
rejected by a digest of the validated registration. Never edit published records.

Stored application references serialize in `apps.security.oauth_application_sources`
with nickname, revision, digest, and current noncredential directives. The
`oauth_registration_store.path` is absolute. Provider statements serialize in
`oidc_provider_directives`, keyed by portal name. Loaded credentials and copied
provider clients are removed before serializing the Caddy configuration; `App`
reconstructs them only in its private runtime copy. This protects the saved
credentials from adapted JSON, Caddy autosave, and admin configuration views.

Without `registration`, existing native JSON remains supported at
`apps.security.config.oauth_applications`, as `{ "name": ..., "client": ... }`
objects. Explicit credentials remain secret-bearing configuration. Caddy's
`{$VARIABLE}` substitution runs before adaptation; application fields do not
implement runtime `{env.*}` or `secrets:*` expansion. The separate provisioning
file does not expand variables or imports. Its `client_secret` is literal.

Protect all configurations, diagnostics, and backups because other settings can
still contain passwords or keys. Generic configuration dumping is not credential
storage. See the private provisioning reference for filesystem permissions,
protected RP handoff, and recovery after interrupted writes.

## Examples and Validation

The complete, synthetic example is
[`testcase_security_oauth_applications.Caddyfile`](../../../testdata/caddyfile_adapt/testcase_security_oauth_applications.Caddyfile).
It includes all three authentication methods, a local portal, exact callbacks,
and applications declared after the portal. Replace its fixture credentials
before using it outside tests.

Coverage belongs to `caddyfile_oauth_application_test.go`,
`TestCaddyfileAdaptAuthenticationToJSON`, `TestResolveRuntimeAppConfig`, and
`TestCaddyOAuthApplicationsE2E` in `oauth_application_e2e_test.go`. The E2E test
adapts that file, provisions Caddy with a valid local portal, authenticates over
TLS, reloads repeatedly, rejects invalid native JSON, removes/reintroduces an
application, and checks explicit secret rotation and redacted process logs.
Header-error tests cover inline and imported declarations through the real
adapter, including empty blocks and grouped headers with misplaced credentials.
Block-boundary tests reject quoted delimiters and settings after a closing brace.
The E2E test also verifies login remains available after those adaptations fail.
It verifies that application declarations alone enable no OP endpoints.
`TestCaddyRegistrationE2E` exercises the registered CLI in independent processes,
real Caddy restart/reload and validation, RP code exchange and ID-token signature
verification, old-secret rejection after activation, failed activation, key
rollover, and redaction of actual admin/autosave/log surfaces.
`TestCaddyRegistrationInterruptedWriterE2E` kills a writer during a partial write,
checks that the actual CLI times out on the retained lock while adaptation still
reads the prior registration, and verifies rotation after deliberate recovery.
`oauth_registration_store_test.go` covers atomic failure paths, concurrency, permissions,
invalid lock entries, read-only adaptation with a failing randomness source, bounded publication,
ambiguous/corrupt JSON, and revision integrity. `oauth_registration_config_test.go`
checks provider key path identity and permissions for Caddyfile and native JSON
providers; `command_provision_test.go` checks private
input filename identity. The process E2E tests reject malformed input and records
without creating credentials or replacing the active deployment. They also verify
that unsafe keys in native JSON are rejected without changing the active provider
or autosave, and that private keys work in explicit configurations without a store.
`command_security_test.go` covers Caddy command-group registration, descriptive
subcommand help, flags specific to each action, and rejection of positional
secrets. Keep the namespace's inherited Cobra flag-error handler: flag parsing
runs before command handlers, and default errors echo unknown flag names and
invalid values. Help must perform no provisioning. `TestCaddySecurityCommandE2E`
and `TestCaddySecurityCommandFlagErrorsE2E` check help, dispatch, and error
redaction through the actual Caddy CLI in separate processes.
`testcase_security_oauth_registration_store`, `testcase_security_oauth_registration_malformed`,
and `testcase_security_oauth_registration_legacy`
cover the new adaptation syntax; the positive fixture provisions deterministic
synthetic credentials in a temporary private directory. Runtime reference
resolution is tested through the complete App and Caddy lifecycle, since the
older root-config-only resolution helper does not load host-owned references.

Follow [testing-and-ci](../testing-and-ci/SKILL.md) for validation commands and
[syntax maintenance](../configuration/references/syntax-maintenance.md) when
changing the Caddy wrapper or selected upstream grammar.
