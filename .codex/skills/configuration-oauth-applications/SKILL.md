---
name: configuration-oauth-applications
description: Configure named OAuth applications in caddy-security with explicit client credentials, authentication methods, callback URIs, scopes, PKCE, and consent settings. Use for oauth application blocks and their native JSON registrations; external login providers belong to configuration-oauth-providers.
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

An application registers a client for future provider configuration. This
Caddyfile feature does not enable an OpenID Provider (OP) or attach public OP
routes. External login through `oauth identity provider` uses
[configuration-oauth-providers](../configuration-oauth-providers/SKILL.md).

## Grammar

This is a catalogue of fields inside `security`; only `redirect_uri` may repeat:

```caddyfile
oauth application <nickname> {
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
  choose `client_secret_post`. Both require an explicit client ID and a secret
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

Adaptation never generates credentials and currently passes no persisted
record. Missing credentials return a value-redacted error. Persisted records
must come through the private storage integration when it is implemented;
prior Caddy config, removed declarations, and stored records are not implicit
registrations. Build a fresh declaration set on every adaptation/reload.

Supply complete explicit credentials. Caddy's `{$VARIABLE}` substitution runs
before adaptation and can supply them from the environment; this feature does
not add runtime `{env.*}` or `secrets:*` replacement for application fields.
Quoted names and credentials survive Caddy tokenization and the upstream CSV
codec. Errors and routine logging must never include client secrets.

Native JSON stores registrations at `apps.security.config.oauth_applications`
as a list of `{ "name": "nickname", "client": { ... } }` objects. This JSON
contains credentials; it is configuration data for private storage, not a
logging representation. Registry lookups return independent named/client
copies. Provider clients remain independent snapshots; later registration or
reload must not silently mutate an existing provider.

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
It verifies that no OP endpoints are enabled. Full OP exchanges belong to the
later provider integration; parser and JSON tests do not establish that flow.

Follow [testing-and-ci](../testing-and-ci/SKILL.md) for validation commands and
[syntax maintenance](../configuration/references/syntax-maintenance.md) when
changing the Caddy wrapper or selected upstream grammar.
