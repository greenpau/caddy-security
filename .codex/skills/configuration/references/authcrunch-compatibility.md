# AuthCrunch compatibility through Caddy

## Selected implementation

Read `go.mod` and `go list -m -json github.com/greenpau/go-authcrunch` to
establish the selected version, module directory, and any replacement. This
checkout selects published v1.3.11; sibling source and integrated xcaddy build
arguments can select different code and are not proof of the normal build's
behavior. Record that distinction in qualification evidence. A dependency task
must inspect the Makefile xcaddy argument and CONTRIBUTING examples separately.

The table maps supported upstream surfaces to their Caddy host boundaries. Grammar details remain in the owning skills; do not copy the standalone
AuthCrunch HTTP server's configuration into Caddy's app or routes.

## Integration surfaces and evidence

Caddy v2.11.7 is selected in both the Go module and xcaddy build arguments.
It requires Go 1.26 and the already-selected quic-go v0.63.0/qpack v0.6.0.
The v2.11.4 → v2.11.7 upgrade changes quoted-brace tokenization, HTTP header
and idle-transfer defaults, authentication-provider response isolation and
shutdown coordination. Quoted brace arguments remain literal; policy block
delimiters still must be unquoted. Unit/adapt tests retain source diagnostics
and reject incomplete owned blocks; OAuth application E2E preserves literal
client names through TLS login and replacement. The Caddy lifecycle and private
logger ownership were rechecked against the published source. See
[HTTP integration defaults](../../configuration-http-integrations/SKILL.md#caddy-host-defaults)
and [runtime lifecycle](../../coding-directives/references/runtime-lifecycle.md).

The v1.3.10 → v1.3.11 comparison fixes unconditional ACL evaluation without
requiring `exp` in normalized or fresh identity claims. Caddy removes its older
refresh/OIDC/System API transform restriction and retains ordering, claim and
factor-policy regressions through real TLS. The shared cookie parser adds
`cookie cross-device session id name`; initialized cookie snapshots now contain
that tenth role, including prefixed defaults. Cookie unit/adapt/runtime tests
cover naming, collisions and token-role isolation. Cross-device login itself is
disabled by default. Caddy now delegates complete `enable cross-device login`
and `disable cross-device login` statements to the shared parser and preserves
the typed `cross_device_login` field through JSON reload. Real Caddy TLS and
Chrome journeys qualify explicit approval, independent credentials, provider
callbacks, lifecycle and browser cancellation. See
[cross-device login](../../configuration-authentication-cross-device/SKILL.md).
The dependency also requires go-crypto v1.5.2 and etree v1.8.1. The Caddy upgrade below is qualified separately; the selected quic-go and
qpack versions remain unchanged.

The v1.3.8 → v1.3.10 comparison adds typed custom ACL definitions, shared field
parsing and guardian claim projection. Caddy exposes `acl field`, serializes
`access_list_fields`, applies the collection once before policy validation and
rejects null field entries. Other delegated Caddyfile grammar is unchanged;
standalone HTTP-host validation, upstream test/automation changes and identity
comment cleanup do not add Caddy directives. See
[typed ACL fields](../../configuration-authorization/references/typed-acl-fields.md)
for grammar, TLS coverage and the default-rule ordering regression.

The v1.3.6 → v1.3.8 comparison adds GitHub ID/organization claims, shared
provider matcher compilation and reserved-claim validation. Caddy preserves
`match github` statements for that compiler; the transform and OAuth-provider
skills own grammar, trust and lookup limits. Adapter/unit tests and
`TestCaddyGithubTransformsE2E` qualify persisted matchers and signed-token
resource authorization through actual Caddy. The upstream generated ACL
changes preserve existing grammar; unconditional evaluation is corrected in
v1.3.11 as described above.

The earlier v1.3.4 → v1.3.6 source comparison leaves delegated Caddyfile parsers,
configuration shapes and defaults unchanged. Runtime hardening and the HTTP/3
return-URL fix arrive through the dependency; no new directive or Caddy redirect
builder is needed. The module keeps its existing quic-go v0.63.0 selection and
qpack v0.6.0: Caddy v2.11.4 requests quic-go v0.59.1 and AuthCrunch v1.3.6
requests v0.62.0 for its protocol tests. Do not downgrade the selected transport.
quic-go v0.63.0 leaves ordinary request URLs relative, masking the old
AuthCrunch bug in live traffic. The wrapper unit regression deliberately also
covers v0.62.0's absolute URL with origin-form `RequestURI`; live E2E keeps the
selected transport and never changes server request fields.
`TestAuthzRedirectRequestTargets` and `TestCaddyAuthorizationRedirectE2E` qualify
the host integration; see [authorization options](../../configuration-authorization/SKILL.md#policy-options).

| Upstream surface | Caddy integration and validation |
| --- | --- |
| `PortalConfig.CrossDeviceLogin`, `pkg/authn/cross_device/parser` | Aggregate portal statements preserve token boundaries and reject duplicate/conflicting settings, imports and nested blocks. Unit/adapt/resolution fixtures and `TestCaddyCrossDevice*` exercise real Caddy TLS, QR/copy Chrome flows, MFA/refresh/OP, signed OAuth/SAML, expiry, revocation and restart. The library owns all transfer runtime and embedded assets. |
| `Config.Logging`, `pkg/logging`, `pkg/logging/parser` | Root `logging` preserves typed rules and delegates parsing/validation. AuthCrunch component filters are instance-owned; built-command tests qualify scope, reload, removal and persistent sessions. Caddy v2.11.7's private authentication logger lacks a supported wrapping hook, so issue #280 remains open. See [configuration-logging](../../configuration-logging/SKILL.md). |
| `Config.State`, `pkg/state/parser` | Root `state` adapter delegates grammar and preserves library JSON. Persistent runtime construction occurs in Start; Caddy rejects overlapping persistent reload before candidate route startup. `TestCaddyRuntimeStateE2E` qualifies built-command restarts, storage/capacity failures and revocation. See configuration-state. |
| `PolicyConfig.OAuth`, `pkg/authz/oauth/parser` | Complete `use oauth`/`oauth` statements select portal-free provider login. The new authorization route handler preserves all three outcomes; parser/adapt, response-contract and built-command tests cover the host boundary. |
| `pkg/authchal`, `pkg/authn/transformer` | Complete transform blocks use the shared parser. Conditional replacement, additive legacy requirements, field existence, `match any`, typed custom/nested claims and deletion are exposed. Static local users accept repeated rule bodies. Unit/adapt/resolution tests and `TestCaddyAuthenticationChallengesE2E` cover actual selection and rejection. |
| `pkg/ids/local`, `pkg/identity`, `pkg/requests`, `pkg/user` | Static users map through exported local-store types; inventory stays server-owned. Deleting a required factor leaves stored rules in force and fails login closed; administrative replacement permits deliberate recovery. `TestCaddyLocalIdentityE2E` verifies password/MFA lifecycle and credential-version invalidation; the challenge E2E adds stored rule creation/replacement/omission and profile policy reset. The Caddy local CLI continues to use public admin operations. |
| `pkg/identity/password`, `pkg/identity/password/parser` | Argon2id v19 and strict bcrypt imports already pass through the local-user adapter; `TestPasswordImport*` qualifies preservation and malformed provisioning. The existing offline generator exposes `--algorithm argon2` through the shared parser/constructor. `TestCaddyPasswordArgon2E2E` builds the actual binary and qualifies HTML/native/Basic login, restart/overwrite, public profile/registration rejection and refresh revocation. See [password hashing](../../configuration-users/references/password-hashing.md). |
| `pkg/authn` profile handlers | Existing profile routes expose flow preview and atomic rule replacement. The challenge E2E verifies owner binding, rejected candidates, reauthentication and stale refresh/profile rejection. No new enable directive is needed. See [authentication flows](../../authentication-portal-api/references/authentication-flows.md). |
| `pkg/authn` sandbox, direct login, refresh | Password/TOTP/U2F-only flows, authoritative AMR and fresh policy checks remain upstream-owned. Challenge, local-identity and token-refresh E2E exercise HTML/JSON/native flows through verified TLS. A valid API key cannot bypass an explicit password policy; Basic cannot bypass a selected factor. |
| `pkg/acl`, `pkg/authz`, `pkg/authproxy` | `amr` is a list field accepted by rules and shortcuts. Existing Caddy authz delegation preserves path checks, accepted-token stripping and clearing configured claim headers before bypass/deny. Authorization-path and composed portal/resource E2E validate the route boundary; challenge E2E verifies factor-specific access. |
| `pkg/oidc` including shared parsers | Existing named application and provider wrappers expose `request_object_key`, `request_object_signing_alg`, `acr`, `refresh lifetime`, `max refresh tokens` and the expanded scopes. Relying-party capability E2E verifies signed requests, claims, ACR and rotating refresh. Challenge E2E additionally verifies factor-only AMR in independently checked ID tokens. Current policy is reevaluated in OP and backchannel contexts. |
| `pkg/idp` OAuth and SAML | Shared OAuth parsing and existing SAML mapping remain current. Nonce/signature/redirect hardening comes through library delegation. OAuth and composition E2E retain origin, callback, signature and role boundaries. The SAML session cookie is already exposed by the shared cookie parser and covered by cookie/composition tests. |
| `pkg/authn/cookie` | Existing shared parser exposes `cookie saml session id name`; prefix, uniqueness, scope and cleanup rules use the library factory. `cookie cross-device session id name` is also exposed by v1.3.11; naming it does not enable cross-device login. |
| `pkg/authn` UI/assets and OIDC pages | Embedded themed UI, SVG profile assets, same-origin consent policy and redirect/MFA rendering fixes are consumed automatically. `theme basic` is still the only registered theme. Existing browser refresh and OIDC E2E check the delivered pages and flow; do not invent light/dark Caddy directives. |
| `pkg/authclient` | The standalone authenticator uses the public client; factor-only password/TOTP behavior is covered by challenge E2E, with native transport/API-key interoperability in the existing client suite. WebAuthn requires an assertion-capable client. |
| `pkg/util` | Randomness and supporting hardening are inherited by portal/session/key operations. Existing key, refresh, registration and client E2E exercise these consumers; Caddy has no replacement random source. |
| `pkg/httpserver`, standalone executables | The new standalone authdb HTTP host has its own lifecycle/configuration. Caddy already owns listeners, TLS, routes and app lifecycle. Its parser/directives are not Caddy syntax and are not duplicated here. |
| Upstream tests, automation, release metadata, CodeQL exceptions | Reviewed as evidence and maintenance changes, not application grammar. Do not port sibling suppressions automatically, run sibling suites, or describe upstream-only evidence as a Caddy test. |

The LDAP fallback correction is also covered here: `fallback roles` now retains
its first value, and a disposable LDAPS peer proves service bind, user bind,
JWT roles and protected-resource access. Repeated directives replace the list.

## Unconditional matching

Selected v1.3.11 evaluates `match any` independently of timestamp presence.
The generated ACL evaluator reaches an always-true condition even when `exp`
is absent. This applies both to default authorization rules over normalized
users and to portal transforms over untimed backend identity claims.

Caddy accepts these transforms with portal refresh, OIDC and System API keys.
Do not inject synthetic timestamps or rewrite policy in the host.
`TestPortalTransformMatchAnyIdentityContext` and
`TestPortalTransformMatchAnyEncoding` cover timestamp-free evaluation and
quoted/runtime-resolved native JSON. The challenge TLS journey applies the
same unconditional factor policy during login, refresh and OIDC, checks renewed
claims, and still rejects unsatisfied Basic authentication. System API E2E
checks encrypted password assertions, unconditional claims and denial when
policy requires an unproved TOTP factor. Malformed multiline instructions still
fail resolution before CSV decoding, preserving the active deployment.
See [transform semantics](../../configuration-authentication-user-transforms/SKILL.md#unconditional-matching)
and [ACL ordering](../../configuration-authorization/references/typed-acl-fields.md#default-action-ordering).

## Syntax qualification

Follow [syntax maintenance](syntax-maintenance.md) for the complete ownership
map and audit procedure. Inventory standalone Caddyfiles,
production `Syntax:` comments, Markdown Caddyfile fences and Go inline inputs
when their grammar or selected dependency changes.
Classify complete examples, contextual fragments, alternative catalogues,
intentional failures and external-resource requirements before adapting them.

Review intentional-failure fixtures beyond their first expected error: a
missing external module or misplaced brace can hide stale grammar in later
blocks. `TestIdentityStoreSecretsFixture` checks the local-user block even when
the optional external secrets plugin is absent. Keep provider declarations in
the parsed scope and verify required `driver` and store/provider attachment.

Transform replacement preserves `{claims.*}` only in encoded transform
arguments. Recompile after replacement, reject empty arguments before encoding,
and keep the shared replacer unchanged. Reject CR/LF in native JSON transform
instructions before CSV decoding: its first-record reader can otherwise discard
a later matcher or challenge requirement before shared validation. This applies to Caddyfiles and native
JSON. Matchers and actions retain their upstream meaning; Caddy must not
substitute untrusted claims into policy selection itself.

Remaining distinctions:

- OAuth `logout_url` is still rejected by the shared IdP allowlist in v1.3.11;
  `enable logout` is supported. Keep the restriction documented and tested.
- Local static API keys have no `overwrite` suffix. Email authentication
  checkpoints are unsupported in both conditional-policy surfaces.
- Adaptation alone does not prove file loading, provider discovery, login or
  credential issuance. Operator examples have disposable runtime E2E. Provision
  an external-secrets fixture only with a binary containing its selected plugin
  and isolated synthetic storage; the ordinary binary intentionally lacks that
  optional module. External AWS examples require their module and backend;
  classify that dependency without contacting AWS or a real identity provider
  merely to qualify grammar.
- Historical official OP-plan reports remain tied to their recorded dependency
  and non-pass outcomes. The normal unit/E2E gate is separate from
  [official conformance](../../configuration-oauth-applications/references/oidc-conformance.md).

The [testing workflow](../../testing-and-ci/SKILL.md) owns the race-enabled
full suite, automation checks, build and reports. Keep audit manifests and raw
adapter diagnostics under this checkout's `tmp/`; they may include synthetic
credentials. Run skill metadata/link validation for documentation changes and
inspect the resulting diff. Use release/license regeneration only when its inputs changed;
a documentation-only review does not need broad source regeneration. Do not
raise the Caddy module's own release version as a side effect of a dependency
update.

## Qualification evidence

Record the selected module/version/replacement, candidate source hashes,
commands, original outcomes and artifact paths with each qualification run.
Keep regular unit/E2E and automation results separate from official conformance;
report intentional subprocess-helper skips and incomplete or interrupted runs
without promoting them to success. Focused follow-up checks qualify only the
changes and test surfaces they exercise, not a new full-suite result.

For syntax audits, retain the inventory and classification of complete examples,
contextual fragments, catalogues, expected rejections and external-resource
requirements. Verify optional-module fixtures with their actual selected plugin
before claiming runtime evidence. Keep manifests and raw diagnostics under this
checkout's `tmp/` and generated test reports under `.coverage/`; those ignored
artifacts are evidence for their recorded candidate, not portable proof for a
later checkout.
