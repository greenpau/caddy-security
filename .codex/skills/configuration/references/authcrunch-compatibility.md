# AuthCrunch compatibility through Caddy

## Selected implementation

Read `go.mod` and `go list -m -json github.com/greenpau/go-authcrunch` to
establish the selected version, module directory, and any replacement. This
checkout selects published v1.3.4; sibling source and integrated xcaddy build
arguments can select different code and are not proof of the normal build's
behavior. Record that distinction in qualification evidence. A dependency task
must inspect the Makefile xcaddy argument and CONTRIBUTING examples separately.

The table maps supported upstream surfaces to their Caddy host boundaries. Grammar details remain in the owning skills; do not copy the standalone
AuthCrunch HTTP server's configuration into Caddy's app or routes.

## Integration surfaces and evidence

| Upstream surface | Caddy integration and validation |
| --- | --- |
| `Config.Logging`, `pkg/logging`, `pkg/logging/parser` | Root `logging` preserves typed rules and delegates parsing/validation. AuthCrunch component filters are instance-owned; built-command tests qualify scope, reload, removal and persistent sessions. Caddy v2.11.4's private authentication logger lacks a supported wrapping hook, so issue #280 remains open. See [configuration-logging](../../configuration-logging/SKILL.md). |
| `Config.State`, `pkg/state/parser` | Root `state` adapter delegates grammar and preserves library JSON. Persistent runtime construction occurs in Start; Caddy rejects overlapping persistent reload before candidate route startup. `TestCaddyRuntimeStateE2E` qualifies built-command restarts, storage/capacity failures and revocation. See configuration-state. |
| `PolicyConfig.OAuth`, `pkg/authz/oauth/parser` | Complete `use oauth`/`oauth` statements select portal-free provider login. The new authorization route handler preserves all three outcomes; parser/adapt, response-contract and built-command tests cover the host boundary. |
| `pkg/authchal`, `pkg/authn/transformer` | Complete transform blocks use the shared parser. Conditional replacement, additive legacy requirements, field existence, `match any`, typed custom/nested claims and deletion are exposed. Static local users accept repeated rule bodies. Unit/adapt/resolution tests and `TestCaddyAuthenticationChallengesE2E` cover actual selection and rejection. |
| `pkg/ids/local`, `pkg/identity`, `pkg/requests`, `pkg/user` | Static users map through exported local-store types; inventory stays server-owned. Deleting a required factor leaves stored rules in force and fails login closed; administrative replacement permits deliberate recovery. `TestCaddyLocalIdentityE2E` verifies password/MFA lifecycle and credential-version invalidation; the challenge E2E adds stored rule creation/replacement/omission and profile policy reset. The Caddy local CLI continues to use public admin operations. |
| `pkg/authn` profile handlers | Existing profile routes expose flow preview and atomic rule replacement. The challenge E2E verifies owner binding, rejected candidates, reauthentication and stale refresh/profile rejection. No new enable directive is needed. See [authentication flows](../../authentication-portal-api/references/authentication-flows.md). |
| `pkg/authn` sandbox, direct login, refresh | Password/TOTP/U2F-only flows, authoritative AMR and fresh policy checks remain upstream-owned. Challenge, local-identity and token-refresh E2E exercise HTML/JSON/native flows through verified TLS. A valid API key cannot bypass an explicit password policy; Basic cannot bypass a selected factor. |
| `pkg/acl`, `pkg/authz`, `pkg/authproxy` | `amr` is a list field accepted by rules and shortcuts. Existing Caddy authz delegation preserves path checks, accepted-token stripping and clearing configured claim headers before bypass/deny. Authorization-path and composed portal/resource E2E validate the route boundary; challenge E2E verifies factor-specific access. |
| `pkg/oidc` including shared parsers | Existing named application and provider wrappers expose `request_object_key`, `request_object_signing_alg`, `acr`, `refresh lifetime`, `max refresh tokens` and the expanded scopes. Relying-party capability E2E verifies signed requests, claims, ACR and rotating refresh. Challenge E2E additionally verifies factor-only AMR in independently checked ID tokens. Current policy is reevaluated in OP and backchannel contexts. |
| `pkg/idp` OAuth and SAML | Shared OAuth parsing and existing SAML mapping remain current. Nonce/signature/redirect hardening comes through library delegation. OAuth and composition E2E retain origin, callback, signature and role boundaries. The SAML session cookie is already exposed by the shared cookie parser and covered by cookie/composition tests. |
| `pkg/authn/cookie` | Existing shared parser exposes `cookie saml session id name`; prefix, uniqueness, scope and cleanup rules use the library factory. No new cookie role is missing. |
| `pkg/authn` UI/assets and OIDC pages | Embedded themed UI, SVG profile assets, same-origin consent policy and redirect/MFA rendering fixes are consumed automatically. `theme basic` is still the only registered theme. Existing browser refresh and OIDC E2E check the delivered pages and flow; do not invent light/dark Caddy directives. |
| `pkg/authclient` | The standalone authenticator uses the public client; factor-only password/TOTP behavior is covered by challenge E2E, with native transport/API-key interoperability in the existing client suite. WebAuthn requires an assertion-capable client. |
| `pkg/util` | Randomness and supporting hardening are inherited by portal/session/key operations. Existing key, refresh, registration and client E2E exercise these consumers; Caddy has no replacement random source. |
| `pkg/httpserver`, standalone executables | The new standalone authdb HTTP host has its own lifecycle/configuration. Caddy already owns listeners, TLS, routes and app lifecycle. Its parser/directives are not Caddy syntax and are not duplicated here. |
| Upstream tests, automation, release metadata, CodeQL exceptions | Reviewed as evidence and maintenance changes, not application grammar. Do not port sibling suppressions automatically, run sibling suites, or describe upstream-only evidence as a Caddy test. |

The LDAP fallback correction is also covered here: `fallback roles` now retains
its first value, and a disposable LDAPS peer proves service bind, user bind,
JWT roles and protected-resource access. Repeated directives replace the list.

## Upstream match-any limit

The selected v1.3.4 retains a library limitation covered by Caddy TLS regression:
`match any` actions appear in access-only login but disappear when portal
refresh rebuilds identity claims. Source tracing also finds the same input
shape in the OIDC identity verifier. `pkg/acl/condition.go` implements
`match any` using the `exp` field, and `pkg/acl/rule.go` checks that the field
exists before calling the always-match condition.
`pkg/authn/token_refresh_runtime.go:WithIdentity` and
`pkg/authn/oidc_runtime.go:WithIdentity` omit timestamps while applying
transforms. The encrypted System API path in
`handle_api_system.go:respondSystemAuthentication` also passes untimed claims.
This can skip policy as well as ordinary claim actions.

Caddy rejects this combination at runtime resolution, before creating a new
runtime or displacing a working deployment. The guard covers Caddyfiles and
native JSON, either enabled renewable feature or System API key usage, and
normalized/resolved matcher arguments, including a native JSON condition encoded
as one quoted `"match any"` argument. Compare the decoded ACL meaning, not the
serialized spelling. Shared KMS parsing identifies key usage;
raw key material is never treated as a usage keyword. Absent/disabled renewable
features still permit `match any` when no System API key is present. Use explicit
realm matchers for refresh/OIDC/System API configurations. This is an upstream compatibility restriction,
not full support for unconditional matching across those features.

Separate upstream work is required: make unconditional ACL evaluation independent
of token timestamp presence, and qualify refresh/OIDC/System API policy checks with
untimed fresh identity maps. Do not add fictitious timestamps or relax completed
factor checks in the host to hide the problem.
`TestPortalTransformMatchAnyIdentityContext` records the library behavior so an
upstream fix forces this restriction to be reconsidered. The Caddy E2E verifies
safe access-only matching, stable realm-based claims, and rejected replacement
without losing the active refresh/OIDC session. The encrypted System API E2E
verifies password assertions and transformed claims, rejection of the unsafe
replacement, and denial when realm-based policy requires a TOTP proof.

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

- OAuth `logout_url` is still rejected by the shared IdP allowlist in v1.3.4;
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
