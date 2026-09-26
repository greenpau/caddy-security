# AuthCrunch compatibility through Caddy

## Selected implementation

The supported dependency is published `github.com/greenpau/go-authcrunch v1.3.4`,
commit `a97ff2f0a4429e286c30b9cc0cd6babab109b964`, without a local replacement.
The review baseline is `7b890459d5eb3782d1df4f035e7920a3a3ed1c71` (v1.2.5).
Use `go list -m -json github.com/greenpau/go-authcrunch` to reestablish the
selected version and module directory before repeating this qualification.
The Makefile xcaddy pin and CONTRIBUTING commands must select the same release.

The table maps every changed upstream package family in that range to its host
boundary. Grammar details remain in the owning skills; do not copy the standalone
AuthCrunch HTTP server's configuration into Caddy's app or routes.

## Changed surfaces and evidence

| Upstream surface | Caddy integration and validation |
| --- | --- |
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

A real Caddy TLS regression found an unresolved v1.3.3 library limitation:
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
factor checks in the host to hide the problem. No sibling files were changed.
`TestPortalTransformMatchAnyIdentityContext` records the library behavior so an
upstream fix forces this restriction to be reconsidered. The Caddy E2E verifies
safe access-only matching, stable realm-based claims, and rejected replacement
without losing the active refresh/OIDC session. The encrypted System API E2E
verifies password assertions and transformed claims, rejection of the unsafe
replacement, and denial when realm-based policy requires a TOTP proof.

## Syntax qualification

Follow [syntax maintenance](syntax-maintenance.md) for the complete ownership
map and audit procedure. This update inventories all standalone Caddyfiles,
production `Syntax:` comments, Markdown Caddyfile fences and Go inline inputs.
Classify complete examples, contextual fragments, alternative catalogues,
intentional failures and external-resource requirements before adapting them.

Two previously hidden fixture errors illustrate why failure fixtures also need
source review: an extra brace in the portal parser test made its later LDAP,
SAML and OAuth declarations unreachable, and the external-secrets fixture's
expected missing-module error concealed obsolete local API-key syntax. The
portal test now parses all declarations with `driver` and correct store/provider
attachment. `TestIdentityStoreSecretsFixture` checks the local-user block even
when the optional external secrets plugin is absent.

Transform replacement preserves `{claims.*}` only in encoded transform
arguments. Recompile after replacement, reject empty arguments before encoding,
and keep the shared replacer unchanged. Reject CR/LF in native JSON transform
instructions before CSV decoding: its first-record reader can otherwise discard
a later matcher or challenge requirement before shared validation. This applies to Caddyfiles and native
JSON. Matchers and actions retain their upstream meaning; Caddy must not
substitute untrusted claims into policy selection itself.

Remaining distinctions:

- OAuth `logout_url` is still rejected by the shared IdP allowlist in v1.3.3;
  `enable logout` is supported. Keep the restriction documented and tested.
- Local static API keys have no `overwrite` suffix. Email authentication
  checkpoints are unsupported in both conditional-policy surfaces.
- Adaptation alone does not prove file loading, provider discovery, login or
  credential issuance. Operator examples have disposable runtime E2E. The static-secrets fixture was
  also adapted and provisioned in isolated storage using a separate binary with
  `caddy-security-secrets-static-secrets-manager v1.0.1`; the ordinary binary
  intentionally lacks that optional module. External AWS examples require their
  module and backend; do not contact AWS to establish grammar. Never contact a
  real identity provider just to qualify grammar.
- Historical official OP-plan reports remain tied to their recorded dependency
  and non-pass outcomes. The normal unit/E2E gate is separate from
  [official conformance](../../configuration-oauth-applications/references/oidc-conformance.md).

Use the [testing workflow](../../testing-and-ci/SKILL.md) for the race-enabled
full suite, automation checks, build and reports. Keep audit manifests and raw
adapter diagnostics under this checkout's `tmp/`; they may include synthetic
credentials. Run skill metadata/link validation and `make license`, then inspect
the resulting diff. Do not raise the Caddy module's own release version as a
side effect of this dependency update.


## Qualification evidence for this update

The initial v1.3.3 `make ci-check` qualification passed version validation, all 33 automation
tests, the complete race-enabled Go suite, and both binary builds. Go reported
1,908 passed, zero failed, 23 subprocess-helper skips and zero incomplete entries;
weighted profile coverage was 84.39%. Parent E2E tests exercised those helpers,
including actual Caddy TLS, encrypted System API, LDAPS, signed WebAuthn,
local-identity mutations, operator examples, OIDC and real Chrome refresh.

A follow-up review reproduced and fixed two native JSON validation gaps:
quoted/resolved unconditional matchers could escape the compatibility guard,
and CSV decoding could discard later lines before transform validation.
The focused race suite passed transform unit tests, Caddyfile adaptation,
runtime resolution and actual Caddy challenge/reload E2E after both fixes.
Those E2E checks preserve working resource access, refresh/OIDC sessions and
encrypted System API assertions after rejected replacements. `go vet ./...`,
module verification and both binary builds also passed. The full-suite counts
above describe the initial qualification; the follow-up uses the focused suite.

The final syntax inventory contains 51 standalone Caddyfiles and 102 Markdown
fences, with 117 regular contextual adaptations plus five using the optional
static-secrets plugin. Intentional rejections, catalogues and the AWS backend
requirement remain separately classified. Seventeen changed skills passed
frontmatter, metadata, invocation and link/anchor checks. `make license`, module
verification and diff/format checks passed. Earlier failures and interrupted
runs were retained separately; none were relabeled as successful.

Local evidence is preserved in `.coverage/authcrunch-v1.3.3-complete/` and
`tmp/authcrunch-v133/qualification.md`, including the source hashes and syntax
manifests. Follow-up evidence is in `tmp/authcrunch-v133/review-qualification.md`.
These generated paths are ignored and do not ship with the module;
repeat the documented workflows to establish evidence for a later checkout.
