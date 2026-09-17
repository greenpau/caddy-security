# Composed Caddy security qualification

Use this suite when changing the interaction between portal login, refresh,
downstream OIDC, upstream OAuth, authorization, edge metadata, or Caddy reload.
The selected dependencies are Caddy v2.11.4 and go-authcrunch v1.2.5; these tests
run in caddy-security, without running or modifying sibling repositories.

```sh
go test -mod=readonly -race -count=1 -parallel=4 -timeout=10m \
  -run 'TestSecurityRequestMetadata|TestAuthzResponseContract|TestAuthzPathDelegation|TestCaddyCompositionE2E|TestCaddyTokenRefreshBrowserE2E' .
```

`TestCaddyCompositionE2E` starts a bounded child process so Caddy global state,
test TLS roots, and logging remain isolated. Feature configurations are adapted
from Caddyfiles and loaded with `caddy.Load`. HTTP clients verify the fixture
certificate. Tests use two local realms, private named registrations, independent
portal/OP keys, an actual TLS OAuth provider, and a counted protected upstream.
The protected route within each cookie scope runs before portal dispatch, so
ordinary browser cookies must authorize a real upstream as well as bearer JWTs.
No OP key is added to a portal verification set to make a JWT test pass.

## Coverage map

| Surface | Evidence |
| --- | --- |
| Features absent, independently enabled, combined | `composition_e2e_test.go`: upstream OAuth, named applications, OP, refresh, and custom cookie names; real local login, signed RP exchanges, refresh and upstream calls |
| Authorization result translation | `TestAuthzResponseContract`: independently calls `Gatekeeper.Authenticate` and the Caddy wrapper; checks error, authorized/bypassed flags, handled status and absence of denied user metadata |
| Denial routing | Missing/invalid credentials with redirects disabled and a closed gatekeeper through Caddy TLS; explicit status, no-store, response marker and upstream request count. Nil gatekeeper error alone is not authorization |
| Credential purposes | OIDC ID token and opaque UserInfo token rejected by portal/resources; portal JWT rejected by UserInfo; distinct public key sets |
| OAuth trust | Actual callback with retained issuer and supplemental access audience validation; invalid supplemental claims cannot add roles; upstream login remains access-only |
| Realm replacement | Browser JSON password challenges with one slot in each portal component, cross-realm replacement, old family/grant rejection, strict spent-token replay, active-cookie and legacy-path deletion, default/custom names |
| Completion failure | OP-only session occupies the single OP slot; local refresh issuance then OP-full completion returns 503 without credentials; logout releases the OP slot and a new login rotates successfully, proving refresh capacity was reclaimed |
| Current identity | Admin API role overwrite followed by refresh; freshly signed claims contain current roles and authorization denies the removed grant |
| Two issuers | Independent hosts, mounts, keys and cookies, successful login/exchange at each issuer, bidirectional copied bearer/renamed refresh and OP-cookie denial, and both runtimes invalidated on replacement |
| Edge | `composition_edge_e2e_test.go`: direct TLS, untrusted hostile/duplicate hints, real TLS proxy, Caddy `trusted_proxies_strict`, alternate `client_ip_headers`, retained Origin/issuer/TLS checks, raw/encoded and look-alike paths |
| Reload | Missing-key candidate fails without displacing active grants/families; successful replacement preserves immutable registration bytes and key files, invalidates refresh/OP grants and unredeemed codes, and still verifies compatible stateless access JWTs |
| Disposal | `composition_lifecycle_e2e_test.go`: two bounded requests held inside real AuthCrunch calls; replacement serves while old cleanup waits; released old refresh responses do not create authority in the new runtime |
| Browser | The `composition` scenario in `testdata/browser/token_refresh_browser_e2e.cjs`, driven through Chromium/CDP, reuses the existing task-12 browser coordinator: two-tab rotation, realm/OP-cookie replacement at capacity, committed-response loss without retry/lookup recovery, fresh login, logout, HttpOnly privacy and legacy-path cleanup |

The existing `TestCaddyTokenRefreshBrowserE2E` also runs default root, custom
nested, and expired-access continuation scenarios. Chrome/Chromium and Node 24
remain required; missing prerequisites fail rather than skip. Browser trust is
limited to the generated fixture certificate's SPKI. Protocol clients and the
TLS proxy retain normal certificate verification.

Failure responses are checked for no-store and credential redaction. The
composition fixture captures issued credentials (including upstream codes and
tokens) for INFO-and-higher log checks, and checks that private stored
registrations do not appear in adapted JSON. Test probes hold or cut real
responses; they do not mint authentication evidence. Ordinary correlation
session IDs may be logged; they are distinct from credential-bearing OIDC
session cookies, which remain included in redaction checks.

`TestCaddyJWKSPersistenceE2E` separately checks persisted portal keys across
process restarts and live retirement. Its post-reload discovery probes close
cached idle connections first so they target the replacement HTTP server;
they never retry a failed request. Transport diagnostics omit URLs and headers.

## Limits that must remain explicit

This suite does not certify DEBUG log redaction. The selected go-authcrunch
v1.2.5 OAuth implementation, `pkg/idp/oauth/authenticate.go`, logs callback
code/state and the raw token response at DEBUG before identity validation.
That upstream logging needs separate remediation; enabling DEBUG can disclose
credentials even when the subsequent login fails. Do not describe the
INFO-level qualification as an all-level no-secret logging guarantee.

The edge tests cover forwarded IPv4 and a compressed IPv6 address. The
dependency also misparses some other forwarded IPv6 representations; see the
[edge trust limit](../../configuration-http-integrations/SKILL.md#edge-trust).
Direct peers retain `RemoteAddr`, avoiding that forwarded-parser regression.

Refresh and OP completion are separate component operations, not a general
transaction. The tested completion failure cleans up the newly issued refresh
family, but that does not promise rollback of an earlier account replacement,
external effects, or arbitrary failures in every component. Browser uncertainty
after a committed response is handled by fresh login, never replay or lookup.

These are single-process stores and lifecycle guarantees. Refresh families,
OP sessions, pending requests, codes and grants are volatile across replacement
or restart. They are not shared between active instances. Private registration
revisions and configured signing-key files survive independently. Compatible
access JWTs remain valid until their normal expiry/policy boundary.

The reload fixtures use `:memory:` users to avoid overlapping writers. Recreated
users can have different internal IDs and downstream subjects after replacement;
this suite does not promise persistent user identity. Live reload over the same
local user file remains rejected by the
[runtime ownership restriction](../../coding-directives/references/runtime-lifecycle.md#persistent-identity-files-current-reload-restriction).
Caddy publication is not a transaction across all apps or external side effects;
cleanup errors do not roll back a deployment that is already serving.

The upstream reference tests are `server_composition_e2e_test.go`,
`server_oauth_composition_e2e_test.go`, `server_lifecycle_e2e_test.go`, and
`pkg/authn/token_refresh_completion_e2e_test.go`. Its coding skill's
`references/embedding-integration.md` describes the host contract. Those are
read-only references, not substitutes for this Caddy suite or permission to run
sibling automation.
