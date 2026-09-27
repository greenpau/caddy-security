# Direct OAuth authorization

Read this reference for policy-owned external OAuth sessions without a portal.
JWT policy defaults do not apply to this mode.

## Direct OAuth Without a Portal

Select one configured OAuth identity provider inside a policy:

```caddyfile
authorization policy app_policy {
	use oauth identity provider upstream
	oauth public origin https://app.example.test
	oauth base path /private/oauth
	oauth session cookie name __Host-APP_SESSION
	oauth login cookie name __Host-APP_LOGIN
	oauth session lifetime 900
	oauth maximum sessions 10000
	oauth maximum pending logins 1024
	validate method path
	allow roles authp/user
}
```

The provider is an ordinary `oauth identity provider upstream` declaration.
Use [configuration-oauth-providers](../../configuration-oauth-providers/SKILL.md)
to configure its credentials and protocol settings. No portal, local store or JWT key
is required. The shared `pkg/authz/oauth/parser` owns all `use oauth` and `oauth`
statements. Collect the complete set before calling `ConfigureOAuth`; duplicates,
unknown fields, empty tokens, extra arguments and nested blocks fail. Quoted
values retain their token boundaries. `{$VARIABLE}` expands during adaptation;
`{env.*}` and `secrets:<manager>:<key>` resolve during provisioning. If any OAuth
statement contains a runtime reference, the complete list is retained as
`oauth_authorization_directives[POLICY]` in Caddy JSON. Resolution substitutes
each original token once and then invokes the shared parser once, preserving
duplicate detection. Do not also supply typed `oauth` for that policy. Native
JSON `oauth` string fields support replacement; numeric fields remain numbers.
The named provider retains its existing independent secret-resolution workflow.
Providers may appear before or after policies; root validation resolves names.

Only provider selection is required. Omitted base path defaults to
`/_authcrunch/oauth2/POLICY`; cookie names to `AUTHZ_POLICY_SESSION` and
`AUTHZ_POLICY_LOGIN`. Session lifetime is absolute, 1–86400 seconds (default
900), with no sliding renewal or upstream refresh. Session/pending capacities
are 1–65536 (defaults 10000/1024); explicit zero is invalid. Policy names use
1–128 ASCII letters, digits, underscores or hyphens. Public origin, if supplied,
must be HTTPS without credentials, query, fragment or a non-root path. Without
it, incoming requests need TLS and trusted Host routing. Behind TLS termination,
pin the external origin and preserve Host through a trusted proxy.

Mount the whole base namespace through the same policy as the application:
the GET callback is `BASE/authorization-code-callback`; same-origin POST
`BASE/logout` revokes the local session. With the example base, a
`route /private/* { authorize with app_policy ... }` covers both. Do not strip
the base path, bypass callbacks, accept provider tokens as app credentials,
or synthesize callback success. Callbacks retain state, browser, origin, nonce,
PKCE and replay checks in AuthCrunch. Cookies are host-only, root-path, Secure,
HttpOnly and SameSite=Lax; duplicate/invalid credentials fail closed.

The verified identity receives `authp/user` plus provider roles. Allowing that
baseline grants every account accepted by the provider. AuthCrunch never creates
`authp/admin`. Replace a broad `allow roles authp/user` with a narrower rule,
for example inside the policy:

```caddyfile
acl rule {
 match roles authp/user
 match email alice@example.com
 allow stop
}
```

This requires both the baseline role and the exact email, with default denial
for other identities. Provider-specific roles can narrow access too, when the
provider actually supplies them. No portal transform adds roles in this mode.
Every session request reevaluates current ACLs, including method/path and source
address checks. Use
`validate method path` for resource restrictions: generic provider identities
do not carry token path grants required by `validate path acl`.
Direct policies do not apply portal transforms/MFA/profile/refresh/OP features.
They cannot mix JWT crypto, bearer validation, token sources, auth proxies or
portal cookie-name settings. Existing JWT policies keep those features.

`authorize` adapts to `http.handlers.authorization`. Its three-outcome wrapper
runs downstream only for `Authorized` or `Bypassed`; handled redirects,
callbacks, logout and denials retain status/headers/body, including capacity
503s. Unhandled authentication errors deny and retain the
`{http.auth.authorizer.error}` placeholder for existing `handle_errors` routes.
App admission failures retain their 503 status through Caddy's error helper.
The legacy JSON authenticator
`http.authentication.providers.authorizer` remains available, but Caddy's
generic authentication chain cannot preserve handled OAuth responses; use the
new handler for direct policies and regenerate old adapted route JSON.

Without state, completed sessions and pending exchanges disappear at restart.
[Persistent runtime state](../../configuration-state/SKILL.md) retains completed
sessions and revocations across stop/start; pending exchanges still disappear.

## LinkedIn and route deployment

Use [`assets/config/integration/direct-oauth.Caddyfile`](../../../../assets/config/integration/direct-oauth.Caddyfile)
for the complete issue #460 shape. Register exactly
`https://app.example.com/_authcrunch/oauth2/linkedin_oauth_policy/authorization-code-callback`
at the provider. The site's hostname matcher constrains callback origin selection.
Do not expose a wildcard host that permits arbitrary Host values. `oauth public
origin https://app.example.com` pins that origin for trusted TLS termination;
the proxy must preserve the same external Host. X-Forwarded-Host and
X-Forwarded-Proto never select direct OAuth callback origins. Existing Caddy
trusted-client-IP normalization still applies. This is an application route,
not an arbitrary forwarded-target authentication service.

Whole-site authorization naturally mounts callback and logout. For a restricted
application, place `oauth base path /app/oauth` inside a route covering `/app/*`,
or explicitly mount the default namespace through the same named policy. Do not
use `handle_path` to strip the namespace. AuthCrunch reserves all descendants
before bypass evaluation and rejects unsupported/encoded endpoint aliases.
Callback and original return URI path/query bytes must reach the library intact.

LinkedIn keeps its existing UserInfo driver behavior, including disabled nonce
and PKCE in that named driver. Generic OIDC defaults to both checks enabled.
The consumer's generic TLS/Chrome fixture is not a live LinkedIn test or a new
LinkedIn security guarantee. AuthCrunch's separate synthetic named-driver
fixture tunnels the fixed UserInfo host locally and is library evidence only.

Only the configured opaque session cookie authenticates the direct policy.
Portal JWTs, upstream tokens, bearer/query copies of sessions, Basic credentials
and API keys do not. Cookies and transactions are policy-local and origin-bound.
Logout accepts same-origin POST, revokes local session and pending/in-flight
login, and does not log out of the upstream provider. One login is active per
browser/policy; replacement, cancellation and expiry release provider state.
Custom provider wrappers must retain `CancelLogin` as well as `IdentityProvider`.

Without root state, reload/restart discards sessions and pending logins; multiple
instances require sticky routing. Persistent completed-session support follows
the separate stop/drain/close-before-open contract, with pending logins always
volatile. No profile UI, local MFA, transforms, refresh or downstream OP exists
in a direct policy.

## Consumer validation

The selected AuthCrunch v1.3.6 already contains the direct OAuth APIs.
`TestAuthorizationOAuth*` and `TestParseAuthorizationOAuth` cover complete
statement parsing, token boundaries, runtime secrets, JSON restoration, root
provider references, and collisions. `testcase_authorize_oauth` is registered
for both adapted and runtime-resolved JSON comparison. The built-Caddy
`TestCaddyDirectOAuthE2E` uses a local TLS generic provider with independently
signed assertions and a counted TLS protected upstream. It checks redirects,
callbacks, identity metadata, replay, wrong-browser/origin transplants, malformed
assertions, namespace/method rules, ACLs, cookie stripping, capacity, absolute session expiry, the fixed 300-second pending expiry,
logout cancellation, shared-provider policy isolation and volatile reload.
The custom-origin case also completes login through plaintext backend requests
with the external Host preserved; the unpinned case rejects those requests.
Chrome independently checks the Secure/HttpOnly/Lax cookie journey with private
CA trust and an invalid-certificate negative control. The fixture main changes
only the private trust pool; the command, app and handlers are production Caddy.
`TestAuthorizationHandlerAdmissionAndDrain` checks retained handlers and single
request admission through downstream completion; `TestAuthzResponseContract`
checks ordinary JWT/error compatibility.

Run the focused selection, then `make ci-check`. Separately built command
processes do not contribute to the Go parent coverage profile; the focused unit
and existing instrumented Caddy tests provide that coverage.
