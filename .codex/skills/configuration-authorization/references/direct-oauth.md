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
unknown fields, extra arguments and nested blocks fail. Use `{$VARIABLE}` for
these statement values; restricted origin/path/numeric values are validated
during adaptation and do not defer `{env.*}` resolution.

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
baseline grants every account accepted by the provider; choose narrower ACLs
when needed. Every session request reevaluates current ACLs. Use
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
