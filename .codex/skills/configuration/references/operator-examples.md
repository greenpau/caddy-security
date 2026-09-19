# Qualified operator configurations

The complete server inputs in `assets/config/integration/` use this module's
outer `{ security { ... } }` syntax and Caddy HTTP routes. They are not library
body fragments. `TestCaddyOperatorExamplesE2E` adapts each input, calls Caddy
validation/provisioning, starts verified TLS listeners and a protected upstream,
then repeats the journey by loading the complete generated native JSON.

| Caddyfile | Journey |
| --- | --- |
| `legacy-access.Caddyfile` | Password/JSON access-token login in three realms, Bearer authorization, refresh/OP absent, private export denied. |
| `local-token-refresh.Caddyfile` | Two eligible local realms, an attached unselected guest realm, default cookies, browser rotation and opted-in native body transport. |
| `upstream-oauth.Caddyfile` | Real upstream OAuth callback with static Ed25519 public keys, explicit issuer and supplemental access-token audience; wrong issuer fails and wrong supplemental audience cannot add roles. |
| `named-applications.Caddyfile` | Load a durable confidential registration and declare a public PKCE client; declaring applications alone does not enable an OP. |
| `oidc-token-refresh.Caddyfile` | Independent `/auth` and `/other` providers, separate portal/OP keys, default/custom cookies, both local realms, unselected guests, consent and confidential/public S256 exchanges, UserInfo and token-purpose rejection. |
| `admin-private-export.Caddyfile` | Explicit administrative login and private export opt-in; the other five inputs leave export disabled. |

The upstream API uses Bearer portal access tokens. Portal cookies are scoped to
their mount; they are not sent to `/protected` outside it. Do not widen cookie
scope to make two issuers share credentials. Match exact mounts and their slash
children, keep `authorize` on resource routes, and preserve the original URL.
The combined example's resource policy trusts only the first portal's access
key. Give the second portal its own resource policy when those resources should
accept its access tokens; dedicated OP keys never belong in either policy.
The loopback bind and supplied certificate make these local operator examples;
change address, bind, certificate and public origins together for deployment.
`auto_https off` disables automatic certificate management, not HTTPS: every
site uses an explicit HTTPS origin and a supplied certificate/key.

## Private prerequisites

Run provisioning and Caddy as the same service account. Use physical absolute
paths: symlinks, including a symlink in an ancestor, are rejected for private
registration/key storage. The example environment selects:

| Variables | Meaning |
| --- | --- |
| `EXAMPLE_ORIGIN` | Canonical HTTPS origin, for example `https://localhost:8443`, without trailing slash. |
| `EXAMPLE_RESOURCE` | Reachable protected HTTP upstream, for example `127.0.0.1:8080`. |
| `EXAMPLE_TLS_CERT`, `EXAMPLE_TLS_KEY` | Existing certificate chain and matching key, trusted by clients; never use a TLS-bypass flag. |
| `EXAMPLE_EMPLOYEES_DB`, `EXAMPLE_CONTRACTORS_DB`, `EXAMPLE_GUESTS_DB` | Separate local identity database files. |
| `EXAMPLE_PASSWORD` | Private bootstrap password for the disposable `alice` examples; supply through the service's protected environment. Replace these bootstrap identities for deployment. |
| `EXAMPLE_LOG` | Private Caddy log path; examples use INFO and never log response bodies. |
| `EXAMPLE_ACCESS_KEY`, `EXAMPLE_ACCESS_PUBLIC_KEY` | Portal RSA signing key and its matching public verification key. |
| `EXAMPLE_SECOND_ACCESS_KEY` | Independent signing key for the second portal. |
| `EXAMPLE_REGISTRATION_STORE` | Existing private registration directory. |
| `EXAMPLE_OP_KEY`, `EXAMPLE_SECOND_OP_KEY` | Separate dedicated provider RSA keys from explicit provisioning. |
| `EXAMPLE_UPSTREAM_ORIGIN`, `EXAMPLE_UPSTREAM_CLIENT_ID`, `EXAMPLE_UPSTREAM_SECRET` | Upstream provider URL and separately registered RP credentials; its registered callback is `EXAMPLE_ORIGIN/auth/oauth2/upstream/authorization-code-callback`. |
| `EXAMPLE_UPSTREAM_IDENTITY_PEM`, `EXAMPLE_UPSTREAM_ACCESS_PEM` | Trusted upstream **public** Ed25519 PEM files for key IDs `identity` and `access`. Use the provider's real IDs/keys in deployment. |

Only supply variables referenced by the chosen input. `{$NAME}` is Caddyfile
environment substitution; `{env.NAME}` in the selected identity/user fields
is the module's runtime replacement. They are different stages. Keep the
environment private and disable shell tracing. No credentials or private PEMs
are committed in these examples. Adapted JSON and diagnostic artifacts remain
private even when their current content contains only credential references.

For exact credential **create, load, rotate and key rollover** commands, use
[private provisioning](../../configuration-oauth-applications/references/private-provisioning.md).
The executable commands are:

```sh
bin/authcrunch security oauth init provisioning store --config "$PRIVATE/oauth_store.Caddyfile"
APP_RECORD=$(bin/authcrunch security oauth create application \
  --config "$PRIVATE/oauth_client.Caddyfile" --name website --revision v1)
EXAMPLE_OP_KEY=$(bin/authcrunch security oidc create signing key \
  --config "$PRIVATE/oauth_store.Caddyfile" --name login --revision k1)
EXAMPLE_SECOND_OP_KEY=$(bin/authcrunch security oidc create signing key \
  --config "$PRIVATE/oauth_store.Caddyfile" --name second --revision k1)
NEW_RECORD=$(bin/authcrunch security oauth rotate secret \
  --config "$PRIVATE/oauth_rotate.Caddyfile" --name website --from v1 --revision v2)
NEXT_KEY=$(bin/authcrunch security oidc create signing key \
  --config "$PRIVATE/oauth_store.Caddyfile" --name login --revision k2)
```

These are separate operator steps, not one unconditional startup script.
`PRIVATE` is an existing trusted `0700` directory. Standalone provisioning
inputs must be `0600`, contain literal paths and exactly the documented store
and application blocks, and cannot use imports/environment expansion. For these
examples, register `https://rp.example.test/callback?registered=yes`. Generate
omitted credentials during creation; put an explicit new secret directly into
the private rotation input, not argv or stdout. Deliver credentials to the RP
through a private handoff file. Default PKCE and consent remain enabled.

Loading `registration v1` reads the existing record; there is no create-on-load.
Activate a rotation by deliberately selecting `registration v2`. There is no
dual-secret grace period. For OP rollover list the new key path first and the
retained old path second; both public keys remain in JWKS during the intended
overlap. Never add OP keys to portal JWT verification. Keep revisions/keys needed
for recovery. Commands print paths, not secret values. Caddy private-key export
is unrelated to provisioning and unnecessary for OIDC.

## Complete native JSON and execution

Generate each complete native Caddy JSON from its actual private registration
state. Do not copy a sample digest or hand-copy library provider bodies into
`apps.security.config`:

```sh
umask 077
bin/authcrunch adapt --adapter caddyfile --pretty \
  --config assets/config/integration/oidc-token-refresh.Caddyfile \
  > "$PRIVATE/native.json" 2> "$PRIVATE/adapt.log"
bin/authcrunch validate --config "$PRIVATE/native.json" \
  > "$PRIVATE/validate.log" 2>&1
bin/authcrunch run --config "$PRIVATE/native.json"
```

Select any of the six Caddyfiles above. These are complete native JSON examples
generated by the real adapter, not a new JSON templating language. The output
retains HTTP/TLS apps and the selected security features. Stored applications
retain `oauth_application_sources` with their immutable-record digests; the
combined example retains `oidc_provider_directives` and typed portal
`refresh_tokens`. Refresh bodies with runtime placeholders instead retain
`portal_token_refresh_directives`.
The `security` app resolves these references before runtime validation. Preserve
the environment used by remaining runtime replacements. Changing a stored
record after adaptation fails its digest check. Independent native input may
use typed `authentication_portals[].oidc_provider` / `.refresh_tokens`, but must
not supply both typed and deferred definitions for the same portal.

To retain all twelve tested configurations and private fixture material:

```sh
umask 077
mkdir -p tmp/operator-examples
CADDY_SECURITY_EXAMPLE_EVIDENCE="$PWD/tmp/operator-examples" \
  go test -mod=readonly -race -count=1 -timeout=5m \
  -run '^TestCaddyOperatorExamplesE2E$' .
```

Use a new directory for each run. Each case retains `Caddyfile`, a complete
`native.json`, `environment.private.json`, keys, registrations, local databases
and logs with private permissions. The fixture's temporary listener addresses
are evidence, not long-running services. Reproduce the journey with the test;
configure operator-owned listeners and credentials before deploying a copy.
The normal CI gate includes these examples; no external OP suite is required.

## Runtime boundaries

One portal owns at most one downstream OP; use distinct portals, keys, cookie
scopes and nonoverlapping issuer mounts for additional OPs. Eligible OP/portal
refresh realms must name attached local identity stores. Portal login from an
unselected local realm or upstream OAuth can succeed without gaining local
refresh/OP authority. An upstream OAuth identity provider authenticates Caddy's
users; a downstream OP issues tokens to registered relying parties. Neither
configuration substitutes for the other.

OIDC ID tokens and opaque UserInfo access tokens cannot authorize portal
resources. Portal JWTs cannot call OP UserInfo. Native portal JSON body transport
requires the explicit `body transport enabled` setting and `refresh_transport:
body` at every login checkpoint; it is not an OAuth grant or arbitrary CORS
permission. Cookie transport remains HttpOnly and does not expose refresh
credentials in browser JSON.

The selected library supports downstream OIDC refresh grants, subject to its
registered scopes, offline consent and provider limits. **Portal** token refresh
does not itself provide OAuth refresh grants or refresh an upstream provider's
credentials. Dynamic client registration and RP-initiated logout are absent.
Do not document the historical absence of downstream OIDC refresh as current.

Persisted client registrations and OP keys survive reload/restart; in-memory
refresh families, OP sessions, pending requests, codes and opaque grants do not
survive successful replacement. Failed replacement preserves the active app.
Already signed access/ID tokens retain their signature/expiry semantics when
verification keys remain available; a reload alone is not global JWT revocation.
Verifier policy, issuer/audience, nonce and other validation still apply.
The current host rejects overlapping use of one persistent local identity file;
use a stop/start for those stores. In-memory store E2E reload tests do not promise
live reload of shared identity files. Active/active OP and refresh deployments
and durable session replication are unsupported.

Default browser pages integrate the continuation client. Custom themes/apps
must deliberately include and use the documented session client and its
coordination, return and logout contracts; refresh is not automatic renewal of
every application's JWT. See [browser continuation](../../authentication-portal-api/references/browser-refresh.md).
Keep source/API names fully qualified as `token_refresh`; Caddy syntax remains
`token refresh`, and the API remains `/api/refresh_token`. Existing underscores,
legacy OAuth aliases and route-level `authenticate with` / `authorize with`
syntax remain supported; see [upstream grammar](../../configuration-oauth-providers/references/shared-parser.md).

Parser/unit tests and actual Caddy TLS, browser, native, lifecycle and composed
E2E are complementary. The outer host owns routing, reference/key safety and
candidate activation; shared parsers and runtime own protocol/realm validation.
Read sibling sources as references only. Fixes, tests, generated artifacts and
skills stay in caddy-security; never change or run a sibling repository to
qualify these examples.
