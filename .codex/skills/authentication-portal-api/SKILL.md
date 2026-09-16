---
name: authentication-portal-api
description: "caddy-security authentication portal JSON API and admin/server API guidance. Use when building, reviewing, or debugging programmatic login clients, Portal API calls, Accept: application/json behavior, sandbox challenge sequences, /beacon, /whoami JSON/probe/id_token responses, refresh token API behavior, admin API directives, private signing-key export, public access-token JWKS discovery, and API-oriented authentication troubleshooting."
---

# Authentication Portal API

## Purpose

Use this skill for HTTP/JSON interactions with a configured authentication
portal. Use `configuration-authentication` for the surrounding portal
Caddyfile and `configuration-http-integrations` for route mounting.

Read these files when details matter:

- `../go-authcrunch/pkg/authn/handle_json_*.go`
  for JSON handlers and response shapes.
- `../go-authcrunch/pkg/authn/handle_http_*.go`
  for browser versus JSON behavior.
- `caddyfile_authn.go` and `caddyfile_authn_admin_api.go` for admin directives.
- `../go-authcrunch/pkg/authn/admin_api/parser/parser.go`,
  `admin_api_config.go`, `respond_api.go`, and `handle_api_private_keys.go`
  for the admin configuration and authorization boundary (the latter three
  files are directly under `pkg/authn`).

Upstream handler paths are read-only references under the
[repository scope](../coding-directives/SKILL.md#repository-scope). Keep client
changes and integration tests here. If an API fix belongs to go-authcrunch,
describe the separate upstream work instead of editing or testing that checkout.

## JSON Requests

Portal endpoints return JSON when the request includes either:

```text
Accept: application/json
format=json
```

Without one of those signals, many endpoints follow browser-oriented behavior
such as rendering HTML or redirecting.

Assume endpoint paths are relative to the portal base path. If the portal is
served at `/auth`, then `/login` means `/auth/login`, `/whoami` means
`/auth/whoami`, and admin endpoints are under `/auth/api/server/...`.

## Login Challenge Sequence

Programmatic login is challenge-based:

1. `POST <base>/login` with `username` and `realm`.
2. The portal returns `sandbox_id`, `sandbox_secret`, and `next_challenge`.
3. The client posts the same identity plus `sandbox_id`, current
   `sandbox_secret`, `challenge_kind`, and `challenge_response`.
4. The portal may rotate `sandbox_secret` and return another challenge.
5. When all checkpoints pass, access-only JSON login returns
   `authenticated: true`, `access_token_name`, and `access_token`. An enabled,
   participating local refresh login instead uses the transport contract below:
   browser tokens arrive in cookies; opted-in native clients receive JSON tokens.

Common challenge kinds are `password`, `totp`, and `mfa`. For WebAuthn/U2F,
the client first answers `challenge_kind: mfa` with
`challenge_response: webauthn`; the next challenge contains a base64-encoded
WebAuthn payload. The final response must contain the signed WebAuthn result.

Do not reuse an old `sandbox_secret`; use the latest value returned by the
portal. Sandbox sessions are temporary and separate from the final JWT session.

## Portal Refresh Transports

Use the [token refresh configuration](../configuration-authentication/references/token-refresh.md)
for explicit participating local realms, origin, mount, cookie naming and limits.
The selected go-authcrunch v1.2.4 implements real rotation; `/api/refresh_token`
is no longer a timestamp probe. No enabled block means access-only behavior and
404 at the refresh/session API routes.

Browser login uses the default `cookie` transport. Tokens arrive in HttpOnly
cookies and JSON contains session/expiry metadata without bearer credentials.
After login, POST `{}` as JSON to `<base>/api/refresh_token`, `<base>/api/logout`,
or `<base>/api/refresh_session` with the cookie jar, exact configured HTTPS
`Origin`, and `X-Authcrunch-Refresh: 1`. Disallowed fetch metadata, origins or
mixed transports fail closed. Responses preserve `Cache-Control: no-store`.
A valid refresh cookie can rotate despite an expired or malformed access token.

Native clients require `body transport enabled` and send
`refresh_transport: body` at every login checkpoint. Send no Cookie, Origin or
Sec-Fetch headers. Login and rotation return `access_token`, `refresh_token`,
names, session ID, and expiry metadata in JSON without cookies. Subsequent POSTs
use `{"refresh_token":"<credential>"}`. Omitting explicit native opt-in selects
browser transport; enabling the feature alone does not opt clients in.

Successful rotation changes the refresh credential and access-token `jti`,
retains the session binding and absolute deadline, and reloads current local
identity attributes. Replaying an old refresh token revokes the family. Serialize
rotations and avoid automatic retries when delivery is ambiguous. Invalid/revoked
credentials return 401, origin/transport violations 403, admission exhaustion
503. A family's rotation-limit exhaustion revokes it and reclaims capacity.

With a refresh cookie, GET `<base>/logout` displays confirmation; the session API
POST completes revocation and cookie deletion, including an associated OP
session. Portal refresh grants are unrelated to OIDC refresh or upstream provider
refresh. API-key and other unsupported login kinds remain access-only.
`TestCaddyTokenRefreshE2E` covers these transports through verified Caddy TLS.

## Status And Identity Endpoints

Use `/beacon` for a light authentication probe. A valid token returns `200 OK`
with a plain `OK` body; an invalid or expired token returns an access-denied
JSON response when JSON was requested.

Use `/whoami` for the current user claims. Useful query parameters include:

- `probe=true`: include `authenticated` and `expires_in`.
- `format=json`: force JSON when no JSON `Accept` header is present.
- `id_token=true`: include the upstream identity provider ID token when an
  OAuth provider was configured with `enable id token cookie`.

Send access tokens using the portal-supported Authorization header or cookies
that match the portal's token validator configuration. If custom access-token
cookie names are used, keep portal and authorization policy names aligned with
`configuration-authentication-cookies` and `configuration-crypto`.

## Public Signing-Key Discovery

`GET <mount>/.well-known/jwks.json` returns the public keys used for portal
access-token signing. `HEAD` returns the same headers and Content-Length with
no body. No enable directive, session, admin API, or private-export setting is
required. Requests with invalid credentials, JSON headers, or `format=json`
still reach discovery before authentication and content negotiation.

The first eligible non-system signer determines availability: an asymmetric
signer enables discovery, while HMAC first returns 404 even when asymmetric
signers follow. Verification-only keys never enable discovery. When available,
the endpoint publishes RSA, EC, and Ed25519 signing public keys in signing
order, excluding HMAC, verification-only, and System API keys. Success is an
object with a `keys` array, including for one key, using
`application/jwk-set+json`. All methods use `Cache-Control: no-store` and
`nosniff`, without cookies or login redirects. Unsupported methods return 405
with `Allow: GET, HEAD`.

Ed25519 keys use `kty: OKP`, `crv: Ed25519`, and a 32-byte unpadded base64url
`x`; no private `d` or EC `y` appears. Match the exact `alg` and `kid` to the
signed JWT. Generated keys can advertise `EdDSA` or `Ed25519`; imported keys
default to `EdDSA`. Default key ID `0` is omitted in both JWT and JWK. See
[crypto settings](../configuration-crypto/SKILL.md) for key sources and labels.

The embedding Caddy routes define the mount boundary. Use the complete path
beneath that mount; trailing slashes, filename suffixes, and query-only matches
are not discovery. See [public JWKS routing](../configuration-http-integrations/SKILL.md#public-jwks-routing)
to keep it ahead of a protected catch-all. This endpoint is distinct from
`/oidc/jwks` and the OP's dedicated RS256 ID-token signing keys.

`TestCaddyJWKSE2E` verifies the HTTP contract over trusted TLS, reconstructs
public keys from discovery to verify real login tokens independently, and
checks gatekeeper rejection of wrong keys and tampered tokens. Its first request
is HEAD, and negative-route checks inspect both headers and bodies.
`TestCaddyJWKSPersistenceE2E` checks persisted rollover across fresh processes:
retained verification keys continue accepting old tokens
without publishing them; removing those keys on reload rejects cached old
tokens. Discovery publishes current signing configuration and does not retain
removed keys automatically.

## Admin Server API

For the built-in administration client, use
[`security local`](../scripts-and-automation/references/local-user-commands.md).
It delegates login to `go-authcrunch/pkg/authclient` and exposes realm/user
inspection, account CRUD, password reset, role/challenge updates, and reload
through the admin endpoints.

Add this inside `authentication portal <name>` to enable the server/admin API:

```caddyfile
authentication portal myportal {
	enable admin api
}
```

The documented endpoints include:

- `GET /api/server/metadata`: version, build, and server timestamp metadata.
- `POST /api/server/realms`: local realm discovery.
- `POST /api/server/info`: local identity database path, modification time,
  and password/user policy details for a realm.

Admin API requests require an active authorized session with an admin role.
When debugging, check both the Caddyfile directive and the authenticated user's
roles before suspecting handler bugs.

### Private Signing-Key Export

The portal accepts exactly these admin statements, with separate keywords:

```caddyfile
enable admin api
disable admin api
enable admin api private key export
disable admin api private key export
```

Choose at most one statement for each setting. Both settings default to false;
enabling export alone does not enable admin access. Boolean values, extra
arguments, grouped keywords such as `"admin api"`, and duplicate or conflicting
settings are errors, including when separated by unrelated portal directives.

The adapter collects the entire portal's admin statements and delegates to
`NewAdminAPIConfigFromDirectives`, then applies its `*authn.AdminAPIConfig` with
`PortalConfig.ConfigureAdminAPI`. Preserve `ProfileEnabled` and the existing
`api.admin_enabled` / `api.admin_fetch_private_keys_enabled` JSON fields; do not
replace the aggregate API configuration. Profile operations require a stored
portal session; the ordinary JSON access-token login does not create that
browser session.

`GET <mount>/api/server/private_keys` uses the existing `authenticate` route and
`Portal.ServeHTTP`. Export requires both flags and an authenticated portal admin.
For valid admin requests, the flag matrix is 404/404/404/200 (neither, admin
only, export only, both). Authentication failures precede the flag checks and
return 401 for invalid/expired tokens. With no token, authorization finds no
user: disabled export returns 404, while enabled export returns 403. A normal
authenticated user receives the same 404/403 export results. Authorized export
supports GET only; other methods return 405 with `Allow: GET` when both flags
are enabled. The library validates format and encoding selectors and sends
`Cache-Control: no-store` on success and errors.

Public access-token discovery at `GET` or `HEAD <mount>/.well-known/jwks.json`
precedes authentication and remains independent of both flags. It publishes
public signing keys only. OIDC setup does not require private export. Do not
add a public export route, another export serializer, or response-body logging.

Validation lives in `caddyfile_authn_admin_api_test.go`, the
`testcase_authenticate_with_admin_api` adaptation fixture, and
`TestCaddyAdminAPIE2E` in `admin_api_e2e_test.go`. The TLS tests exercise real
browser logins, both header and cookie credentials, root and nested mounts,
profile settings, methods/selectors, PKCS#8 key matching, public JWKS field
restrictions, and response/log redaction. Live reload coverage verifies that
existing tokens obey changed flags immediately, removed directives disable both
flags, and malformed configurations leave the active portal unchanged.

## Troubleshooting

- Missing JSON response: add `Accept: application/json` or `format=json`.
- Login sequence fails after password: verify the client preserved the latest
  `sandbox_id`, latest `sandbox_secret`, and expected `challenge_kind`.
- MFA prompts unexpectedly: inspect user tokens, `require mfa` transforms, and
  auth challenge rules stored in the local user database.
- `/whoami` omits upstream ID token: verify the OAuth provider uses
  `enable id token cookie ...` and the browser/client sends the ID-token cookie.
- `/api/refresh_token` failures: check explicit realm participation, configured
  origin/mount, the required browser header, native opt-in, and replay/capacity
  limits using the transport contract above.
- Admin endpoint returns unauthorized: verify `enable admin api`, active portal
  session, and `authp/admin` or equivalent portal admin role.
