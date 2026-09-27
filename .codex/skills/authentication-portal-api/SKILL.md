---
name: authentication-portal-api
description: "Build or troubleshoot portal JSON/native login clients, refresh, profile and admin APIs, and public JWKS. Use for HTTP contracts; portal Caddyfile wiring belongs to configuration-authentication."
---

# Authentication Portal API

## Purpose

Use this skill for HTTP/JSON interactions with a configured authentication
portal. Surrounding Caddyfile declarations belong to
[configuration-authentication](../configuration-authentication/SKILL.md);
route mounting belongs to
[configuration-http-integrations](../configuration-http-integrations/SKILL.md).
These are configuration boundaries, not prerequisites for an HTTP client task.

For user-owned profile keys, legacy PGP/RSA metadata, ownership isolation, and
canonical profile identity and transformed-claim isolation, read
[profile public keys](references/profile-public-keys.md).
For conditional login selection, authoritative AMR and profile policy preview/
replacement, read [authentication flows](references/authentication-flows.md).
For password/MFA mutations and refresh/OIDC invalidation, read
[local identity compatibility](../configuration-identity-stores/references/local-identity.md).

For the standalone `caddy-authenticator` CLI, profile configuration, terminal
input and private storage, use the
[command maintenance reference](../scripts-and-automation/references/caddy-authenticator.md).
Keep fresh login delegated to the public authclient package; the command owns
cached-token scheduling and its explicit native refresh request.

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

For the public Go client, native transport, API-key login and private credential
files, use [JSON/native interoperability](references/native-client.md).
`Authenticate` performs fresh login; renewal is a separate explicit operation.

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

Common challenge kinds are `password`, `totp`, and `mfa`. The public Go authclient
supports password/TOTP, including combined MFA selection. It does not implement
WebAuthn/U2F assertions and returns `ErrUnsupportedChallenge` for an assertion
challenge. A separate client that supports assertions first answers
`challenge_kind: mfa` with `challenge_response: webauthn`; the next challenge
contains a base64-encoded WebAuthn payload. The final response must contain the
signed WebAuthn result.

Do not reuse an old `sandbox_secret`; use the latest value returned by the
portal. Sandbox sessions are temporary and separate from the final JWT session.

## Portal Refresh Transports

Use the [token refresh configuration](../configuration-authentication/references/token-refresh.md)
for explicit participating local realms, origin, mount, cookie naming and limits.
The selected go-authcrunch implements real rotation; `/api/refresh_token`
is no longer a timestamp probe. No enabled block means access-only behavior and
404 at the refresh/session API routes.

Browser login uses the default `cookie` transport. Tokens arrive in HttpOnly
cookies and JSON contains session/expiry metadata without bearer credentials.
After login, POST `{}` as JSON to `<base>/api/refresh_token`, `<base>/api/logout`,
or `<base>/api/refresh_session` with the cookie jar, exact configured HTTPS
`Origin`, and `X-Authcrunch-Refresh: 1`. Disallowed fetch metadata, origins or
mixed transports fail closed. Responses preserve `Cache-Control: no-store`.
A valid refresh cookie can rotate despite an expired or malformed access token.
The browser coordinator also sends the optional rotation precondition
`X-Authcrunch-Refresh-Session`; forward it unchanged. Session lookup is
browser-only and must never recover an uncertain rotation. See
[browser refresh through Caddy](references/browser-refresh.md) for continuation,
coordination, strict request parsing, fresh-login recovery and real Chrome tests.

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

Admin endpoints require the configured admin API and an authorized portal
session. Private signing-key export is independently disabled by default and
requires both flags plus administrator authorization. Public JWKS is separate
and needs neither flag. Read [admin/server API contracts](references/admin-api.md)
for endpoint shapes, exact status/method behavior, key formats, and Caddy tests.

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
