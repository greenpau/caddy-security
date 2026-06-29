---
name: authentication-portal-api
description: "caddy-security authentication portal JSON API and admin/server API guidance. Use when building, reviewing, or debugging programmatic login clients, Portal API calls, Accept: application/json behavior, sandbox challenge sequences, /beacon, /whoami JSON/probe/id_token responses, refresh token API behavior, enable admin api, /api/server metadata/realms/info endpoints, and API-oriented authentication troubleshooting."
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
- `caddyfile_authn_misc.go` for `enable admin api`.

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
5. When all checkpoints pass, the current JSON login path returns
   `authenticated: true`, `access_token_name`, and `access_token`. The
   `AuthResponse` struct has refresh-token fields, but the current
   `handleIssueTokens` path in local go-authcrunch does not populate them.

Common challenge kinds are `password`, `totp`, and `mfa`. For WebAuthn/U2F,
the client first answers `challenge_kind: mfa` with
`challenge_response: webauthn`; the next challenge contains a base64-encoded
WebAuthn payload. The final response must contain the signed WebAuthn result.

Do not reuse an old `sandbox_secret`; use the latest value returned by the
portal. Sandbox sessions are temporary and separate from the final JWT session.

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

## Admin Server API

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

## Troubleshooting

- Missing JSON response: add `Accept: application/json` or `format=json`.
- Login sequence fails after password: verify the client preserved the latest
  `sandbox_id`, latest `sandbox_secret`, and expected `challenge_kind`.
- MFA prompts unexpectedly: inspect user tokens, `require mfa` transforms, and
  auth challenge rules stored in the local user database.
- `/whoami` omits upstream ID token: verify the OAuth provider uses
  `enable id token cookie ...` and the browser/client sends the ID-token cookie.
- `/api/refresh_token` surprises: the current endpoint is an authenticated JSON
  endpoint that returns a timestamp; it does not mint a replacement token value.
- Admin endpoint returns unauthorized: verify `enable admin api`, active portal
  session, and `authp/admin` or equivalent portal admin role.
