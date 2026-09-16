# JSON and Native Client Interoperability

## Boundary

Use the public `github.com/greenpau/go-authcrunch/pkg/authclient` package to
consume portal JSON login. `NewClient` validates configuration without logging
in; each `Authenticate(ctx)` performs initial or fresh authentication. It does
not renew credentials, read configuration files, manage terminal input, or call
admin/profile APIs. Caddy continues to forward the request to `Portal.ServeHTTP`.
Keep terminal/configuration/management code out of server handlers.

`cmd/caddy-authenticator` is the standalone profile-based consumer of this API.
It reuses the shared config parser, client, credentials and FileTokenStore.
Its `profiles/<name>/token.jwt` is the same JSON credential representation,
including native metadata. See the
[command maintenance reference](../../scripts-and-automation/references/caddy-authenticator.md)
for storage, input, documentation and its real-Caddy E2E coverage.
The command reuses unexpired tokens, requests native refresh within three minutes
of expiry, and uses `login --force` for explicit fresh authentication. That
scheduling and its persistent refresh-uncertainty marker belong to the command;
`authclient.Authenticate` itself still always performs fresh authentication.

This is direct portal login with password/TOTP or an independent API key. An
[OAuth public relying party](../../configuration-oauth-applications/references/oidc-provider.md)
instead uses browser authorization, authorization code plus PKCE, and its
registered callback, including the restricted loopback forms. Native portal
credentials do not create an OP browser session. A bearer token or API key is
not evidence that password/MFA checkpoints completed for an OIDC browser login.

## Transport Selection

| Client setting | Portal configuration | Result |
| --- | --- | --- |
| Omitted or `RefreshTransportCookie` | Access-only realm | Legacy JSON access token |
| Omitted or `RefreshTransportCookie` | Participating refresh realm | Browser metadata; client returns `ErrNativeTransportRequired` |
| `RefreshTransportBody` | Participating realm, body transport enabled | Native access token, refresh token, SID and deadlines |
| `RefreshTransportBody` | Refresh or body transport unavailable | `HTTPError` with status 400; no retry |
| API key with default/cookie mode | Refresh enabled or disabled | Independent access-only credential |
| API key with body mode | Any portal | Invalid client configuration; raw login also rejects it |

Cookie mode omits the `refresh_transport` field from every wire request. This
preserves compatibility with older strict-schema portals, including v1.1.41.
Do not send an explicit `cookie` value merely because it is the typed default.
Refresh-enabled browser completion exposes metadata without bearer credentials;
the Go client returns the transport error with no credentials and does not retry
an already-completed login.

Body mode sends `refresh_transport: body` on initial identification and every
password/TOTP checkpoint. The portal must name the local realm and explicitly
enable `body transport enabled` in its [refresh block](../../configuration-authentication/references/token-refresh.md).
Successful checkpoints/completion set no cookies. Native requests must carry
no Cookie, Origin or Fetch Metadata. `NewClient` copies the supplied HTTP client
and ignores its Jar in body mode; custom transports remain trusted dependencies
and must not inject browser headers. Preserve server error responses, including
status and any ordinary tracking cookies on rejected initial requests.

## Password, TOTP and API Keys

Supply configured password/TOTP inputs or a context-aware `PromptFunc`.
Configured TOTP secrets are raw secret bytes, not base32 text; defaults are
six digits, SHA-1 and 30 seconds. For a combined MFA checkpoint, `PromptMFA`
selects TOTP; the client then generates a code from the configured secret or
calls `PromptTOTP` when no secret is set. Without a prompt, a configured secret
answers combined MFA directly. The portal resolves
username, email and case aliases and retains the canonical sandbox identity.

`ErrInputRequired`, `ErrUnsupportedChallenge`, cancellation and `HTTPError`
remain distinct outcomes. The client does not implement WebAuthn/U2F assertions;
do not advertise selecting that method as a completed authentication flow.
Fresh login is established by a new checkpoint exchange. An access-only JWT
can repeat when identity claims and issuance seconds match; native fresh login
creates a new SID and refresh credential.

API-key login sends only realm and key, once. It must not prompt, fall back to
password/MFA, issue refresh authority, or set browser cookies. This remains true
for MFA-enrolled accounts and refresh-enabled realms. Expired, disabled, revoked
or invalid keys and disabled owners fail. Mixing a key with username or sandbox
fields is invalid; body transport is invalid for this independent credential.

## Existing Outbound Configuration

`security local` already owns a private YAML client configuration.
`parseSecurityLocalConfig` decodes that existing schema, rejects unknown or
duplicate fields/documents and invalid UTF-8, and encodes authentication fields
for `pkg/authclient/parser.NewAuthenticationClientConfigFromDirectives`.
The parser's `*authclient.Config` result owns defaults and validation; CLI-only
`token_path` and legacy `cookie_name` stay outside it. There is no new server
Caddyfile client block or terminal/config machinery in portal handlers.

The adapter maps `base_url`, `username`, `realm`, `password`, `api_key`,
`totp_secret`, `totp_code_length`, `totp_code_lifetime`, `access_token_name`,
and `refresh_transport` to the corresponding space-separated shared settings.
Quote/encode a value as one argument so embedded spaces/quotes remain data.
Always CSV-quote YAML string scalars, including values that appear to need no
quotes. The shared encoder trims record whitespace and can otherwise drop an
unquoted trailing tab or Unicode whitespace. That changes raw TOTP/API-key
credentials and can silently turn invalid transport, URL or token-name settings
into valid ones. Double embedded quotes for the shared CSV decoder; do not use
Go/JSON backslash quoting for this directive boundary. Validation still belongs
to the shared parser. Password bytes are also preserved on the client wire;
the portal's own password whitespace normalization is a separate behavior.
Omitted/empty optional YAML scalars and zero TOTP integers retain library
defaults. Nonempty whitespace-only or multiline authentication values fail the
shared parser with redacted errors. YAML field names remain unchanged; the
shared directive grammar is an internal adapter boundary, not new YAML syntax.
See [local client configuration](../../scripts-and-automation/references/local-user-commands.md#client-configuration-and-login).

## Persistence and Explicit Renewal

Choose an isolated `FileTokenStore` path per portal and identity. Save the
returned `Credentials`, reopen the file, then pass `Credentials.Authorization()`
only to the intended trusted resource. New directories use 0700 and files 0600
on Unix. Existing directory permissions are retained. Legacy files carry no
portal/identity binding; atomic replacement does not coordinate refresh races.
Credential validation checks transport syntax, not signatures or expiry. A
separate Caddy authorization policy must verify the token and its claims.

The client retains access/refresh token names, SID and expiry metadata. Portal
access cookie names become lower-case names in the client's named Authorization
header. An explicit renewal consumer must preserve this conversion when building
updated `Credentials`; the refresh cookie name retains its advertised spelling.
`FileTokenStore.Save` fills `created_at` when the caller omitted it.

Renewal/logout are separate explicit POSTs to `<mount>/api/refresh_token` and
`<mount>/api/logout`, with JSON `{"refresh_token":"<credential>"}`, no browser
headers, and no cookie jar. Rotation changes both tokens and retains SID and the
absolute deadline. Logout revokes the refresh family; it does not imply that an
already-issued access JWT immediately becomes invalid at every resource server.
`/api/refresh_session` is browser-only and is not native recovery.

An interrupted response may follow a committed rotation. Never retry the spent
credential automatically or add replay grace. Obtain a new family through an
explicit fresh login, or explicitly revoke the old family. Merely retaining a
refresh token in `Credentials` does not enable automatic renewal.

## Caddy Validation

- `TestAuthenticationClientConfigAdapter` checks every existing YAML login
  field, defaults, quoting, redacted rejections and typed JSON restoration.
- `TestAuthenticationClientConfigWhitespace` checks exact credential bytes and
  rejection of settings that would become valid if trailing whitespace vanished.
- `TestAuthenticationClientLegacyWire` runs the public client against a strict
  legacy request schema across password and TOTP checkpoints.
- `TestAuthenticationClientUnsupportedChallenge` checks that a WebAuthn
  assertion challenge stops without credentials or another request.
- `TestCaddyAuthenticationClientE2E` runs real TLS Caddy at root/nested mounts
  with default/custom names, password/configured/prompted TOTP/combined MFA,
  aliases, canceled input, opt-in/off, API keys, private credential reopening,
  an independently authorized resource and native/OIDC separation. Existing
  `security local connect` is also exercised with native MFA and saved metadata.
  Password/TOTP fixtures include trailing whitespace, and a changed API key must
  be rejected rather than repaired. Request counters include attempts that fail
  before a response, so cancellation and no-retry checks cannot miss them.
- `authentication_client_token_refresh_e2e_test.go` exercises explicit native
  rotation/logout and loss of a committed response through the existing test-only
  Caddy fault probe. Revoking the uncertain old family must leave a fresh family
  usable. The probe never issues tokens or bypasses authentication.

The fixture explicitly disables both admin and profile APIs before provisioning.
Caddyfile portals currently default profile APIs on and expose no profile toggle;
the fixture supplies the supported portal JSON `"api": {}` object. Successful
authentication uses only `/login`; separate authenticated probes confirm the
management/profile endpoints remain unavailable. No admin feature is needed to
authenticate or authorize the resource.

Run these tests in this repository. Upstream authentication-client source and
skills are read-only references, not instructions to run sibling suites.

```sh
go test -mod=readonly -race -count=1 -run 'TestAuthenticationClient|TestCaddyAuthenticationClientE2E' .
make ci-check
```
