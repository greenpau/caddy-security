---
name: configuration-authentication-cross-device
description: "Configure and verify optional cross-device portal login, QR activation, explicit approval, browser binding, cancellation, and lifecycle through Caddy. Native login and external provider configuration retain their own owners."
---

# Cross-device Portal Login

## Configuration and ownership

The selected published go-authcrunch v1.3.11 supplies the parser, runtime and
embedded UI. Check `go.mod` and the selected module directory when changing this
integration; a sibling working tree is only a read-only reference. No local
replacement or copied portal handler, QR generator, store or template is needed.

Inside an existing authentication portal:

```caddyfile
authentication portal myportal {
    enable identity store localdb
    enable cross-device login
    cookie cross-device session id name __Secure-LOGIN_TRANSFER
}
```

Declare `localdb` separately and mount the portal through `authenticate with
myportal`. Omit the cookie override to use `AUTHP_CROSS_DEVICE_SESSION_ID`.
`disable cross-device login` explicitly disables the feature. Omission also
disables it and preserves a nil field in adapted JSON. Enabling produces
`"cross_device_login":{"enabled":true}` in the portal config; an explicit
false/empty object is disabled on JSON load. Cookie naming alone never enables
routes or a login action.

`caddyfile_authn.go` collects complete enable/disable statements before the
ordinary miscellaneous/admin dispatch, encodes original token boundaries with
`cfgutil.EncodeArgs`, and calls the public
`cross_device/parser.NewCrossDeviceLoginConfigFromDirectives` once per portal.
The shared parser owns grammar and duplicate/conflict checks, including imports.
Reject empty/multiline tokens before encoding, nested blocks, joined quoted
keywords, wrong arity and unsupported arguments without echoing their values.
Individual quoted keywords preserve the same token boundaries and remain valid.
Do not add per-line boolean mutation to `caddyfile_authn_misc.go`.

## Routing and browser contract

Mount the entire namespace, without stripping its prefix:

```caddyfile
auth.example.com {
    @portal path /auth /auth/*
    route @portal {
        authenticate with myportal
    }
}
```

All paths below are relative to that mount; root and nested mounts work.
A name containing `cross-device`, such as `/cross-device-team/auth`, is not a
transfer route by substring. `/oauth2/cross-device` and `/saml/cross-device`
remain provider realms even when transfer is disabled. Unknown transfer children
return 404; do not reserve the name globally or add permissive CORS.

| Path | Methods | Behavior |
| --- | --- | --- |
| `/cross-device` | GET | Request page, QR and copyable activation link |
| `/cross-device/start` | POST | New request; 300-second lifetime, 2-second polling |
| `/cross-device/activate?code=...` | GET | Matching-code warning and approver binding |
| `/cross-device/begin` | POST | CSRF validation and fresh HTML login |
| `/cross-device/confirm` | GET, POST | Display account/code; explicit approve or deny |
| `/cross-device/poll` | POST | Pending/slow down or independent credential cookies |
| `/cross-device/cancel` | POST | Cancel before redemption |

Use HTTPS on both devices. POSTs require exactly one matching Origin,
compatible Fetch Metadata and one URL-encoded Content-Type; parameters such as
`charset=UTF-8` are supported. The 4 KiB bound includes streamed bodies without
Content-Length. Oversize is 413, unsupported media is 415, malformed/ambiguous
forms or Content-Type is 400, and method errors advertise supported methods.
Caddy owns trusted forwarded origin/source normalization. Preserve
`Referrer-Policy: strict-origin`; `no-referrer` makes Chrome form Origin become
`null` and correctly fail CSRF validation.

The link/QR contains only an activation code. A separate requester secret stays
in page memory and POST bodies; the code cannot redeem approval. Poll responses
issue HttpOnly cookies, never bearer tokens in JSON. Keep normal redirect trust
allowlists, and never log form bodies or place the requester secret in URLs.

The approver binding cookie is Secure, HttpOnly, host-only, mount-scoped,
SameSite=None and has a 300-second Max-Age. None permits signed cross-site SAML
POST callbacks. Browser binding, strict transfer POST origins and explicit
approval remain mandatory. Shared prefix/override/collision rules apply;
`__Host-` names require a root mount. Ordinary cookie attributes do not relax
this binding. A second tab's new binding must invalidate an older account's form;
only the displayed account may reach its corresponding requester.

## Identity, cancellation and lifecycle

Scanning and logging in do not approve a request. Require fresh HTML login and
all selected factors, or a freshly verified OAuth/SAML callback, then explicit
approval of the displayed account and matching code. Existing JWTs, Basic,
API-key and JSON login cannot complete approval. Local credential versions and
current requester challenge policy are checked again at redemption. Provider
transfers rerun requester transforms and never copy upstream identity tokens;
they do not introduce upstream revocation introspection.

Each device receives independent access, refresh and OP sessions. Rotation of a
live approver refresh family remains valid. Logout, replay, fresh account
replacement and logout after the access cookie is gone invalidate unconsumed
approval. Only committed local refresh issuance supplies its authoritative
family reference; custom access/provider `sid` claims are not family IDs.
Failed completion publishes no credentials and releases an undelivered family.
These checks belong to AuthCrunch and need no Caddy logout or issuance hooks.

Pending records are volatile, origin/mount scoped, limited to 1024 per portal
and eight per trusted source IP, and consumed atomically before issuance.
Reload, restart and Close discard them even with persistent `state`. Persistent
reload itself retains the existing host rejection policy: use complete stop/start.
Multiple instances require affinity for a pending interaction. Lost redemption
responses require a new request; cancellation cannot undo consumed approval.

Navigation ends the visible flow and clears its capability. Back may show a
terminal document or a new request, never resume the old capability. Late
clipboard/network callbacks must not replace cancellation. The embedded client
uses original AbortController APIs, ten-second request/body deadlines and a
separate five-second cancellation deadline; it does not require
`AbortSignal.any` or `AbortSignal.timeout`. Chrome evidence does not certify
physical TV/VR hardware. Custom login templates must retain the conditional
cross-device action outside ordinary provider-link visibility conditions.

## Acceptance and validation

- Unit/adapt/resolution cases in `caddyfile_authn_cross_device_test.go` and
  `testcase_authenticate_with_cross_device` qualify omission, enabled/disabled
  JSON, encoded grammar, imports, redaction and cookie defaults/overrides.
  Existing cookie parser cases retain reserved modern keywords and collisions.
- `TestCaddyCrossDeviceE2E` exercises actual Caddy TLS routes, independent
  credentials/resource access, mounts, strict HTTP boundaries, MFA/refresh/OP,
  non-HTML exclusion, revocation, race redemption, JSON reload, persistent
  restart, optional host-prefix scope and failed-issuance rollback.
  `TestCaddyRuntimeStateE2E/cross_device_pending` also crosses an actual
  built-Caddy process restart with durable state enabled.
- `TestCaddyCrossDeviceProvidersE2E` uses real signed OAuth and SAML callbacks,
  including the provider realm `cross-device`, provider-only/mixed UI and a
  custom access-only `sid`.
- `TestCaddyCrossDeviceBrowserE2E` runs independent Chrome contexts through the
  embedded UI with private fixture trust, QR/copy, explicit approval, navigation,
  cancellation, native aborts without static helpers, and the two-account
  stale-form regression. Keep TLS/Origin enforcement intact.
  Dispose completed scenario contexts before opening the next devices; assert
  their contexts and targets are gone. The stale-form scenario retains two
  isolated requesters and two approver tabs sharing one fresh context.
  `TestBrowserContextCleanup` checks awaited disposal, partial failure cleanup
  and ownership of contexts still requiring cleanup.
- `TestCaddyCrossDeviceExpirationE2E` waits for the real five-minute deadline,
  checks source quota despite untrusted forwarded addresses and verifies expiry
  releases capacity. It deliberately adds five minutes to the full Go suite.

Use this command for focused evidence, then `make ci-check` for the full gate:

```bash
make test TEST='TestPortalCrossDevice|TestPortalCookie|TestCaddyCrossDevice' TEST_DIR=.
```

Keep failures in separate coverage bundles. Sibling tests and official
OP conformance do not substitute for these Caddy journeys.
