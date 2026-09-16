# Browser Refresh Through Caddy

## Ownership and Routing

`AuthnMiddleware.ServeHTTP` delegates the original request to
`Portal.ServeHTTP`. Keep the complete canonical mount, request body, cookies,
Origin/Fetch Metadata and refresh headers. The library dispatches these exact
POST endpoints before ordinary access authorization:

- `<mount>/api/refresh_token`: rotate a browser or explicitly opted-in native
  credential.
- `<mount>/api/refresh_session`: obtain the browser family's SID without rotating.
- `<mount>/api/logout`: revoke the family and clear browser authentication cookies.

Expired access must not prevent these operations. They authenticate their own
refresh credential; all other APIs retain ordinary authorization. Do not add a
suffix-based gatekeeper bypass, preauthorize the portal, strip its mount, retry
POSTs, or add permissive CORS. Put the complete portal route before a protected
catch-all. Use the [routing skill](../../configuration-http-integrations/SKILL.md)
and [refresh configuration](../../configuration-authentication/references/token-refresh.md).

## Request Contract

Browser operations POST the JSON object `{}`, with HttpOnly cookies, the exact
configured HTTPS `Origin`, and `X-Authcrunch-Refresh: 1`. Compatible Fetch
Metadata is required when present: same-origin site, cors/same-origin mode and
empty destination. Forward these values unchanged; embedding servers own any
trusted proxy normalization, and must not infer an intended public origin from
an untrusted request.

The coordinator also sends `X-Authcrunch-Refresh-Session: <SID>` on rotations.
This binds the pending request to its old family when another login changes the
browser's cookies concurrently. An unknown/different SID cannot consume a valid
current credential. The header is optional for other consumers, but an empty or
duplicate header, or its use on lookup/logout/native requests, is malformed.

Do not mix cookie and body credentials. Reject duplicate refresh cookies,
ambiguous Origin/refresh headers, unknown or duplicate JSON fields (including
escaped duplicate names), trailing data, query parameters, and bodies exceeding
1 KiB. The session lookup endpoint is browser-only even with native body
transport enabled. It supplies a SID, not fresh authentication evidence or an
uncertain-exchange recovery mechanism. Known spent credentials still trigger
normal replay revocation.

Preserve library statuses and `Cache-Control: no-store`: malformed requests use
400, missing/revoked authority or a wrong expected SID uses 401, origin/transport
violations use 403, disabled/wrong refresh endpoints use 404, wrong methods use
405 with `Allow: POST`, wrong content types use 415, and temporary failures use
503. A path outside the mounted Caddy route follows that site's other handlers;
it is not a library refresh response. Do not rewrite failures into success or
introduce replay grace.

## Browser Coordinator and Continuation

Serve the embedded `<mount>/assets/js/refresh.js` from the same library version
as the handlers. This public asset name stays `refresh.js`; Go and Node test
filenames use `token_refresh` without renaming the served URL. The client exposes
`AuthCrunchSession.refresh()` and `AuthCrunchSession.logout()`. Use those methods
instead of implementing an independent fetch/retry loop.

Both operations share a real Web Lock across tabs. A same-page refresh promise
and metadata from a completed exchange avoid competing rotations. localStorage
contains only SID/expiry metadata and pending/blocked markers. Tokens stay in
HttpOnly cookies, never localStorage or URLs. Persist pending state before
sending a rotation. Loss of a response can follow a committed exchange and
updated cookies; never retry that exchange or use session lookup to recover it.

HTML `data-session` and `data-expires` values are hints. Bootstrap confirms the
current signed access cookie with `/whoami?probe=true` under the shared lock.
Old HTML cannot replace newer pending state. A different SID confirmed after a
real fresh login can recover blocked tabs; the same SID cannot clear uncertainty,
even if its access cookie was updated by a lost response. Storage events and
explicit focus/refresh checks preserve this rule. Missing Web Locks or unusable
storage must produce the `authcrunch:reauthenticate` event with the fresh-login
URL, without rotating or looking up uncertain credentials.

With an eligible refresh cookie and expired access, top-level `/portal` or
`/login` serves the session continuation page. When no uncertainty exists, it
looks up the SID, rotates, then returns through `/portal`. Trusted login returns
use `redirect_url`; untrusted destinations are ignored. `/login?fresh=1` displays
login instead of returning to continuation. This does not automatically renew
arbitrary cross-origin protected applications: those applications must explicitly
integrate navigation to the portal.

GET `/logout` with refresh state is a confirmation page, not revocation. Its
button uses the protected POST and follows only the trusted `redirect_uri` or
the portal login fallback. Keep the session page's no-store, no-referrer and
frame-blocking CSP. Logout remains available after bootstrap refuses rotation;
a failed revocation must not claim success. Provider logout has its own protocol.

## Cookie and Account Replacement

Honor the configured default, prefix or explicit refresh name. Active refresh
cookies use the actual mount (`/` at root). Remove the same-name legacy cookie
at `<mount>/api/refresh_token` without deleting the newly issued active cookie.
Successful logout deletes both paths. Fresh browser password/MFA login replaces
a presented family atomically, including at `max sessions 1`; an independent
login at capacity still fails.

Switching into an access-only realm must retire previous refresh authority,
update the browser access cookie, and delete active/legacy refresh cookies.
Verify the old credential at the actual endpoint after replacement; checking
only HTML, storage or the newly issued access token misses retained authority.
API-key and explicit native-body logins remain separate contracts.

## Validation in This Repository

- `TestAuthnTokenRefreshDelegation` compares middleware status, response fields,
  headers and unchanged request metadata against direct library dispatch at root
  and nested mounts. It checks protected APIs, the exact embedded asset and
  continuation/confirmation/fresh-login pages.
- `TestCaddyTokenRefreshBrowserE2E` launches a bounded child process with actual
  parsed Caddy TLS routes and real Chrome/Chromium. Its Go HTTP cases send
  malformed requests with live credentials, verify session lookup is browser-only,
  and prove rejected requests do not consume a valid family. Explicit-cookie
  cases use a client without a cookie jar: appending another jar cookie would
  make mixed-transport tests pass on duplicate-cookie rejection instead.
- `testdata/browser/token_refresh_browser_e2e.cjs` is a dependency-free Node CDP
  driver using two actual tabs, cookies, localStorage, storage events and Web
  Locks. It checks coordinated rotation/logout, stored pending state, stale HTML,
  committed-response loss, fresh-login recovery, SID preconditions, absence of
  tokens in storage/URLs, unsupported browser primitives, default/custom cookies,
  legacy-path deletion, access-only replacement, single-slot relogin, actual
  access expiry, top-level continuation and trusted returns.
- For two-tab concurrency, finish bootstrap first, hold the first rotation at
  the server, and observe the second operation in the actual Web Lock queue
  before releasing it. Assert that no competing rotation or logout reached the
  server while held. Count both operations when checking maximum concurrency;
  issuing two browser commands alone does not establish overlap.
- A test-only Caddy module holds already-rendered HTML or truncates an already
  committed response. It wraps the real authenticator; it does not inject
  authentication evidence, issue tokens or implement refresh behavior. No such
  module is registered in the production binary.
- `TestCaddyRefreshBrowserStartup` verifies delayed/partial CDP readiness, early
  process exits, missing executables, deadline cleanup and process reaping.

Node 24 and Chrome/Chromium are required; missing engines fail rather than skip.
Set `AUTHCRUNCH_TEST_BROWSER` to a browser executable when autodetection cannot
find it. The launcher uses a temporary profile, mock/basic key storage and a
certificate-specific SPKI allowance. It does not change machine trust, reuse a
personal browser profile or disable general TLS validation. CI selects Node 24
and checks the runner's Google Chrome before `make ci-check`; the browser test is
part of the normal Go suite. This is local Chrome integration evidence, not a
promise about every browser or production proxy.

```sh
go test -mod=readonly -race -count=1 -run 'TestAuthnTokenRefreshDelegation|TestCaddyRefreshBrowserStartup|TestCaddyTokenRefreshBrowserE2E' .
make ci-check
```

Upstream `refresh-token-transports` and handler/UI sources are read-only
references. Keep integration tests and fixes in this checkout. Do not run
upstream build/test commands or copy the coordinator into a second client.
