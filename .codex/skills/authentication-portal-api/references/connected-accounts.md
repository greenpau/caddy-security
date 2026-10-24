# Browser connection of external accounts

The portal serves `<mount>/connected-accounts/` for explicitly attached external
identities and their local accounts. It is an HTML browser interaction, including
with `Accept: application/json`; it is not a bearer-token account-merging API.
Read [attached identity configuration](../../configuration-identity-stores/references/connected-accounts.md)
for exact target selection, local realm enablement, durable UUIDs and policy.

## Required browser authority

The browser must send exactly one nonempty configured session-ID cookie and one
access-token cookie. The access token must be the current token in a stored
portal session and must have been admitted from that cookie. Headers, query
credentials, native JSON access tokens and refresh credentials do not establish
this authority. An existing local login alone does not prove a new connection.

Start with a recent verified external login. Its attached source must be a
passwordless disposable shell, and the same portal must enable its explicitly
named local store for a new local login. The initial page can instead list an
already connected account or request reauthentication. Provider email never
selects the target account.

## User flow

1. Load `/connected-accounts/` with the existing browser cookie jar. The rendered
   form carries a private one-use operation path and CSRF value. The pending
   operation binds the browser, source identity, target store and portal mount.
2. Submit that form with `action=start`. The server redirects to its own
   `login?fresh=1` URL with the exact connection return destination.
3. Complete the newly created local browser sandbox in the selected target realm,
   including all required password/TOTP/WebAuthn checkpoints. This specific fresh
   HTML sandbox, followed by its issued access token, is bound to the operation.
4. Review the confirmation page, then submit `action=connect` or `action=cancel`
   with the original CSRF value. Successful connection renders a result without
   issuing another login credential. Log in through the external provider again
   to obtain its identity attached to the chosen local UUID.

Keep the browser jar throughout the flow. Do not manufacture cookies, replay a
saved access token, replace the return URL or insert a native JSON login between
steps. A prior local login, an unrelated fresh sandbox, a superseded sandbox or a
native JSON completion does not satisfy the confirmation boundary. Starting a
second intended local sandbox supersedes the first for this operation. A copied
operation URL in another browser cannot acquire its authority.

Operations and fresh proofs are bounded to five minutes; pending capacity is
4,096 per portal. Pending operations are process-local and do not survive root
replacement. Expired, canceled, consumed or foreign-browser operations fail.
Connection consumes the operation before attempting storage mutation, so a storage
failure requires a new flow rather than a retry of confirmation. Logout cancels
that browser's pending authority. Preserve uncertainty instead of assuming a
failed delivery means the account transaction did not commit.

## Wire behavior

GET renders HTML. POST requires an exact same-origin `Origin`, permitted fetch
metadata, `application/x-www-form-urlencoded` and a body no larger than 4 KiB.
Submit exactly two single-valued fields, `csrf` and `action`; repeated or extra
fields fail. The root collection accepts GET; operation paths accept GET/POST.
Only the expected action for the current step is valid.

| Result | HTTP behavior |
| --- | --- |
| Page, confirmation or connected result | 200 HTML |
| Start/cancel | 303 to a mounted portal route |
| No usable access cookie/stored token | 302 login redirect |
| Missing/ambiguous browser-session cookie or stale local proof | 401 |
| Origin/CSRF, proof or target authority violation | 403 |
| Invalid fields/action or malformed form | 400 |
| Missing/malformed operation path | 404 |
| Unsupported method | 405; supported operation methods are GET, POST |
| Consumed, expired or wrong-browser operation | 410 |
| Wrong media type / oversized body | 415 / 413 |
| Conflicting or failed account transaction | 409 |
| Pending admission limit / unavailable attachment storage | 429 / 503 |

These responses disable caching. Connection pages use a restrictive CSP and
`Referrer-Policy: strict-origin`, which preserves form Origin while withholding
operation paths from referrers. Do not log operation URLs, CSRF values, source or
target tokens, sandbox secrets, passwords or factor responses. Caddy retains its
own request copy, so application query/path handling does not redact host logs;
use appropriate diagnostic and access encoders.
For these flows, redact `request>uri`, `request>headers>Referer` and
`resp_headers>Location` in Caddy sinks, and `url`, `redirect_url` and
`redirect_url_any` in the diagnostic encoder. Fresh login and sandbox navigation
can carry the connection destination in same-origin referrers; the connection
page's referrer policy does not govern subsequent documents. The diagnostic
fields can carry a connection operation in DEBUG redirect events.

## Effects and qualification

Only the external key moves. Local target profile data, roles, factor material,
passwords, API keys and Documents remain unchanged. The disposable source is
disabled and its current proof is invalidated. Later external login uses the
target's current roles and factor policy; it does not convert federated evidence
into local profile, Documents or OP authority. Local account administration
retains the admin API and command owner's eligibility checks.

`TestCaddyConnectedAccountsE2E` exercises root and nested mounts, two provider
identities with the same display email, exact cookies/forms, wrong-browser and
replay rejection, intended versus unrelated local proof, and actual Chrome
confirmation with password/TOTP. Provider and restart suites are mapped in the
[configuration reference](../../configuration-identity-stores/references/connected-accounts.md).
Use real browser navigation and natural form POSTs for Origin/cookie/freshness
acceptance; jar-free HTTP negatives verify rejection, not browser SameSite behavior.
