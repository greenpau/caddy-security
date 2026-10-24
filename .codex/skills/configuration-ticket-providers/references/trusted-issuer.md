# Trusted application ticket issuance

The trusted application authenticates and authorizes its user before calling
`plugins/identity-providers/sqlite.Provider.Issue`. The Caddy adapter creates no
issuer HTTP service or command. An issuer route used by the repository tests is
test-only; copying it without real authentication would let callers choose login
identity and roles.

Open a separately owned provider with the same name, realm, private database,
origin, mount, cookie name and issuer URL as Caddy. Only share this local POSIX
file between trusted processes with appropriate filesystem access. The public
constructor does not contact the issuer URL. Keep one bounded application-owned
handle and close it after its users drain. Caddy's private runtime handle is not
an issuance service and should not be exported from the app.

The application receives a request identifier from the initial redirect. Treat it
as opaque untrusted input until the library validates it. Authenticate the user
through the application's established mechanism; authorize which portal roles
that identity may receive. Construct `idp.LoginIdentity` from verified server-side
data, never arbitrary callback/form fields. Use a bounded request context.

This helper represents only the final authenticated operation:

```go
package issuer

import (
    "context"
    "net/url"

    "github.com/greenpau/go-authcrunch/pkg/idp"
    tickets "github.com/greenpau/go-authcrunch/plugins/identity-providers/sqlite"
)

// completedIdentity comes from the application's completed authentication and
// authorization, including its own decision about allowed roles.
func completeLogin(ctx context.Context, provider *tickets.Provider,
    requestID string, completedIdentity *idp.LoginIdentity) (string, error) {
    target, err := url.Parse(provider.CallbackURL())
    if err != nil {
        return "", err
    }
    ticket, err := provider.Issue(ctx, requestID, completedIdentity)
    if err != nil {
        return "", err
    }
    target.RawQuery = url.Values{
        "state": {requestID},
        "ticket": {ticket},
    }.Encode()
    return target.String(), nil
}
```

Redirect only to the provider's pinned `CallbackURL`, never the HTTP caller's
`callback` parameter. URL-encode state and ticket. Do not log the returned URL,
request identifier, ticket, browser secret or credentials. Apply no-store to the
issuer's responses. An HTML form document whose POST checks Origin can use
`Referrer-Policy: strict-origin`: it withholds query identifiers while preserving
the browser's request origin. A document-level `no-referrer` policy can instead
produce `Origin: null` on form navigation; do not weaken the exact origin check
to accept that value. Use `no-referrer` on credential redirects and callbacks,
and protect request, response and proxy logs. The callback still requires the
initiating browser's secure binding cookie; knowing a request identifier is
insufficient.

Issuance snapshots identity once, atomically, for an existing live browser request.
Concurrent issuance admits at most one winner; normal contention can also yield
uncertainty. An uncertain return publishes nothing. Reconcile after draining and
reopening; the normal recovery path is a fresh login. If issuance commits but the
application cannot deliver its redirect, there is no revoke/reset operation to
compensate. Do not retry issuance automatically; the ticket expires within its
short lifetime. A Close error after delivery does not authorize a second ticket.

The separate issuer handle does not establish the local identity used in Caddy's
signed `id`. Consumption authenticates through Caddy's concrete provider-owned
attachment. Do not transfer a private memory attachment or fabricate local proof
in the issuer. Backend name and realm alignment alone cannot reproduce that state.

For acceptance, use the actual authenticated application flow and Caddy TLS
callback, verify the resulting token independently, reject anonymous/wrong issuer
credentials before issuance, and prove that browser-supplied subject, role and
callback values cannot influence the verified result. The repository's ticket
E2E fixture demonstrates this boundary without adding a production issuer route.
