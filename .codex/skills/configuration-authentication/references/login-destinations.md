# Login destinations and concurrent tabs

Configure `trust login redirect uri domain exact <authority> path <matcher>
<path>` in the portal. The authority includes a port when one is present.
Trust is checked on capture and delivery; return navigation does not authorize
the destination resource. The protected route must still use its policy.

The first `redirect_url` query value belongs to that login transaction. Preserve
its presence even when empty, malformed, untrusted or oversized: the result is
`<portal-mount>/portal?redirect_url=`, never another tab's return cookie. Values
are bounded to 16384 bytes before and after removing `login_hint`. Values above
2048 bytes travel with the transaction and are not written into redirect cookies.
Removing `login_hint` also canonicalizes query-key order. Escaped query
separators and fragments retain their meaning.

Password/MFA sandboxes, upstream OAuth state, signed SAML transactions and
cross-device requester state hold their own destinations. Later login pages,
factor POST fields, provider callback queries and cross-device approvers cannot
replace them. A legacy local start with no bound destination retains shared
return-cookie fallback. Custom themes and JavaScript must retain the login
navigation context when constructing their own forms or links.

A signed-in tab with a valid portal session can return to its own destination.
An ordinary waiting login page probes for login elsewhere and navigates after
another tab signs in. `fresh=1` disables that shortcut: both its GET and submitted
POST require an interactive login, including when another tab signs in while
the page remains open. Refresh-only sessions use the existing continuation page.

Browser password/MFA starts issue a separate HttpOnly proof for each sandbox;
the [cookie contract](../../configuration-authentication-cookies/SKILL.md#independent-browser-login-proofs)
owns its scope, limits and legacy compatibility. Two tabs can reach their
checkpoints before either completes, then finish in reverse order without
restoring cookies. Access and refresh cookies remain shared, so the last
completed identity becomes the browser's current identity. This is not separate
simultaneous signed-in identities within one browser context.

## Verification

`TestCaddyLoginDestinationsE2E` covers mounted TLS boundaries, explicit empty and
malformed first values, cookie-free long destinations, competing return cookies,
factor POST tampering, browser admission and termination, reverse-order MFA with
refresh enabled, independent JWT identities and native proof rotation.
`TestCaddyLoginDestinationsProvidersE2E` covers reverse OAuth/SAML completion and
cross-device requester ownership, with wrong-proof recovery and spent-proof
replay against the original credentials.

`TestCaddyLoginDestinationsBrowserE2E` uses normally trusted Chrome, one context
and two actual tabs at root and nested mounts. It also exercises a native signed
SAML POST from a different site, including browser cookie retention and callback
consumption. Never replace these checks with two jars, restored cookies, TLS
exceptions or rewritten Origin headers. Existing authorization redirect tests
retain the broader protocol/legacy matrix; refresh browser tests own continuation.
