---
name: configuration-ticket-providers
description: "Configure SQLite or Consul single-use ticket login issued by a trusted application, browser binding, storage and recovery. OAuth/SAML providers have separate owners."
---

# Ticket Identity Providers

## Scope and trust boundary

For shared `identity provider consul NAME` tickets, read
[Consul companions](../configuration-state/references/consul-companions.md).
The Consul provider preserves the trusted-application/browser-binding protocol;
its attached account identity still follows the core local-store boundary.


Use `identity provider sqlite <name>` for login tickets issued by an authenticated,
authorized application. The application owns its user authentication and chooses
the verified subject and roles. Caddy owns portal routing, policy and access-token
signing. This adapter installs no issuer service, anonymous issuance endpoint or
issuance command. Read [trusted application integration](references/trusted-issuer.md)
when implementing the application's public Go API consumer.

The global identity dispatcher loads `security.identity_providers.sqlite`.
Its flat block delegates to the selected AuthCrunch ticket parser. Native JSON
uses `apps.security.identity_providers` with `driver: sqlite`; the runtime
provider reports kind `sqlite-ticket` and protocol driver `ticket`. These names
are distinct. Ordinary OAuth and SAML declarations retain their own parsers.

## Configuration and deployment

```caddyfile
{
 log {
  output stdout
  format filter {
   wrap json
   fields {
    request>uri delete
    resp_headers>Location delete
   }
  }
 }
 security {
  identity provider sqlite trusted-app {
   realm application
   path /var/lib/caddy-security/tickets/login.db
   public_origin https://login.example.test
   issuer_url https://issuer.example.test/signin
   base_path /auth
   cookie_name APP_LOGIN_BINDING
   timeout 1s
  }
  authentication portal myportal {
   crypto key sign-verify {env.JWT_SHARED_KEY}
   enable identity provider trusted-app
  }
  authorization policy app-policy {
   crypto key verify {env.JWT_SHARED_KEY}
   set auth url https://login.example.test/auth
   allow roles authp/user
  }
 }
}

login.example.test {
 log {
  output stdout
  format filter {
   wrap json
   fields {
    request>uri delete
    resp_headers>Location delete
   }
  }
 }
 @portal path /auth /auth/*
 handle @portal {
  authenticate with myportal at /auth
 }
 handle /app* {
  authorize with app-policy
  respond "Authenticated application"
 }
}
```

All backend fields are literal; runtime placeholders and secret lookups are not
expanded. `name` comes from the header. `realm`, `path`, `public_origin` and
`issuer_url` are required, each once with one value. Optional `base_path` defaults
to `/auth`, `cookie_name` to `AUTHP_PROVIDER_SESSION_ID`, and `timeout` to 1s
within 1ms–30s. Realm contains 1–64 ASCII letters, digits, underscores or hyphens.
The parser validates without opening storage or contacting the issuer.

Origin and issuer must be canonical HTTPS URLs without userinfo, query or
fragment. Origin has no path; issuer has a simple slash-separated path. Explicit
ports must be 1–65535. The mount accepts `/` or simple nested ASCII segments,
without a trailing slash, up to 512 bytes; portal-owned namespaces are excluded.
The issuer cannot equal the callback. Configure the actual deployed HTTPS origin
and mount: adaptation cannot infer arbitrary Caddy routing. Preserve the full
path when mounting `authenticate`.

Select the provider by name in each portal. Provider names are globally unique
across built-ins and modules; selected store/provider names and realms must not
collide. Unknown selections fail before factories run. A portal with no explicit
store or provider selection retains the root's default-backend selection rules;
explicit selection keeps deployment intent clear.

Add `attach to local identity store <name>` once to bind the provider to one
configured built-in local store. Native JSON uses
`"attachment": {"local_identity_store": "accounts"}`. The name is literal,
including in native JSON; it is not a realm or file path. Missing, disabled,
ambiguous, wrong-kind and SQLite password-store targets fail before ticket
storage opens. The target name `:memory:` is invalid; a named local store whose
path is `:memory:` remains available for a nonpersistent root.

Omission, `null` and native `{}` select the same private-memory default and
normalized descriptor. Explicit targets enter the descriptor and root state
binding. Attaching does not enable the target as a login realm. Enable it in the
portal only when users need fresh local login, connection or local challenges.
Read [attached identities](../configuration-identity-stores/references/connected-accounts.md)
for account continuity and the browser connection boundary.

## Browser and identity behavior

The rendered Application sign-in link starts `GET <mount>/provider/<realm>`.
The backend creates a five-minute request and a random browser-binding cookie,
then redirects to the pinned issuer with `request` and `callback` parameters.
The trusted issuer returns a ticket valid for at most two minutes and no longer
than the request. The callback requires exact TLS, host and path, exactly one
`state`, one `ticket` and one binding cookie. Extra or duplicate parameters fail.
At most one successful consumption returns a verified identity.

The binding cookie is Secure, HttpOnly, host-only, SameSite=Lax and scoped to
that exact callback path. Issuance and deletion use identical scope. Its name is
independent of the portal prefix; it cannot collide case-insensitively with any
portal role or configured upstream identity cookie. `__Secure-` is supported;
`__Host-` cannot use this callback subpath, including with a root-mounted portal.
The portal validates both provider cookie configuration and runtime results.

The issuer supplies subject, email, display name and roles, without local-factor
proof. Portal transforms and current policy still run. Signed authentication
methods are server-owned `federated`, and origin is the selected realm. A stronger
local MFA requirement cannot be satisfied by asserted roles. A consumed ticket
stays spent if later policy or signing fails. The endpoint remains a browser
redirect protocol; JSON negotiation does not create a native issuance API.

Without an explicit target, AuthCrunch creates a provider-owned private
passwordless memory identity for the pinned issuer and verified subject. The signed local `id` differs from
`sub`; email does not select an existing account. Repeated logins through the same
provider instance share that identity. Replacement/restart creates a new private
identity even though pending tickets survive. Preserve the exact provider's
attachment interface through root/portal wiring; a separate fallback store cannot
validate its proof. A file-backed explicit target preserves the local UUID and its current account
policy across restart; private memory does not provide that durability. Existing stateless access JWTs keep their normal lifetime. Application roles
do not automatically grant portal access. Public asset and favicon requests
preserve a valid application-only cookie without admitting its user to restricted
portal assets; invalid tokens still receive deletion.

Portal logout clears portal credentials. It does not revoke pending tickets,
perform upstream logout or immediately revoke already issued access JWTs.
OAuth refresh snapshots do not support this protocol, and downstream OP login
rejects external identity proof. Optional inherited cross-device transfer is
access-only and bounded by the proof expiry; do not claim a new refresh family.
The cross-device configuration owner retains its protocol acceptance boundary.

## Storage, replacement and diagnostics

Use an absolute private local POSIX file with existing 0700 parent directories;
database and sidecars require 0600. Storage is pure Go, unencrypted and unsuitable
for a shared network filesystem. Ticket files and journal/WAL/shared-memory
namespaces must be distinct from other database categories. The app checks known
optional declarations and local/dropbox files before live backend construction,
including existing inode and parent-path aliases. Native SQLite paths are cleaned
before alias checks, matching the constructors; local snapshot/dropbox paths keep
their original traversal semantics. Custom modules own their own
storage separation. Do not replace filesystem entries beneath a serving runtime.

Compatible provider handles can share one canonical ticket file. Binding values
separate their records; capacity is 1,024 live requests across that file, with
expired entries pruned on admission. Different hardlink names cannot share safe
journal ownership and are rejected. Same-category sharing does not imply remote
issuance, multi-host availability or durable portal sessions.

The app derives descriptors before root validation and opens fresh handles before
root construction. Runtime bindings are absent from JSON. The root borrows the
exact instances and never configures or closes them. Only a optional ticket
module with a nonempty target opts into `IdentityProviderAttachmentStores`:
the root captures its fresh unbound attachment, validates the exact enabled
local declaration before acquisition, then binds the actual root store before
publication. Other borrowed providers retain caller-prebound or unnamed lazy
memory behavior; merely implementing the attachment interface does not opt in.
Failed candidates close acquired resources; retirement drains requests and disposes the root before
provider closure. Persistent-root construction remains deferred to Start and
retains its stop/start restriction. Config digests bind runtime state to the
provider's normalized policy and storage declaration.

Pending requests and issued tickets survive compatible restart. Changing name,
realm, origin, mount, issuer or cookie binding prevents old state consumption.
Changing only the attachment target changes the root configuration/session epoch;
it does not change the ticket protocol binding or revoke a pending request.
An accepted callback uses the currently selected attachment. On unavailable storage or uncertain commit, publish no ticket, identity or
credential. Drain and reopen quarantined handles, reconcile the outcome, then
begin a fresh login. Do not retry blindly or restore consumed cookies as recovery.

Tickets and request IDs travel in URLs. Caddy retains an earlier request copy for
logging; handler query stripping cannot protect that copy. The example deletes
`request>uri` and `resp_headers>Location` in both diagnostic and access encoders,
preserving status and denial entries. Caddy records response Location headers,
including the initial issuer redirect containing a request identifier. Apply
equivalent protection at the issuer and any proxy; do not log credential-bearing
Location headers. A query-only filter needs separate evidence
for malformed URL parsing before it can replace whole-field deletion. Component
skip rules do not provide this redaction or resolve the separate host logger issue.

## Acceptance

`TestSQLiteTicket*`, `TestAppIdentityProvider*` and `testcase_identity_provider_sqlite`
cover text/native declarations, implicit and explicit attachments, no-I/O
validation, exact runtime bindings, storage separation and owned lifecycle.
Standalone public parser, descriptor, attachment, browser-binding and durable
ticket cases live in `plugins/identity-providers-sqlite/consumer_test.go`,
`attachment_test.go` and `binding_test.go`. Root tests retain global dispatch,
native aliases, route wiring, attachment admission and shared storage ownership.
`testcase_identity_attachments` adds attached SAML/LDAP/ticket adaptation;
`TestAppIdentityProviderAttachment*` checks target preflight, deferred snapshots,
file-backed identity and unchanged third-party ownership. The connected-provider
and persistence journeys in the [shared reference](../configuration-identity-stores/references/connected-accounts.md)
qualify the explicit target through actual Caddy.
`TestCaddySQLiteTicketE2E` must qualify actual TLS Caddy and an authenticated trusted
issuer, Chrome login, independent JWT verification, binding-cookie scope, malformed
callbacks, wrong browser/host/credentials, concurrent consumption, replay, restart,
failed replacement, stronger policy and log redaction. Parser success and upstream
standalone consumers do not establish host acceptance. Retain real uncertainty
and expiry/capacity evidence from the selected backend as separate support.
