# Attached external identities

Use this reference for local account ownership behind OAuth, SAML, LDAP and
SQLite ticket login. The [browser connection contract](../../authentication-portal-api/references/connected-accounts.md)
owns the explicit user confirmation flow. Offline SQLite password administration
and local user creation retain their existing owners.

## Configure the target

The optional clause inside each external backend is:

```caddyfile
attach to local identity store accounts
```

It takes one exact configured store name, once. Quote a name containing spaces.
The target must be one enabled built-in `local identity store` declaration,
not a realm, path, LDAP store or `security.identity_stores.sqlite` module.
Missing, ambiguous and wrong-kind targets fail. The name `:memory:` is rejected;
a configured local store with a normal name and path `:memory:` is valid for a
nonpersistent root. That sentinel is an in-memory storage mode, even if the
working directory contains a file, directory or symlink named `:memory:`.

For example, this fragment inside `security` declares the account owner:

```caddyfile
local identity store accounts {
 realm local
 path /var/lib/caddy-security/accounts.json
}
```

Configure the provider using its own OAuth, SAML, LDAP or
[ticket](../../configuration-ticket-providers/SKILL.md) owner and add the clause
to that backend. To offer connection or required local password/MFA checkpoints,
select both the external backend and the target local store in the same portal.
An attachment alone never enables its target as a login realm. LDAP itself is
selected with `enable identity store`; OAuth/SAML/tickets use
`enable identity provider`.

OAuth preserves complete deferred parser statements. SAML/LDAP preserve nested
`params.attachment.local_identity_store` through Caddy JSON and resolve that
value once before typed validation. A nonempty environment/secret reference
resolving to empty fails; it cannot silently choose private memory. Ticket
module fields are literal, including `attachment.local_identity_store` in native
JSON. No selector is reinterpreted as grammar after substitution.

Omission or an empty native attachment means provider-private memory. It has no
default administrator or password, survives only for the runtime instance, and
does not support the explicit connection UI. Use a file-backed named local store
for durable account identity. Root/session durability remains a separate
[configuration](../../configuration-state/SKILL.md); ticket pending storage alone
does not preserve account UUIDs.

## Identity and policy

The verified external key selects the account: provider name, kind, issuer and
subject. Display email or username never silently joins an existing account.
New subjects create passwordless, email-less local shells with opaque local UUIDs;
provider email remains display information, not a local login/recovery alias.
Repeated logins retain the attached UUID. Two provider identities with the same
email remain distinct until the explicit browser operation connects them.

Signed `id` is the local UUID; `sub` and `origin` retain upstream identity.
Current local roles and policy participate before signing, while provider claims
remain subject to portal transforms. The authenticated methods are server-owned.
OAuth/SAML/ticket evidence begins as `federated`; LDAP's successful remote password
flow includes `pwd` but cannot substitute for a separately required local password
or MFA proof. Enabling a local target does not weaken those checks.

Stored local challenge requirements must be completed before credentials are
issued. Without the target's enabled local login realm, a required checkpoint
fails closed. Disabled/locked accounts and changed credential/security generations
are rechecked; a valid external response alone is insufficient. Access-only APIs,
System API, Basic login, direct OAuth and cross-device approval preserve their
own authority boundaries. Do not promise new refresh/profile/OP authority from
an attachment or connection.

For Basic/API-key authorization through a named portal in the same app, each
selected credential request verifies the backend again and uses the current
attached account policy. A previously successful LDAP Basic credential therefore
fails after its local target adds an unmet password/MFA requirement or is disabled.
See [credential freshness](../../configuration-authorization/SKILL.md#basic-and-api-key-authentication)
for the remote-authenticator, bearer-token and per-request cost boundaries.

Connection moves one proven external key from a disposable shell to a freshly
proved local account. It does not merge profile fields, roles, passwords, factors,
API keys or Documents. The source shell loses the connection, is disabled and has
its credential generation advanced. An established source with credentials,
factors or multiple connections cannot be consumed as a disposable shell.
The next external login resolves to the target UUID and current target policy.
Existing stateless access tokens retain their ordinary verification/lifetime
behavior; stored browser/refresh proofs receive their normal current-state checks.

## Administration

Use [local user commands](../../scripts-and-automation/references/local-user-commands.md#commands)
to inspect or mutate an attached account through the configured portal admin API.
An automatic record without local email aliases supports an empty email selector;
an ordinary record or automatic record with a local alias still needs the matching
email. The server decides from the current record during each operation. Obtain
the stored username from listing; a provider's display email cannot select it.
The [HTTP selector contract](../../authentication-portal-api/references/admin-api.md#local-user-selection)
owns wire types, disabled-account selection and response failures.

Resetting a password does not itself remove the record's automatic flag or add
an email alias. New provider logins still follow the current local roles and
required-factor policy. Disable preserves the account/connection for an explicit
enable; delete removes the account, so a later verified provider login can create
a new UUID without the old local roles, password or challenge rules. Neither
operation changes the ordinary lifetime semantics of an already issued stateless
access JWT. Keep administration distinct from the user-confirmed connection flow.

## Ownership and changes

Built-in OAuth/SAML/LDAP bindings use the root's configured local instance.
The host's bundled ticket module explicitly opts a fresh attachment into that
same root store. Third-party provider modules retain their caller-prebound or
implicit-memory contract. The root never rebuilds or closes borrowed providers;
retirement drains Caddy requests, closes the root, then closes host-owned handles.
See [plugin ownership](../../coding-directives/references/host-plugins.md).

Changing a ticket attachment target changes its normalized root binding, including
persistent session epochs. It does not change the ticket protocol's pending-request
binding; a callback accepted after such a change uses the current target. Preserve
account storage and configuration identity when continuity is required.

## Acceptance

`TestIdentityAttachment*`, `TestSQLiteTicketAttachment*`,
`TestAppIdentityProviderAttachment*` and `testcase_identity_attachments` exercise
complete parser statements, literals, runtime resolution, no-I/O validation,
normalized digests, target selection, prepared Start snapshots and caller ownership.
`TestCaddyConnectedAccountsE2E` covers two independent OAuth identities, root/nested
browser authority, one-use connection, freshness and actual Chrome password/TOTP.
`TestCaddyConnectedProvidersE2E` covers signed SAML, verified LDAP and their local
policy/connection boundaries, including reuse of the same Basic credential across
live local-policy changes and encrypted System API checks.
`TestCaddyConnectedAccountsPersistenceE2E` checks
actual-process identity continuity and in-memory sentinel isolation. Keep the
existing ticket, provider-refresh, cross-device, local identity and protocol
negative suites when their shared boundaries change; adaptation alone cannot
prove those user flows.
`TestCaddyConnectedAccountsAdministrationE2E` uses the built CLI against actual
Caddy for empty-email administration, ordinary/aliased selector rejection,
disabled-account recovery, generated-password policy and fresh-login identity
checks after mutation or deletion.
