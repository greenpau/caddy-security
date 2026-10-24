# SQLite email-confirmed enrollment

Read this for durable signup backed by SQLite accounts, pending registrations
and notification queues. This workflow creates enabled accounts with only the
`authp/user` role after email confirmation. It has no invitation code, administrator
approval, domain/MX policy, terms gate or MFA enrollment. These settings cannot be
borrowed from the legacy registration block. Confirmed mailbox access is not an
MFA factor.

## Declaration and selection

```caddyfile
{
 security {
  identity store sqlite accounts {
   path /var/lib/caddy-security/accounts/users.db
   realm staff
  }
  messaging email provider smtp-local {
   address 127.0.0.1:1025
   protocol smtp
   passwordless
   sender auth@example.test
  }
  messaging sqlite provider notifications {
   path /var/lib/caddy-security/mail/outbox.db
   delivery smtp-local
  }
  user registration sqlite signup {
   path /var/lib/caddy-security/signup/pending.db
   identity_store accounts
   realm staff
   email_provider notifications
   public_origin https://login.example.test
   base_path /tenant/auth
   timeout 1s
  }
  authentication portal myportal {
   crypto key sign-verify {env.JWT_SHARED_KEY}
   enable identity store accounts
   enable user registration signup
  }
 }
}
```

Mount `authenticate with myportal` at `/tenant/auth` and `/tenant/auth/*` on the
configured HTTPS origin, preserving the request path. The app cannot infer Caddy's
route mount from a registration declaration. Matching `public_origin` and
`base_path` to deployment is an operator responsibility; valid but mismatched
values produce unusable confirmation links. The workflow always uses these
configured values, ignoring request Host and forwarded host metadata.

`user registration <name>` retains legacy syntax, including when its name is
`sqlite`. The extra driver word in `user registration <driver> <name>` selects a
module. `security.registration_workflows.sqlite` is represented under native
`apps.security.registration_workflows` with `driver`, `name`, `path`,
`identity_store`, `realm`, `email_provider`, `public_origin`, optional `base_path`
and optional `timeout`. Names are unique across legacy and external registries;
each identity store has at most one registry.

The public SQLite parser owns backend grammar. Every setting occurs once and
takes one value. The header supplies `name`. Fields are literal: Caddy runtime
placeholders and secret lookups are not expanded. Required dependencies select
the exact bundled SQLite identity-store and messaging modules; local/LDAP stores,
email/file senders and lookalike custom modules are not substitutes. The realm
must match the selected store.

`public_origin` is a canonical HTTPS origin with a lowercase host, no path,
userinfo, query or fragment, and any explicit port in 1–65535. `base_path` defaults
to `/auth`; `/` is supported. Other mounts use slash-separated ASCII letters,
digits, underscores or hyphens, without a trailing slash, at most 512 bytes.
Portal-owned protocol namespaces cannot occur in that path. `timeout` defaults to
1s and accepts 1ms through 30s.

Enable both the identity store and the registry in each enrolling portal.
External registries are never selected implicitly. A second portal can use the
same account store without offering registration. Signup links are derived from
the selected, attached registry and detached portal login metadata, so one
portal cannot alter another's visibility. The normal login screen exposes the
mounted realm-specific signup link.

## Storage and lifetime

Use three distinct private local POSIX database files: accounts, pending entries
and outbox. Parents must already exist with mode 0700; files and sidecars use
0600. Module parsing/validation opens nothing. Runtime construction checks path
aliases before opening dependencies, then creates the pending store. Filesystem
replacement outside the app is outside this check; do not alter paths beneath a
serving runtime. Storage is pure Go and needs no SQLite executable or cgo.
The account database must already be provisioned; enabling signup does not change
the identity module's open-existing rule. Use trusted offline
[identity administration](../../configuration-identity-stores/references/sqlite-integration.md#trusted-offline-administration)
to provision initial accounts. Outbox and pending files can be created by their
runtime constructors in existing private parents.
Supported older pending schemas migrate transactionally during construction.
Drain earlier runtimes before a schema upgrade and retain a private backup;
older binaries may be unable to reopen the upgraded database. Unknown schemas
and failed migrations are rejected.

The app derives normalized backend descriptors before root validation, opens
accounts and queues before workflows, then supplies exact runtime registry
bindings to the single AuthCrunch root. Handles are absent from native JSON.
The root borrows these providers; the app owns closing them. Cleanup drains
requests and stops delivery workers before root disposal, then closes workflows
before their borrowed queues and account stores. Failed candidates unwind in
reverse acquisition order. Persistent-root construction retains its deferred
Start and stop/start boundary; backend durability does not make sessions durable.

Pending entries survive restart and contain a bcrypt password hash, digests of
registration IDs and codes, and an enrollment UUID. They expire after 45 minutes.
Five wrong codes exhaust a durable attempt budget. The 10,000-entry lifetime
capacity includes terminal history; there is no eviction or automatic pruning.
Public registration accepts plaintext passwords only; trusted hash-import forms
are rejected. The notification queue contains the plaintext confirmation code
and recipient, so protect its file and delivery access separately.

The outbox's optional delivery worker is configured independently. Queue
acceptance means durable local storage, not recipient delivery. See the
[messaging contract](../../configuration-messaging/SKILL.md) for leases,
cancellation, transport limitations and possible duplicate mail. A notification
failure cancels the pending enrollment. There is no public resend operation.

## Confirmation and recovery

Confirmation requires exactly one body code. Query-only and duplicate codes,
unknown, expired, canceled, exhausted and spent entries fail with a generic page.
Success redirects to the mounted login with HTTP 303; it issues no access token,
refresh token or authenticated session. It never invokes the legacy dropbox or
administrator notification path. The user must then authenticate normally.

The portal binds a validated return destination when registration begins.
Confirmation query parameters and shared cookies cannot replace it. That value
survives pending-state restart and reconciliation; trust rules apply again when
confirmation releases it to the normal login transaction. The host must not
reconstruct or override this navigation state.

Account creation commits before pending confirmation in a separate file. An
error can therefore leave an account with pending evidence. Withhold success,
drain and reopen quarantined handles, inspect current account state, and reconcile
the same still-live evidence. Do not blindly retry on an uncertain serving
handle or delete the evidence first. Recovery preserves the account UUID and
subsequent role/disabled changes; enrollment tombstones prevent recreating an
account deleted during recovery. If the code expires during account lock waits
or after an account commit, success remains withheld and both stores may require
reconciliation. Concurrent confirmation can also return uncertainty; promise at
most one successful consumption, not an immediate winner under every schedule.

## Acceptance boundaries

`TestSQLiteRegistration*` and `testcase_registration_sqlite` cover strict grammar,
native round trips and literal module configuration. `TestAppRegistration*`
covers explicit selection, immutable declarations, exact dependencies, distinct
storage, partial factories, plugin metadata errors, rejected replacements,
request drain and deferred persistent construction.

`TestCaddySQLiteRegistrationE2E` follows signup to SMTP delivery, confirmation,
and native/Basic/Chrome password login with independently verified tokens. Its
fixtures exercise root and nested mounts, hostile Host metadata, wrong/replayed
codes, restart, unavailable queues, immutable return navigation and real SQLite
commit uncertainty. Fresh-handle recovery must preserve identity and management
state and reject resurrection after deletion. Backend expiry/capacity/schema
tests remain upstream; do not claim them from adaptation or a browser success
alone. Run these host tests against the selected dependency before considering
the integration qualified.
