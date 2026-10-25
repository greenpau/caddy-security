---
name: configuration-messaging
description: "Configure email, file and SQLite messaging providers, bounded delivery workers, SMTP transport, sender credentials and registration notifications."
---

# Configuration Messaging

## Purpose

Use this skill to configure `messaging <kind> provider <name>` blocks. The
built-in parser is `caddyfile_messaging.go`; companion modules use
`caddyfile_messaging_backend.go`. The app owns runtime bindings and delivery.

Messaging is most often needed by registration flows, password recovery, MFA
OTP, or administrative notifications.

`caddyfile_messaging.go` forwards provider subdirectives directly to
`go-authcrunch/pkg/messaging`. Use the authcrunch instruction names exactly;
for example, file providers use `root_dir`, not `rootdir`.

## Email Provider

```caddyfile
{
	security {
		messaging email provider localhost-smtp-server {
			address 127.0.0.1:1025
			protocol smtp
			credentials smtp_root
			sender root@example.com "Example Auth Portal"
			bcc admin@example.com audit@example.com
			template password_recovery templates/password_recovery.tmpl
			template registration_confirmation templates/registration_confirmation.tmpl
			template registration_ready templates/registration_ready.tmpl
			template registration_verdict templates/registration_verdict.tmpl
			template mfa_otp templates/mfa_otp.tmpl
		}
	}
}
```

Email providers require:

- `address <host:port>`.
- `protocol smtp` or `protocol smtps`.
- Exactly one of `credentials <name>` or `passwordless`.
- `sender <email> [display_name]`.

Use `passwordless` instead of `credentials <name>` when the SMTP server does
not require authentication.

`smtp` opens a plaintext SMTP connection;
the sender does not negotiate STARTTLS. `smtps` uses implicit TLS with
certificate verification. A server requiring STARTTLS is not supported by
switching `protocol smtp` to port 587. Use an endpoint that supports the chosen
transport; there is no Caddyfile STARTTLS or custom SMTP CA directive here.

The referenced `credentials <name>` object follows
[configuration-credentials](../configuration-credentials/SKILL.md).

For local registration message checks, use the built-in file provider below
with a disposable `root_dir` under this checkout's `tmp/`; no SMTP tool install
is needed. This verifies rendered content, not SMTP authentication, TLS or
recipient delivery. When the task requires SMTP evidence, use an explicitly
configured loopback test server and synthetic credentials, inspect its envelope
recipients as well as message headers, and stop it after the check. Keep any
added test tooling and its output in the repository and pin its version.

## File Provider

```caddyfile
messaging file provider local_outbox {
	root_dir tmp/registration-messages
	sender root@example.com "Example Auth Portal"
	template registration_confirmation templates/registration_confirmation.tmpl
	template registration_ready templates/registration_ready.tmpl
	template registration_verdict templates/registration_verdict.tmpl
}
```

File providers write `.eml` messages under `root_dir`. Authcrunch requires both
`root_dir <path>` and `sender <email> [display_name]`. File providers do not use
`credentials` or `passwordless`.

Email providers put `bcc <email>...` into a `Bcc` message header but
do not add those addresses to SMTP `RCPT TO`. Do not rely on it for copy
delivery or recipient privacy: recipients can see that header. This is an
upstream sender limitation, not configurable Caddy behavior. File providers
parse and preserve `bcc`, but the file sender writes only `To`; it also omits
the configured sender from the `.eml` content.

Both email and file providers validate and preserve these template IDs:

- `password_recovery`.
- `registration_confirmation`.
- `registration_ready`.
- `registration_verdict`.
- `mfa_otp`.

## Template Directive

Use `template <id> <path>` to add an entry to the provider's `templates` map.
Authcrunch validates the ID and preserves the path, but the provider parser does
not check that the path exists.

Current registration notification rendering does not load provider `template`
paths. It uses embedded English subject/body templates from the sibling
`go-authcrunch` repository, then sends the rendered message through the
configured provider.

Default messaging template files live under:
`https://github.com/greenpau/go-authcrunch/tree/main/pkg/messaging/email_templates/en`
The embedded asset loader strips `email_templates/` and `.template`, so
`registration_confirmation_subject.template` is looked up as
`en/registration_confirmation_subject`.

Default files by validated template ID:

- `registration_confirmation`: `registration_confirmation_subject.template`
  and `registration_confirmation_body.template`.
- `registration_ready`: `registration_ready_subject.template` and
  `registration_ready_body.template`.
- `registration_verdict`: `registration_verdict_subject.template` and
  `registration_verdict_body.template`.
- `password_recovery`: no default messaging subject/body file in
  `pkg/messaging/email_templates`; password recovery UI lives in the portal
  sandbox template, not in the messaging template library.
- `mfa_otp`: no default messaging subject/body file in
  `pkg/messaging/email_templates`.

## Registration Wiring

Registration flows reference messaging providers by name with the historical
`email provider <name>` directive. The referenced provider may be email, file or a bound SQLite outbox.
AuthCrunch selects it by exact name at send time. An outbox receives no SMTP
credentials; its independently selected delivery transport receives them only
when the worker sends.

```caddyfile
user registration signup {
	email provider localhost-smtp-server
	admin email admin@example.com
}
```

The registration block belongs to
[configuration-registrations](../configuration-registrations/SKILL.md).

## SQLite outbox

```caddyfile
{
 security {
  messaging email provider smtp-local {
   address 127.0.0.1:1025
   protocol smtp
   passwordless
   sender auth@example.test
  }
  messaging sqlite provider notifications {
   path /var/lib/caddy-security/mail/outbox.db
   timeout 1s
   delivery smtp-local
  }
 }
}
```

The `security.messaging.sqlite` module appears in native JSON under
`apps.security.messaging_providers`, with `driver`, `name`, `path`, optional
`timeout` and optional `delivery`. Names must be unique across modules and
built-ins. The public SQLite parser owns name/path/timeout validation. Fields
are literal; they do not expand Caddy placeholders or secret lookups. Existing
email-provider and credential instructions retain runtime resolution.

`path` is an absolute local POSIX database in an existing private 0700 parent;
its database and sidecars use 0600. Use a separate file from other plugin
categories. Runtime construction can create the outbox; parsing and module
validation perform no storage I/O. Storage is pure Go and requires no SQLite
process or cgo. Bodies, recipients and confirmation codes are plaintext on disk.
`timeout` defaults to 1s and accepts 1ms through 30s for database operations.

Optional `delivery` selects an existing email provider, whose sender, protocol
and credentials apply to every message in this queue. It cannot select another
outbox or a file provider. Missing or ambiguous credentials fail before storage
opens. Omission queues messages without starting a delivery worker; an external
consumer must own delivery. Registration references the queue using
`email provider notifications`.

`Send` success means durable local acceptance. The shared file permits 1000
outstanding messages across all named queues; full storage rejects admission
without eviction. Transactions obtain exclusive access before mutation; ordinary
reader/writer contention waits within the database deadline before admission. Failed or uncertain acceptance must not be blindly retried.
The app rebuilds private runtime bindings after JSON restoration and never
serializes handles or delivery credentials into message records.

Workers start only in `App.Start`. Each claim has a one-minute exclusive lease;
the worker uses its exact persisted expiry, reserves five seconds for
acknowledgement, and caps an SMTP attempt at fifteen seconds. Claim and
acknowledgement contexts are bounded to five seconds, subject to any shorter
queue timeout. Empty or failed attempts poll at one-second intervals. Failed or
uncertain delivery remains leased until expiry; there is no immediate resend,
lease renewal or dead-letter queue. A commit error can quarantine its handle;
drain and reopen the runtime before reconciling uncertain work. The worker does
not automatically reopen storage or reinterpret an error as non-acceptance.
Independent workers can share a named queue.
A crash after SMTP acceptance and before acknowledgement may duplicate delivery;
applications needing deduplication must provide it downstream.

Cleanup closes request admission and drains producers, then cancels and joins
workers before closing the root and queues. Cancellation closes the actual SMTP
socket, including greeting, TLS handshake, DATA and QUIT stalls. A successful
send still gets a bounded acknowledgement when cleanup starts concurrently.
Validation-only candidates never send mail. A candidate that reaches Start may
deliver before an unrelated app fails; Caddy startup has no transaction spanning
external SMTP side effects. Queued work and outstanding leases survive restart.
Other restrictions, including local identity/dropbox overlap, still apply.

Registration renders quoted-printable HTML. The worker preserves those bytes and
the email sender supplies matching MIME headers; it does not double encode or
reinterpret content. General queue callers must honor that body contract. Logs
report fixed failure phases without recipients, bodies, codes, credentials,
leases or raw transport diagnostics. `bcc` retains the built-in sender limitation
above; queue delivery does not turn a header into an envelope recipient.

## Validation surfaces

`plugins/messaging-sqlite/consumer_test.go` and `ownership_test.go` cover public
parsing, private storage, independent queue handles, stale leases and durable
reopen. Root `messaging_sqlite_test.go` retains dispatch, native loading and
adaptation. `app_messaging_test.go` covers
binding validation, candidate cleanup and producer drain;
`app_messaging_worker_test.go` covers budgets, cancellation, failure redaction
and concurrent workers. `app_messaging_e2e_test.go` exercises actual TLS Caddy
registration, SMTP envelope/body delivery, queue errors, restart and shutdown.
Legacy registration confirmation writes a dropbox record; it does not implicitly
activate a login account. Dedicated registration workflows have their own owner.

Adaptation cases include `testcase_messaging_sqlite` and
`testcase_authenticate_with_registration` in `testdata/caddyfile_adapt/`.
File output checks alone do not verify SMTP authentication, TLS or recipients.
Use a disposable loopback server and synthetic credentials for transport tests;
inspect `RCPT TO` separately from headers and close all test-owned connections.
