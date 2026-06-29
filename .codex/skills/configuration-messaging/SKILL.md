---
name: configuration-messaging
description: "caddy-security messaging provider Caddyfile configuration. Use when creating, reviewing, or modifying messaging email provider or messaging file provider blocks, SMTP settings, passwordless email, senders, BCC addresses, message templates, root directories, and registration email wiring."
---

# Configuration Messaging

## Purpose

Use this skill to configure `messaging <kind> provider <name>` blocks. The
parser is `caddyfile_messaging.go`.

Messaging is most often needed by registration flows, password recovery, MFA
OTP, or administrative notifications.

`caddyfile_messaging.go` forwards provider subdirectives directly to
`go-authcrunch/pkg/messaging`. Use the authcrunch instruction names exactly;
for example, file providers use `root_dir`, not `rootdir`.

## Email Provider

```caddyfile
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
```

Email providers require:

- `address <host:port>`.
- `protocol smtp` or `protocol smtps`.
- Exactly one of `credentials <name>` or `passwordless`.
- `sender <email> [display_name]`.

Use `passwordless` instead of `credentials <name>` when the SMTP server does
not require authentication.

Coordinate `credentials <name>` with `configuration-credentials`.

For local registration or MFA email testing, run a mock SMTP server on the
configured address:

```bash
go install github.com/emersion/go-smtp/cmd/smtp-debug-server@latest
smtp-debug-server
```

The common docs examples use `127.0.0.1:1025` with `protocol smtp` and
`passwordless`. The debug server prints raw SMTP conversations and rendered
messages, which helps verify confirmation links, passcodes, BCC recipients,
sender identity, and registration metadata. Installing the tool may require
network access; use an existing local binary when available.

## File Provider

```caddyfile
messaging file provider local_outbox {
	root_dir assets/config/messages
	sender root@example.com "Example Auth Portal"
	template registration_confirmation templates/registration_confirmation.tmpl
	template registration_ready templates/registration_ready.tmpl
	template registration_verdict templates/registration_verdict.tmpl
}
```

File providers write `.eml` messages under `root_dir`. Authcrunch requires both
`root_dir <path>` and `sender <email> [display_name]`. File providers do not use
`credentials` or `passwordless`.

Email providers use `bcc <email>...` when constructing outgoing SMTP messages.
File providers parse and preserve `bcc`, but the current file sender writes only
the `To` recipients into the generated `.eml` file.

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
`email provider <name>` directive. The referenced provider may be either kind;
authcrunch resolves whether it is an `email` or `file` messaging provider at
send time.

```caddyfile
user registration signup {
	email provider localhost-smtp-server
	admin email admin@example.com
}
```

Use `configuration-registrations` for the registration block.

## Fixtures

Use these examples:

- `caddyfile_messaging_test.go`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`.
