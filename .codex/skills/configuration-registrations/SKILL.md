---
name: configuration-registrations
description: "Configure local user signup, domain/MX rules, terms, confirmation, dropbox storage, and messaging. Use for registration versus account activation; OAuth client registration is separate."
---

# Configuration Registrations

## Purpose

Use this skill to configure `user registration <name>` blocks. Dispatch starts
in `caddyfile_user.go`; registration instructions are collected by
`caddyfile_user_registration.go`. The Caddyfile parser injects
`name <block-name>` and `kind local`, then forwards the block instructions to
authcrunch for validation.

Registration flows attach to the target identity store declared by
`identity store <name> [<realm>]`. During authcrunch validation, portals using
that identity store get registration enabled for that store and the registry is
attached at runtime. The current portal parser does not accept
`enable user registration <name>`; use `enable identity store <name>` on the
portal instead.

## Shape

```caddyfile
{
	security {
		user registration signup {
			title "User Registration"
			code {env.REGISTER_CODE}
			dropbox assets/config/registrations_local.json
			require accept terms
			require domain mx
			email provider smtp
			admin email admin@example.com
			identity store localdb
			link terms https://example.com/terms
			link privacy https://example.com/privacy
			allow domain example.com
		}

		local identity store localdb {
			realm local
			path assets/config/users.json
		}

		authentication portal myportal {
			enable identity store localdb
		}
	}
}
```

## Required and Defaulted Fields

Authcrunch requires the effective registry config to have `name`, `kind`,
`dropbox`, `email provider`, at least one admin email address, and
`identity store`. In Caddyfile configuration, `name` comes from the block name
and `kind local` is injected by caddy-security.

`title` is optional and defaults to `Sign Up`. `code` is optional; when present,
the registration form requires the exact configured value. `require accept
terms` and `require domain mx` are optional boolean flags.

The authcrunch parser accepts exactly one admin email address per instruction:
`admin email <address>` or `admin emails <address>`. Multiple addresses on one
line are invalid, and repeated admin-email lines overwrite rather than append.

## Supported Lines

The parser forwards registration lines to authcrunch. Supported patterns in
authcrunch include:

- `title <name>`
- `code <value>`
- `dropbox <path>`
- `require accept terms`
- `require domain mx`
- `email provider <name>`
- `admin email <address>`
- `admin emails <address>`
- `identity store <name> [<realm>]`
- `link terms <url>`
- `link privacy <url>`
- `allow domain <string>`
- `deny domain <string>`
- `allow <exact|partial|prefix|suffix|regex> domain <string>`
- `deny <exact|partial|prefix|suffix|regex> domain <string>`

Domain restrictions are validated by authcrunch. Matching stops at the first
rule that matches the email domain; if no rule matches, the default action is
the opposite of the last configured rule. For a simple allow list, use only
`allow` rules. For a simple deny list, use only `deny` rules.

Coordinate the `email provider` value with `configuration-messaging`; despite
the directive name, authcrunch can notify through a matching email or file
messaging provider. Coordinate identity store names with
`configuration-identity-stores`.

## Workflow Notes

Registration is not the same as immediate account activation. The user reaches
the form from the portal's register link, submits username, password, email,
name, optional registration code, and required terms acceptance, then receives
an email confirmation link and short passcode. The confirmation passcode is
time-limited in authcrunch; when it expires, the user must register again.

After email confirmation, the handler consumes the pending registration, adds
the user to the dropbox database and attempts an administrator notification.
That database is separate from the target login store. Approval and transfer
into the login store remain a separate management operation; no full approval
UI is implemented here. Do not edit a serving identity database as a routine
approval step. Use a supported management path or arrange an offline import and
explicit reload. A notification failure after the dropbox commit is logged and
does not undo the committed registration.

Pending registrations are held in the registry's in-memory cache. Reload or
restart discards them; the durable dropbox only contains confirmed entries.
An expired or lost pending registration must be started again. A supplied
password must be plaintext: the selected AuthCrunch rejects reserved password-hash import prefixes
on the public registration path, while trusted static-user imports are separate.

When multiple registrations target different identity stores or realms, use
separate dropbox paths. The portal exposes realm-specific registration URLs,
for example:

```text
/auth/register/local
/auth/register/userpool1.localdomain
```

For local validation without SMTP, point `email provider` at a file messaging
provider whose `root_dir` is a disposable path under this checkout's `tmp/`.
Inspect the confirmation link and passcode in its `.eml` output using synthetic
identities and separate temporary dropbox/login databases. This does not check
SMTP authentication, TLS, sender headers or BCC delivery; the messaging skill
documents those limits.

## Fixtures

Use these examples:

- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`.
- `assets/config/registrations_local.json`.

The adaptation/resolution fixture verifies configuration shape and defaults,
not a registration journey. `TestCaddyPasswordArgon2E2E/public-registration`
uses the actual executable and a disposable file sender to reject valid, malformed
and whitespace-padded bcrypt/Argon2 imports without a message or persisted user;
ordinary plaintext reaches confirmation-message delivery. This does not qualify
confirmation, approval, transfer or SMTP. The lifecycle tests exercise registry ownership
and replacement, but this checkout has no complete user-signup E2E. Do not
confuse `TestCaddyRegistrationE2E`, which covers persisted OAuth client
registrations, with user signup. A future user-signup acceptance case should
reject wrong codes and disallowed domains, confirm one emitted link/passcode,
verify only the dropbox receives the account, reject replay or lost pending
state, and observe the administrator notification and separate activation.
