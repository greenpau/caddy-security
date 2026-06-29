---
name: configuration-registrations
description: "caddy-security user registration Caddyfile configuration. Use when creating, reviewing, or modifying user registration blocks, registration titles and codes, dropbox files, terms and privacy links, accepted email domains, MX checks, email provider wiring, admin notification addresses, and identity store targets."
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

After email confirmation, current docs still describe administrator approval as
manual: review the dropbox file and move approved user data into the target
local identity store database or another management path. Do not promise a full
admin approval UI unless the current go-authcrunch implementation provides it.

When multiple registrations target different identity stores or realms, use
separate dropbox paths. The portal exposes realm-specific registration URLs,
for example:

```text
/auth/register/local
/auth/register/userpool1.localdomain
```

For local validation without a real SMTP server, `smtp-debug-server` from
`github.com/emersion/go-smtp/cmd/smtp-debug-server` can listen on
`127.0.0.1:1025` and print raw registration email content. This is useful for
verifying confirmation links, passcodes, BCC handling, and registration
metadata. Installing it may require network access.

## Fixtures

Use these examples:

- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`.
- `assets/config/registrations_local.json`.
