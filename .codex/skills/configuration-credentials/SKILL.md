---
name: configuration-credentials
description: "caddy-security reusable generic credentials Caddyfile configuration. Use when creating, reviewing, or modifying security credentials blocks for reusable username/password credentials, optional domains, SMTP or email messaging authentication, registration email provider credentials, environment placeholders, or secret-backed credential values."
---

# Configuration Credentials

## Purpose

Use this skill to configure reusable `credentials <label>` blocks. These are
parsed by `caddyfile_credentials.go` into go-authcrunch generic credentials.
The Caddyfile block label becomes authcrunch's required credential `name`.

## Credentials vs Secrets

Use `credentials` to create a named authcrunch credential object: a reusable
`name`, `username`, `password`, and optional `domain` tuple that another
configuration section can reference, such as an email messaging provider.

Use `secrets` to configure an external `security.secrets` manager and expose
lookup values with the `secrets:<secret_id>:<key>` syntax. A secret lookup is
not a credential object by itself; it is a placeholder-like value that
caddy-security resolves during provisioning.

The two can be combined: put `password "secrets:smtp:password"` inside a
`credentials smtp_root` block when the consumer needs a named credential, but
the password should come from a secrets manager. Use `configuration-secrets`
for the manager block and lookup rules.

## Shape

```caddyfile
security {
	credentials smtp_root {
		username root
		password {env.SMTP_PASSWORD}
		domain example.com
	}
}
```

The block accepts:

- `username <username>`
- `password <password>`
- `domain <name>`

Only generic username/password credentials are exposed through the Caddyfile.
Do not add `name` or `kind` inside the block; caddy-security injects `name`
from `<label>`, and unsupported inner keys fail parsing.

`username` and `password` are required by go-authcrunch after runtime
resolution. `domain` is optional. SMTP sending in go-authcrunch uses the
resolved `username` and `password`; include `domain` only when a downstream
consumer expects it.

All values are single tokens after Caddyfile parsing. Quote values containing
spaces.

## Guidance

Use environment placeholders or secret lookups for passwords:

```caddyfile
password {env.SMTP_PASSWORD}
password "secrets:smtp:password"
```

Secret lookups must use the `secrets:<secret_id>:<key>` shape and require a
matching `secrets <plugin> <secret_id>` block from `configuration-secrets`.
Caddy-security resolves `{env.*}` and `secrets:*:*` values before
go-authcrunch validates credentials.

Placeholders may be used in the block label and fields, but references must
resolve to the same final name. For example, a messaging provider's
`credentials <credential_name>` value must match the resolved credentials block
label.

Use labels that describe the consumer, such as `smtp_root`,
`registration_smtp`, or `mailgun_smtp`, rather than the secret value itself.

When the credential is consumed by email messaging, coordinate with
`configuration-messaging`. Non-passwordless email providers require a
`credentials <credential_name>` reference; passwordless email providers must
not also set credentials.

LDAP bind settings are not wired through reusable `credentials` blocks. LDAP
identity stores configure bind credentials directly with their own `username`
and `password` directives.

## Fixtures

Use these examples:

- `caddyfile_credentials_test.go`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_credentials.Caddyfile`.
- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`.
