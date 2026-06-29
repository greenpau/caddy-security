---
name: configuration-users
description: "caddy-security local user account Caddyfile configuration. Use when creating, reviewing, or modifying local identity store user entries, usernames, display names, email addresses, plaintext or bcrypt passwords, overwrite behavior, roles, static API key prefixes and payloads, and secret-backed user attributes."
---

# Configuration Users

## Purpose

Use this skill for `user <username>` entries inside `local identity store`
blocks. The Caddyfile syntax is authoritative in `caddyfile_identity_store.go`;
the provisioning behavior is authoritative in the local `go-authcrunch` source,
especially `pkg/ids/local/user.go`, `pkg/ids/local/authenticator.go`, and
`pkg/identity/database.go`.

Use `configuration-identity-stores` for the surrounding store.

## Shape

```caddyfile
local identity store localdb {
	realm local
	path assets/config/users.json

	user alice {
		name "Alice Example"
		email alice@example.com
		password {env.ALICE_PASSWORD} overwrite
		roles authp/user authp/admin
		api key kid123456789012345678901 {env.ALICE_API_KEY_BCRYPT}
	}
}
```

`kid123456789012345678901` is intentionally 24 characters. For static user API
keys, authcrunch treats the Caddyfile key id as the API key prefix and currently
requires exactly 24 characters.

## Fields

The current Caddyfile parser supports only these subdirectives:

- `name <full name>` with one or more words; multi-word names are joined with
  spaces.
- `email <address>`.
- `password <plain_text_or_bcrypt_value> [overwrite]`.
- `roles <role> [<role>...]`.
- `api key <key_id> <bcrypt_value_or_secret_reference>`.

Use `overwrite` when the configured password should replace the existing stored
password during provisioning. Passwords may be plaintext or
`bcrypt:<cost>:<hash>` values; authcrunch hashes plaintext passwords before
storing them.

Static user blocks are not a full sync mechanism. During local store
configuration, authcrunch creates the user when it does not exist. When the user
already exists, the static block updates only the password when `overwrite` is
present; it does not overwrite the user's name, email, or roles from the block.

For `api key`, use a stable 24-character key id and a bcrypt-formatted payload
or a placeholder/secret that resolves to one. Do not generate plaintext static
API key payload examples.

Do not generate unsupported user subdirectives. In particular, the underlying
`go-authcrunch/pkg/ids/local.User` struct has fields such as
`AuthChallengeRules` and API key `Overwrite`, but the current caddy-security
Caddyfile parser does not expose `auth_challenge_rules` or API key overwrite
syntax inside `user` blocks.

Authentication challenge rules may still exist in local user records and can be
managed outside the Caddyfile, such as with `authdbctl` or Profile API paths in
go-authcrunch. Rules use challenge names like `password`, `totp`, `u2f`, and
`mfa`, plus conditions such as `if u2f not available`. Treat those as runtime
user-database behavior for troubleshooting; do not add `auth challenges ...`
lines to generated local-user Caddyfile blocks until parser support and tests
exist.

## Secrets

Prefer environment placeholders or secret lookups for passwords and API keys:

```caddyfile
password "{env.USERS_ADMIN_SECRET}" overwrite
password "secrets:users/alice:password" overwrite
api key kid123456789012345678901 "secrets:users/alice:api_key"
```

Make sure API key placeholders and secret lookups resolve to a value in the
`bcrypt:<cost>:<hash>` form.

Use `configuration-secrets` and `configuration-runtime-resolution` for
secret-backed values.

## Review Checklist

Check generated local user entries against these code-backed constraints:

- The entry is inside `local identity store <name> { ... }`, not an LDAP store.
- The username is present and compatible with the local database policy; the
  default policy requires length 3-50.
- New users have a password compatible with the local database policy; the
  default policy requires length 8-128.
- `email`, when present, is a single valid email address.
- `roles` has at least one role when used.
- `password overwrite` has only the literal `overwrite` as its second argument.
- `api key` has exactly `key`, a 24-character key id, and one payload value.
- Static API key payloads are bcrypt-formatted or resolve to bcrypt-formatted
  values.

## Fixtures

Use these examples:

- `caddyfile_identity_store.go` for accepted Caddyfile subdirectives.
- `caddyfile_identity_store_test.go` for local store parser coverage.
- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`.

There is no current authoritative Caddyfile fixture covering static user API
keys; verify any generated example against both `caddyfile_identity_store.go`
and the `go-authcrunch` local identity-store code.
