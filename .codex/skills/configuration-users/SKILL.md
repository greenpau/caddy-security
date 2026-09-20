---
name: configuration-users
description: "caddy-security local user account Caddyfile configuration. Use when creating, reviewing, or modifying local identity store user entries, usernames, display names, email addresses, plaintext or bcrypt passwords, overwrite behavior, roles, static API key prefixes and payloads, authentication challenge rules, and secret-backed user attributes."
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
- `auth challenges <rule body>`; repeat to append ordered rules.

Use `overwrite` when the configured password should replace the existing stored
password during provisioning. Passwords may be plaintext or
`bcrypt:<cost>:<hash>` values; authcrunch hashes plaintext passwords before
storing them.

Duplicate password updates can reuse the active hash while still advancing the
account's credential version. Legacy records without `credential_version`
remain supported. See [local identity compatibility](../configuration-identity-stores/references/local-identity.md)
for update versus reset behavior, invalidation, and Caddy tests.

Static user blocks are not a full sync mechanism. During local store
configuration, authcrunch creates the user when it does not exist. When the user
already exists, `password ... overwrite` replaces its password; configured API
keys are passed to the upstream key operation, and explicit challenge rules
replace its stored rules. Name, email and roles are not synchronized. Keep the
configured email consistent with the existing identity.

For `api key`, use a stable 24-character key id and a bcrypt-formatted payload
or a placeholder/secret that resolves to one. Do not generate plaintext static
API key payload examples.

## Stored authentication rules

For example, inside `user alice`, repeat rule bodies in preference order:

```caddyfile
auth challenges u2f
auth challenges password totp if u2f not available
auth challenges password if u2f and totp not available
```

The shared challenge parser validates the complete list. Methods are `password`,
`totp`, `u2f`, and `mfa`; adjacent methods require all, `or` selects the first
available choice, and `if ... [and ...] not available` tests registered
credentials. Email challenges/conditions, duplicates, empty and malformed rules
fail adaptation. Keywords must be literal. See the
[conditional transform grammar](../configuration-authentication-user-transforms/SKILL.md#conditional-authentication)
for selection, precedence and verified AMR. A matching transform policy can
replace the stored selection.

Explicit static rules are applied both when creating and when provisioning an
existing user. Omitting them preserves the stored policy; removing lines does
not reset it. Caddyfile rules do not enroll factors. Ensure users have the
credentials required by a rule or provide a deliberate fallback.

Use [profile flow management](../authentication-portal-api/references/authentication-flows.md)
for user-owned changes or an explicit reset with an empty `challenges` array.
[`security local update user`](../scripts-and-automation/references/local-user-commands.md)
replaces rules through the server API, which requires a nonempty list. The static API-key directive still has no `overwrite` suffix;
do not invent one from the upstream struct field.

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
- Repeated `auth challenges` rules form one validated, ordered policy.
- `password overwrite` has only the literal `overwrite` as its second argument.
- `api key` has exactly `key`, a 24-character key id, and one payload value.
- Static API key payloads are bcrypt-formatted or resolve to bcrypt-formatted
  values.

## Fixtures

Use these examples:

- `caddyfile_identity_store.go` for accepted Caddyfile subdirectives.
- `caddyfile_identity_store_test.go` for local store parser coverage.
- `testcase_authenticate_with_challenges` for adaptation and resolution.
- `TestCaddyAuthenticationChallengesE2E` for stored policy creation, replacement,
  omission, native login and profile policy management through Caddy.
- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`.

`testcase_security_with_secrets` contains the static API-key lookup form.
`TestIdentityStoreSecretsFixture` checks its local-user block independently of
the optional external module, and the challenge E2E provisions a bcrypt API
key through the Caddyfile and exercises native login and policy rejection.
