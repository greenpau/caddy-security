---
name: configuration-identity-stores
description: "caddy-security local and LDAP identity store Caddyfile configuration. Use when creating, reviewing, or modifying local identity store blocks, LDAP identity store blocks, local user records, store shortcuts, realms, user files, LDAP bind settings, servers, search filters, attributes, groups, recovery settings, support links, fallback roles, and login icons."
---

# Configuration Identity Stores

## Purpose

Use this skill to configure `local identity store <name>` and
`ldap identity store <name>` blocks. The dispatcher is `caddyfile_identity.go`;
the store parser is `caddyfile_identity_store.go`.

Use `configuration-users` for detailed local `user <username>` entries.
Check `github.com/greenpau/go-authcrunch/pkg/ids` when changing this skill:
`ids.Config.Validate` admits only `local` and `ldap` stores and validates the
authcrunch parameter names produced by the Caddyfile parser.

## Local Stores

Local stores require `realm` and `path` in the authcrunch config. The full
Caddyfile form is:

```caddyfile
security {
	local identity store localdb {
		realm local
		path assets/config/users.json
	}
}
```

The local shortcut is valid and sets `realm local` plus the user file path.
Only local stores support this shortcut:

```caddyfile
local identity store localdb assets/config/users.json
```

Add users inline only when the Caddyfile should own the local account data:

```caddyfile
user alice {
	name "Alice Example"
	email alice@example.com
	password {env.ALICE_PASSWORD} overwrite
	roles authp/user authp/admin
}
```

Local store-level options supported by authcrunch are `login_icon`,
`username_recovery_enabled`, `password_recovery_enabled`,
`contact_support_enabled`, `support_link`, and `support_email`. In Caddyfile,
set those with `icon`, `enable username recovery`, `enable password recovery`,
`enable contact support`, `support link`, and `support email`.

## LDAP Stores

LDAP stores require `realm` and `servers` at config-validation time. At
provisioning time authcrunch also needs bind credentials, `search_base_dn`, and
either explicit `groups` or automatic group mapping. Use this practical shape:

```caddyfile
ldap identity store corp {
	realm corp.example.com
	servers {
		ldaps://ldap.example.com ignore_cert_errors
	}
	username "CN=authsvc,OU=Service Accounts,DC=example,DC=com"
	password {env.LDAP_BIND_PASSWORD}
	search_base_dn "DC=example,DC=com"
	search_filter "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
	attributes {
		name givenName
		surname sn
		username sAMAccountName
		member_of memberOf
		email mail
	}
	groups {
		"CN=Admins,OU=Groups,DC=example,DC=com" authp/admin
		"CN=Users,OU=Groups,DC=example,DC=com" authp/user
	}
}
```

Use these Caddyfile-to-authcrunch aliases deliberately:

- `username` becomes `bind_username`; do not write `bind_username` in Caddyfile.
- `password` becomes `bind_password`; if omitted, authcrunch falls back to
  `LDAP_USER_SECRET` during provisioning.
- `search_filter` is a legacy alias for `search_user_filter`; prefer
  `search_user_filter` for clarity when adding new examples.
- `trusted_authority <path>` appends to authcrunch `trusted_authorities`.
- `icon` becomes `login_icon`.

LDAP server addresses must start with `ldap://` or `ldaps://`. Authcrunch uses
default ports `389` and `636`, or a port in the URL, and defaults timeout to 5
seconds; the Caddyfile parser currently exposes only `ignore_cert_errors` and
`posix_groups` server flags.

If `search_user_filter`, `search_group_filter`, or `attributes` are omitted,
authcrunch defaults to Active Directory-style values:
`sAMAccountName`/`mail`, `memberOf`, `givenName`, `sn`, and
`(&(uniqueMember=%s)(objectClass=groupOfUniqueNames))`. Override them for POSIX
or non-AD directories.

Group mapping rules:

- Use `groups { <group_dn> <role> [<role>...] }` for explicit LDAP DN to role
  mappings.
- Use `enable short automatic group mapping` to map group DNs to the lower-case
  first RDN value, such as `ou=mathematicians,...` to `mathematicians`.
- Use `enable full automatic group mapping` to map group DNs to lower-case full
  DN roles.
- Add `posix_groups` on a server when group membership must be found through
  `search_group_filter` instead of the user's `member_of` attribute.
- Authcrunch supports `fallback_roles` for roles assigned when the user
  authenticates but no LDAP group mapping produced roles. It does not replace
  the requirement for explicit or automatic group mapping to configure LDAP.
- Do not add new Caddyfile fallback-role examples until
  `caddyfile_identity_store.go` is fixed and tested: the current parser stores
  `args[2:]`, so ordinary `fallback role authp/user` drops the first role.

## Store Options

Supported store-level options include:

- `disabled`
- `realm`, `path`, `search_base_dn`, `search_group_filter`,
  `search_user_filter`, `search_filter`, `username`, and `password`
- `trusted_authority <path>`
- `attributes { <local_name> <remote_name> }`
- `servers { <ldap_url> [ignore_cert_errors] [posix_groups] }`
- `groups { <group_dn> <role> [<role>...] }`
- `enable username recovery`, `enable password recovery`,
  `enable contact support`
- `enable full automatic group mapping` and
  `enable short automatic group mapping`
- `support link <url>` and `support email <address>`
- `icon <text> ...`

Do not invent raw authcrunch JSON field names as Caddyfile directives unless
the parser accepts them. In particular, Caddyfile uses `username`, `password`,
`trusted_authority`, and `search_filter`/`search_user_filter`, while the
adapted authcrunch config stores `bind_username`, `bind_password`,
`trusted_authorities`, and `search_user_filter`.

## Portal Wiring

After defining a store, enable it from an authentication portal:

```caddyfile
authentication portal myportal {
	enable identity store localdb corp
}
```

## Fixtures

Use these examples:

- `caddyfile_identity_test.go`.
- `caddyfile_identity_store_test.go`.
- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`.
