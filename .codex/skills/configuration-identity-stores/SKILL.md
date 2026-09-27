---
name: configuration-identity-stores
description: "Configure local or LDAP identity stores, realms, databases, binds, TLS trust, searches, and group mappings. Delegates static account entries to configuration-users."
---

# Configuration Identity Stores

## Purpose

Use this skill to configure `local identity store <name>` and
`ldap identity store <name>` blocks. The dispatcher is `caddyfile_identity.go`;
the store parser is `caddyfile_identity_store.go`.

Use [configuration-users](../configuration-users/SKILL.md) to configure static
`user <username>` entries, password imports, API keys, and stored challenge rules.
For password verification, credential versions, management/profile mutations,
reload invalidation, and Caddy qualification, read
[local identity compatibility](references/local-identity.md).
Check `github.com/greenpau/go-authcrunch/pkg/ids` when changing this skill:
`ids.Config.Validate` admits only `local` and `ldap` stores and validates the
authcrunch parameter names produced by the Caddyfile parser.

## Local Stores

Local stores require `realm` and `path` in the authcrunch config. The full
Caddyfile form is:

```caddyfile
{
	security {
		local identity store localdb {
			realm local
			path assets/config/users.json
		}
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

Authcrunch creates a missing local database and bootstraps an administrative
user whenever the loaded database has no administrator, including an existing
database. Configure the bootstrap password explicitly before first startup:
the selected library logs the created username, email and roles, but does not
log the generated password. These environment variables set the account:

```text
AUTHP_ADMIN_USER
AUTHP_ADMIN_EMAIL
AUTHP_ADMIN_SECRET
```

The local database stores password and username policy fields. The default
password policy requires length 8-128, and the default username policy requires
length 3-50. Users with non-guest portal access can change their password from
the portal profile/settings UI; administrators can reset passwords and manage
users through [`security local`](../scripts-and-automation/references/local-user-commands.md)
or `authdbctl`. These commands use the running portal's admin API.

## LDAP Stores

LDAP stores require `realm` and `servers` at config-validation time. At
provisioning time authcrunch also needs bind credentials, `search_base_dn`, and
either explicit `groups` or automatic group mapping. Use this practical shape:

```caddyfile
ldap identity store corp {
	realm corp.example.com
	servers {
		ldaps://ldap.example.com
	}
	trusted_authority /etc/caddy/ldap/corp-ca.pem
	username "CN=authsvc,OU=Service Accounts,DC=example,DC=com"
	password {env.LDAP_BIND_PASSWORD}
	search_base_dn "DC=example,DC=com"
	search_user_filter "(&(|(sAMAccountName=%s)(mail=%s))(objectclass=user))"
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

Prefer `trusted_authority <path>` for LDAPS trust over `ignore_cert_errors`.
When collecting a server certificate chain for trust configuration, use
`openssl s_client -showcerts` against the LDAPS endpoint, split the PEM
certificates, verify the intended CA against the directory operator's trust
material, and point `trusted_authority` at those CA files. A certificate
retrieved from the endpoint alone does not establish trust in that endpoint.

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
- Use `fallback role authp/user` or `fallback roles authp/user directory/member`
  inside an LDAP store. All supplied roles survive adaptation; repeating the
  directive replaces the list. Local stores reject this LDAP-only setting.
  `TestIdentityStoreFallbackRoles` checks typed mapping; the LDAP journey in
  `TestCaddyAuthenticationChallengesE2E` verifies a real service bind, user bind,
  signed role claims and protected route over disposable verified LDAPS/TLS.

Runtime LDAP authentication flow:

1. Identification opens a fresh service-bound connection, escapes the submitted
   username/email for `search_user_filter`, and searches under `search_base_dn`.
2. Identification fails unless exactly one user object is found.
3. It maps LDAP group DNs to roles from explicit or automatic group mapping.
   If no role is produced and no supported fallback applies, authentication
   fails before token issuance.
4. Password authentication opens another fresh service-bound connection,
   repeats the user search, then binds as the found user DN with the submitted
   password. Completing the required challenges allows token issuance.

Connections are closed after each operation; identification and password
verification do not share a long-lived connection.

This flow means a correct-looking Caddyfile can still fail because the search
filter is too broad, group membership does not map to any role, LDAPS trust is
missing, or service bind credentials are wrong.

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

The LDAP journey in `ldap_fallback_e2e_test.go`, invoked by
`TestCaddyAuthenticationChallengesE2E`, checks verified LDAPS, fallback role
claims and a protected route. It does not qualify every directory schema,
POSIX group lookup, or production CA configuration. For those changes, verify
exactly-one-user selection, explicit and automatic mapping, unmapped-user
rejection or fallback, wrong-password rejection and trust failures against a
disposable directory before claiming login compatibility.
