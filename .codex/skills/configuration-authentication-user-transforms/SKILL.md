---
name: configuration-authentication-user-transforms
description: "caddy-security authentication portal user transform Caddyfile configuration. Use when creating, reviewing, or modifying authentication portal transform user blocks, transform matchers, ACL condition syntax, add or overwrite role actions, drop matched role actions, MFA requirements, block or deny transforms, transform UI links, or authcrunch claim replacement placeholders."
---

# Configuration Authentication User Transforms

## Purpose

Use this skill for `transform user` blocks inside `authentication portal <name>`
blocks.

Read these files when details matter:

- `caddyfile_authn_transform.go` for Caddyfile transform forwarding.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/transformer/` for
  supported transform actions and claim replacement behavior.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/acl/condition.go` for ACL
  matcher grammar.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/acl/acl.go` for field
  aliases and field data types.

Use `configuration-authentication` for the surrounding portal and
`configuration-authentication-ui` for regular portal `ui` blocks.

## Transform Shape

The Caddyfile parser forwards matcher and action strings to authcrunch:

```caddyfile
authentication portal myportal {
	transform user {
		match origin local
		action add role authp/user
		require mfa
		ui link "User Profile" /auth/profile/ icon "las la-cog"
	}
}
```

`transform user` and `transform users` are accepted. Each transform must have
at least one matcher and one action after authcrunch parses it.

## Matchers

Bare `match ...` lines become exact ACL matches because the Caddyfile parser
prepends `exact`. Use explicit match strategies when exact matching is not
intended:

```caddyfile
match origin local
partial match email @example.com
regex match role ^authp/(admin|user)$
no regex match any role ^authp/(admin|user)$
```

Authcrunch ACL grammar has `match any`, but the current Caddyfile transform
parser cannot emit that exact string because bare `match ...` gets rewritten to
`exact match ...`. The same parser classification means `field <name> exists`
ACL conditions are not usable as Caddyfile transform matchers today.

Useful field aliases include `role`, `group`, and `groups` for `roles`; `mail`
for `email`; `subject` for `sub`; and `ip`, `ipv4`, or `address` for `addr`.

## Actions

Practical transform actions are `add`, `overwrite`, `drop matched role`,
`require`, `block`/`deny`, and `ui link`. `action add|overwrite|drop ...` is
normalized by authcrunch:

```caddyfile
action add role authp/user
action overwrite roles authp/user
action drop matched role
require mfa
block
deny
ui link "User Profile" /auth/profile/ icon "las la-cog"
```

Do not rely on `delete` until authcrunch `transformData` implements it
end-to-end.

For custom claims, include an explicit data type:

```caddyfile
action add matrix_id "@{claims.sub}:matrix.example.com" as string
action add _couchdb.roles _admin as string list
```

Transform values may use authcrunch claim replacements such as
`{claims.realm}/user` or `{claims.email}`. These are authcrunch transform
placeholders, not Caddy runtime replacer placeholders.

## Fixtures

Use this fixture as the main example:

- `testdata/caddyfile_adapt/testcase_authenticate_with_ui.Caddyfile`
