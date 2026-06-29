---
name: configuration-oauth-providers
description: "caddy-security OAuth and OIDC identity provider Caddyfile configuration. Use when creating, reviewing, or modifying oauth identity provider blocks, Azure, GitHub, Google, LinkedIn, Discord, Facebook, Okta, Cognito, GitLab, Nextcloud, or generic OAuth providers, client IDs and secrets, scopes, id token cookies, icons, PKCE toggles, user group filters, JWKS keys, and portal enablement."
---

# Configuration OAuth Providers

## Purpose

Use this skill to configure `oauth identity provider <name>` blocks. The
Caddyfile syntax is authoritative in `caddyfile_identity.go` and
`caddyfile_identity_provider.go`; the provisioning behavior is authoritative in
the local `go-authcrunch` source, especially `pkg/idp/oauth/config.go`.

Do not use this skill for `sso provider <name>` blocks. Those configure the SSO
app/SAML role-assumption feature and belong in `configuration-sso-app`. Also do
not route `saml identity provider <name>` blocks here; they share the parser
file but use the local `go-authcrunch/pkg/idp/saml` implementation.

Use `assets/config/home.Caddyfile` as the nearest repository example for Azure,
GitHub, and LinkedIn OAuth providers.

## Shape

```caddyfile
security {
	oauth identity provider azure {
		realm azure
		driver azure
		tenant_id {env.AZURE_APP_TENANT_ID}
		client_id {env.AZURE_APP_CLIENT_ID}
		client_secret {env.AZURE_APP_CLIENT_SECRET}
		scopes openid email profile
		enable id token cookie id_token AZURE_ID_TOKEN
	}

	oauth identity provider github {
		realm github
		driver github
		client_id {env.GITHUB_APP_CLIENT_ID}
		client_secret {env.GITHUB_APP_CLIENT_SECRET}
		icon github priority 100
		disable pkce
	}

	authentication portal myportal {
		enable identity provider azure github
	}
}
```

The identity provider name must match the portal's
`enable identity provider <name>` value. The `realm` is what user transforms
usually match:

```caddyfile
transform user {
	match realm github
	action add role authp/user
}
```

## Supported Drivers

`go-authcrunch` currently supports these OAuth drivers:

```text
azure, cognito, discord, facebook, generic, github, gitlab, google, linkedin,
nextcloud, okta
```

Every OAuth provider needs `realm`, `driver`, `client_id`, and
`client_secret`; the Caddyfile provider name becomes authcrunch's config
`Name`. Use Caddy placeholders or secrets for client secrets.

The shortcut form is supported only for `github`, `google`, and `facebook`:

```caddyfile
oauth identity provider github {env.GITHUB_APP_CLIENT_ID} {env.GITHUB_APP_CLIENT_SECRET}
```

Prefer full blocks when adding icons, scopes, cookie behavior, or provider
toggles.

When `scopes` is omitted, authcrunch defaults by driver:

- `github`: `read:user`.
- `facebook`: `email`.
- `discord`: `identify`.
- `nextcloud`: `email`.
- `google`, `cognito`, `linkedin`, and the fallback for `azure`, `gitlab`,
  `okta`, and `generic`: `openid email profile`.

## Provider Notes

- Azure: include `tenant_id` when targeting a tenant. If omitted, authcrunch
  defaults to `common` and computes Azure base and metadata URLs from it.
- Google: authcrunch fills Google base and metadata URLs. If `client_id` has no
  dot, authcrunch appends `.apps.googleusercontent.com`.
- GitHub, Facebook, and Discord: authcrunch fills authorization and token URLs
  and requires only `access_token` in the token response.
- GitLab: authcrunch defaults `domain_name` to `gitlab.com` and computes base
  and metadata URLs from it.
- LinkedIn: defaults to OpenID-style scopes; `assets/config/home.Caddyfile`
  enables an id token cookie for this provider.
- Okta: requires `domain_name` and `server_id` even when overriding URLs. If
  `base_auth_url` is omitted, authcrunch computes base and metadata URLs from
  those fields; if `base_auth_url` is supplied manually, also supply
  `metadata_url` unless using the explicit static-key path below.
- Cognito: requires `region` and `user_pool_id`; authcrunch computes base and
  metadata URLs from them.
- Nextcloud: set `base_auth_url`; authcrunch derives the authorization and
  token URLs from it.
- Generic: always set a parseable `base_auth_url`. Then either set
  `metadata_url` for discovery, or set `authorization_url`, `token_url`, and
  `jwks key <kid> <pem_path>` together. The current repo fixtures pair the
  static-key form with `disable key verification`; without metadata discovery,
  authcrunch otherwise still attempts to fetch JWKS during provider setup.

## Provider-Side Claim Notes

Some OAuth failures require changes in the upstream provider console, not the
Caddyfile parser:

- Discord: the default `identify` scope yields the Discord user identity. Add
  `email` for email claims, `guilds` for guild membership, and
  `guilds.members.read` for guild role checks. When `user_group_filters`
  matches a guild, authcrunch can emit roles such as
  `discord.com/<guild_id>/members`, `discord.com/<guild_id>/admins`, and
  `discord.com/<guild_id>/role/<role_id>` for transform matching.
- GitHub: configure App account permissions for email addresses with read-only
  access when `/whoami` or transforms need email claims. Without this provider
  permission and user consent, email may be absent even when the Caddyfile is
  valid.
- Keycloak: create realm roles or groups that correspond to application roles,
  assign users to them, and add client mappers for email and groups/roles so
  the claims appear in tokens or userinfo. Missing mappers often look like a
  transform bug but are provider-side configuration.
- Cognito: configure required user-pool fields, app client callback/sign-out
  URLs, domain, and custom attributes before login. The legacy docs note that
  custom attributes such as `custom:roles` and `custom:timezone` may not appear
  in the issued portal token without additional provider/userinfo extraction
  behavior.
- Ping Identity, Auth0, OneLogin, and other hosted providers often require
  console-side callback URL, logout URL, scope, and claim mapping setup even
  when the generic Caddyfile shape is correct.

## Common Options

The parser accepts single-value OAuth fields such as `realm`, `driver`,
`tenant_id`, `domain_name`, `client_id`, `client_secret`, `server_id`,
`base_auth_url`, `metadata_url`, `authorization_url`, `token_url`,
`logout_url`, `region`, `user_pool_id`, `identity_token_field_name`, and
`user_info_roles_field_name`.

It accepts numeric retry and delayed-start fields:

```caddyfile
delay_start 10
retry_attempts 5
retry_interval 5
```

With `delay_start` but no retry settings, authcrunch defaults to two attempts
and uses `delay_start` as the retry interval. With `retry_attempts` but no
interval, authcrunch defaults the interval to 5 seconds.

It accepts repeatable/list fields:

```caddyfile
scopes openid email profile
user_group_filters "^github.com/example/"
user_org_filters "^example-org$"
response_type code
required_token_fields access_token id_token
jwks key main testdata/oauth/87329db33bf_pub.pem
```

It accepts userinfo extraction for generic OpenID providers with a discovered
`userinfo_endpoint`:

```caddyfile
extract email profile roles from userinfo
extract all from userinfo
user_info_roles_field_name roles
```

Accepted toggles include:

```caddyfile
disable metadata discovery
disable key verification
disable pass grant type
disable response type
disable scope
disable nonce
disable tls verification
disable email claim check
disable pkce
enable accept header
enable js callback
enable logout
enable id token cookie id_token AZURE_ID_TOKEN
```

`disable metadata discovery` is parsed into
`metadata_discovery_disabled`, but current authcrunch OAuth provider setup does
not use that flag by itself to skip discovery. To avoid metadata fetching,
configure explicit URLs as required by the driver and account for JWKS behavior.

`logout_url` also enables external provider logout behavior even without
`enable logout`.

External logout is separate from local portal logout. Without `enable logout`
or a manual `logout_url`, the portal clears local cookies but may leave the
upstream IdP session active. With `enable logout`, authcrunch uses
provider-specific logout handling when implemented. Current docs describe
redirect parameter behavior for Google (`continue`), Azure/GitLab/Okta
(`post_logout_redirect_uri`), Cognito (`logout_uri` plus client context),
GitHub (logout URL without redirect parameter), and generic providers (manual
URL as-is). For Facebook, Discord, LinkedIn, and Nextcloud, verify current
authcrunch source before promising provider-side session termination.

For id token cookies, use the spaced Caddyfile form:

```caddyfile
enable id token cookie
enable id token cookie id_token
enable id token cookie id_token AZURE_ID_TOKEN
```

The first optional value is the token response field to copy and must be
`id_token` or `access_token`; the second optional value is the cookie name.
When the cookie name is omitted, authcrunch uses `ID_TOKEN` for the provider
identity-token cookie.

## Review Checklist

Check generated OAuth provider entries against these code-backed constraints:

- Use `oauth identity provider <name>`, not `sso provider <name>`.
- Include `realm`, `driver`, `client_id`, and `client_secret`.
- Choose a driver supported by `go-authcrunch`.
- Add provider-specific required fields for Okta, Cognito, Nextcloud, and
  generic providers.
- For generic providers, include `base_auth_url` plus either `metadata_url` or
  explicit `authorization_url`, `token_url`, and static `jwks key` entries.
- Use `enable identity provider <name>` in the authentication portal.
- Use `match realm <realm>` in transforms when assigning roles after OAuth
  login.
- Use the spaced form `enable id token cookie ...`; avoid inventing
  `enable id_token cookie`.
- Treat `disable metadata discovery` as a parsed flag, not as sufficient
  runtime behavior by itself.
- Keep client secrets in placeholders or secret lookups.

## Fixtures

Use these examples:

- `assets/config/home.Caddyfile` for Azure, GitHub, and LinkedIn.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile` for
  OAuth plus portal and authorization wiring.
- `caddyfile_identity_provider.go` for accepted Caddyfile subdirectives.
- `go-authcrunch/pkg/idp/oauth/config.go` for driver defaults and validation.
