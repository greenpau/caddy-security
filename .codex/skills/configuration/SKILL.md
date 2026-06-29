---
name: configuration
description: "caddy-security Caddyfile configuration generation for the security app and authenticate or authorize HTTP directives. Use when creating, reviewing, or modifying Caddyfile configs for authentication portals, authorization policies, identity stores, OAuth or SAML identity providers, SSO app providers, users, registration flows, messaging, credentials, secrets, or runtime replacement in this repository."
---

# Configuration

## Purpose

Use this skill as the entry point for generating caddy-security Caddyfile
configuration. Keep the parent skill as a router: load only the domain skills
needed for the requested configuration.

The authoritative parser entry point is `caddyfile.go`. The global block is
`security { ... }`; route-level HTTP integrations reference configured objects
with `authenticate with <portal>` and `authorize with <policy>`.

Do not generate global Caddy directive-order overrides for caddy-security by
default. `authenticate` and `authorize` register their own order in
`plugin_authn.go` and `plugin_authz.go`. Only add global `order` directives
when debugging a proven directive-order conflict with another third-party
plugin, and explain why.

## Workflow

1. Identify the requested auth flow: local login, LDAP, OAuth/OIDC, SAML, API
   keys, basic auth, registration, SSO app, or policy-only authorization.
2. Load only the relevant `configuration-*` domain skills from the Domain Map
   before drafting the Caddyfile.
   Load `configuration-http-integrations` whenever adding route-level
   `authenticate` or `authorize` handlers.
   Load `configuration-saml-providers` for `saml identity provider <name>`
   blocks; do not substitute the SSO app skill.
   Load `authentication-portal-api` when the request involves Portal API,
   JSON login, `/whoami`, `/beacon`, or admin/server API endpoints.
3. Start from the smallest valid `security` app block, then add route handlers
   that reference the configured portal or policy by name.
4. Prefer environment placeholders or secret lookups for passwords, API keys,
   client secrets, signing keys, and private material.
5. Check generated syntax against the parser files and the fixtures under
   `testdata/caddyfile_adapt/`. Use the `testing-and-ci` skill if validation
   requires running tests or updating fixtures.

## Common Shape

```caddyfile
{
	security {
		local identity store localdb {
			realm local
			path assets/config/users.json
		}

		authentication portal myportal {
			crypto key sign-verify {env.JWT_SHARED_KEY}
			enable identity store localdb
		}

		authorization policy app_policy {
			crypto key verify {env.JWT_SHARED_KEY}
			set auth url /auth
			allow roles authp/admin authp/user
		}
	}
}

example.com {
	route /auth* {
		authenticate with myportal
	}

	route /app* {
		authorize with app_policy
		reverse_proxy 127.0.0.1:8080
	}
}
```

Use the optional matcher forms only when needed:

```caddyfile
authenticate /auth* with myportal
authorize /api/* with api_policy
```

## Domain Map

- HTTP integrations: `configuration-http-integrations`, parsed by
  `plugin_authn.go` and `plugin_authz.go`.
- Authentication portals: `configuration-authentication`, parsed by
  `caddyfile_authn.go` and `caddyfile_authn_*.go`.
- Authorization policies: `configuration-authorization`, parsed by
  `caddyfile_authz.go` and `caddyfile_authz_*.go`.
- Crypto directives and token or System API keys:
  `configuration-crypto`, parsed by `caddyfile_authn_crypto.go` and
  `caddyfile_authz_crypto.go`, implemented by local
  `go-authcrunch/pkg/kms`, and resolved by `caddyfile_resolve.go`.
- Reusable generic credentials: `configuration-credentials`, parsed by
  `caddyfile_credentials.go`.
- Local and LDAP stores: `configuration-identity-stores`, parsed by
  `caddyfile_identity.go` and `caddyfile_identity_store.go`.
- Messaging providers: `configuration-messaging`, parsed by
  `caddyfile_messaging.go`.
- OAuth/OIDC identity providers: `configuration-oauth-providers`, parsed by
  `caddyfile_identity.go` and `caddyfile_identity_provider.go`.
- SAML login identity providers: `configuration-saml-providers`, parsed by
  `caddyfile_identity.go` and `caddyfile_identity_provider.go`, implemented by
  local `go-authcrunch/pkg/idp/saml`.
- User registrations: `configuration-registrations`, parsed by
  `caddyfile_user.go` and `caddyfile_user_registration.go`.
- Runtime placeholder and secret resolution: `configuration-runtime-resolution`,
  applied by `caddyfile_resolve.go`.
- Secrets managers and secret lookup syntax: `configuration-secrets`, parsed by
  `caddyfile_secrets.go` and resolved by `caddyfile_resolve.go`.
- SSO app providers: `configuration-sso-app`, parsed by
  `caddyfile_sso_provider.go`.
- Local user entries in identity stores: `configuration-users`, parsed inside
  `caddyfile_identity_store.go`.
- Portal JSON/admin APIs: `authentication-portal-api`, implemented by local
  `go-authcrunch/pkg/authn/handle_*` handlers and enabled in Caddyfile by
  authentication portal options.

Keep this map synchronized with every directory matching
`.codex/skills/configuration-*`.

SAML identity-provider blocks are distinct from SSO app providers. Use
`configuration-saml-providers` for login through external SAML IdPs and
`configuration-sso-app` for portal-provided SAML SSO app endpoints.

## Fixtures

Use these examples for orientation:

- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`
  for local users, portal crypto, cookies, UI links, and transforms.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile` for
  OAuth plus authorization policy wiring.
- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`
  for registration, messaging, local users, and portal wiring.
- `testdata/caddyfile_adapt/testcase_security_with_secrets.Caddyfile` for
  secrets manager values consumed by users and crypto keys.
