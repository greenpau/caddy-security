---
name: configuration
description: "caddy-security Caddyfile configuration generation for the security app and authenticate or authorize HTTP directives. Use when creating, reviewing, or modifying Caddyfile configs for authentication portals, authorization policies, identity stores, OAuth or SAML identity providers, SSO app providers, users, registration flows, messaging, credentials, secrets, or runtime replacement in this repository."
---

# Configuration

## Purpose

Use this skill as the entry point for generating caddy-security Caddyfile
configuration. Keep the parent skill as a router: load only the domain skills
needed for the requested configuration.

The [repository scope](../coding-directives/SKILL.md#repository-scope) applies
to every configuration domain. Upstream paths in these skills are read-only
implementation references. Keep Caddyfiles, fixtures, custom assets, and local
validation changes here; missing upstream behavior is separate work, not a
reason to edit or run tests in `../go-authcrunch`.

The parser entry point is `caddyfile.go`. Put `security { ... }` inside Caddy's
outer global options block, `{ ... }`. Route-level HTTP integrations reference
configured objects with `authenticate with <portal>` and `authorize with <policy>`.

Do not generate global Caddy directive-order overrides for caddy-security by
default. `authenticate` and `authorize` register their own order in
`plugin_authn.go` and `plugin_authz.go`. Only add global `order` directives
when debugging a proven directive-order conflict with another third-party
plugin, and explain why.

## Syntax Currency

Use [Syntax maintenance](references/syntax-maintenance.md) when auditing syntax,
changing directives, or consuming a Caddy/go-authcrunch dependency update.
The Caddy wrappers and the selected upstream parsers jointly define the syntax.
Maintain Go syntax comments, standalone Caddyfiles, fixtures, and domain skills
together, including grammar delegated to upstream libraries or external modules.

Keep recognized-but-restricted forms visible with their validation status.
For example, document `logout_url <logout_url>` and the shared OAuth validator's
rejection; do not erase it or silently filter it from input. Upstream typed
fields alone do not establish Caddyfile support.

Examples containing only inner blocks or individual directives are fragments
for the enclosing scope described by the domain skill. Complete configurations
need the outer global block and site routes. `<value>` denotes a required value,
`<a|b>` a required choice, `[value]` an optional argument, and `...` repetition;
syntax catalogues with these placeholders are not runnable examples.

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
5. Check generated syntax against the local wrappers, selected upstream grammar
   and validators, and the fixtures under
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
  `caddyfile_identity.go`, `caddyfile_identity_provider.go`, and
  `caddyfile_identity_provider_oauth.go`, delegated to
  `go-authcrunch/pkg/idp/parser` and `pkg/idp/oauth/parser`.
- Named OAuth applications: `configuration-oauth-applications`, parsed by
  `caddyfile_oauth_application.go`, delegated to `go-authcrunch/pkg/oidc/parser`
  and `Config.AddOAuthApplication`. These register clients with explicit
  or persisted credentials; the same skill owns private provisioning and the
  portal `oidc provider` block that selects clients.
- OAuth registration storage: `configuration-oauth-applications`, parsed by
  `caddyfile_oauth_registration_store.go` as `oauth registration store`; app JSON
  uses `oauth_registration_store`. This holds application credentials and provider
  keys independently of user registration and sessions.
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

Use [qualified operator examples](references/operator-examples.md) for complete
outer Caddyfiles and their generated, tested native JSON: legacy access, local
token refresh, Ed25519 upstream OAuth, named applications, two OPs with refresh,
and explicit administrative private export. It covers private setup, exact
provisioning commands, realm/token/cookie boundaries and replacement limits.

Use these examples for orientation:

- `testdata/caddyfile_adapt/testcase_security_authentication_portal.Caddyfile`
  for local users, portal crypto, cookies, UI links, and transforms.
- `testdata/caddyfile_adapt/testcase_authenticate_with_oauth.Caddyfile` for
  OAuth plus authorization policy wiring.
- `testdata/caddyfile_adapt/testcase_authenticate_with_registration.Caddyfile`
  for registration, messaging, local users, and portal wiring.
- `testdata/caddyfile_adapt/testcase_security_with_secrets.Caddyfile` for
  secrets manager values consumed by users and crypto keys.
