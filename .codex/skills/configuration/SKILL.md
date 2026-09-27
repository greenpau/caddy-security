---
name: configuration
description: "Build or review caddy-security Caddyfiles and select focused configuration skills. Use for security app declarations and authenticate/authorize route wiring."
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
Define the global `security` option once; duplicate blocks fail instead of
silently replacing the previous app. Collect declarations inside that one block.

Do not generate global Caddy directive-order overrides for caddy-security by
default. `authenticate` and `authorize` register their own order in
`plugin_authn.go` and `plugin_authz.go`. Only add global `order` directives
when debugging a proven directive-order conflict with another third-party
plugin, and explain why.

## Syntax Currency

Use [Syntax maintenance](references/syntax-maintenance.md) when auditing syntax,
changing directives, or consuming a Caddy/go-authcrunch dependency update.
The [AuthCrunch compatibility map](references/authcrunch-compatibility.md)
tracks changed upstream surfaces, Caddy ownership and validation.
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
2. Follow only the matching Domain Map routes before drafting the Caddyfile.
   HTTP handler placement includes the HTTP integration route; external SAML
   login follows the SAML provider route, separately from portal SSO apps.
   Authentication's narrower routes cover portal sub-blocks. HTTP client/API
   contracts belong to [authentication-portal-api](../authentication-portal-api/SKILL.md).
3. Start from the smallest valid `security` app block, then add route handlers
   that reference the configured portal or policy by name.
4. Prefer environment placeholders or secret lookups for passwords, API keys,
   client secrets, signing keys, and private material.
5. Check generated syntax against the local wrappers, selected upstream grammar
   and validators, and the fixtures under
   `testdata/caddyfile_adapt/`. Test and fixture changes follow the
   [testing contract](../testing-and-ci/SKILL.md).

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
	@portal path /auth /auth/*
	route @portal {
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
@portal path /auth /auth/*
authenticate @portal with myportal
authorize /api/* with api_policy
```

## Domain Map

- Use [configuration-logging](../configuration-logging/SKILL.md) to configure
  diagnostic skip rules, parsed by `caddyfile_logging.go`. AuthCrunch component
  filtering is supported; Caddy's independent authentication middleware logger
  needs an upstream hook.
- Use [configuration-state](../configuration-state/SKILL.md) to configure
  persistent runtime state, parsed by `caddyfile_state.go`. Stop/start persistence
  also supports policy-only OAuth.
- Use [configuration-http-integrations](../configuration-http-integrations/SKILL.md)
  to place `authenticate` and `authorize` HTTP routes, parsed by `plugin_authn.go`
  and `plugin_authz.go`.
- Use [configuration-authentication](../configuration-authentication/SKILL.md)
  to configure authentication portals, parsed by `caddyfile_authn.go` and
  `caddyfile_authn_*.go`. Its routes own cookies, UI, transforms, and Portal APIs.
- Use [configuration-authorization](../configuration-authorization/SKILL.md)
  to configure authorization policies, parsed by `caddyfile_authz.go` and
  `caddyfile_authz_*.go`.
- Use [configuration-crypto](../configuration-crypto/SKILL.md) to configure
  crypto directives and token or System API keys, parsed by
  `caddyfile_authn_crypto.go` and `caddyfile_authz_crypto.go`, implemented by
  `go-authcrunch/pkg/kms`, and resolved by `caddyfile_resolve.go`.
- Use [configuration-credentials](../configuration-credentials/SKILL.md) to
  configure reusable generic credentials, parsed by `caddyfile_credentials.go`.
- Use [configuration-identity-stores](../configuration-identity-stores/SKILL.md)
  to configure local and LDAP stores, parsed by `caddyfile_identity.go` and
  `caddyfile_identity_store.go`.
- Use [configuration-messaging](../configuration-messaging/SKILL.md) to
  configure messaging providers, parsed by `caddyfile_messaging.go`.
- Use [configuration-oauth-providers](../configuration-oauth-providers/SKILL.md)
  to configure external OAuth/OIDC identity providers, parsed by
  `caddyfile_identity.go`, `caddyfile_identity_provider.go`, and
  `caddyfile_identity_provider_oauth.go`, delegated to
  `go-authcrunch/pkg/idp/parser` and `pkg/idp/oauth/parser`.
- Use [configuration-oauth-applications](../configuration-oauth-applications/SKILL.md)
  to register named OAuth clients, configure private registration storage and
  portal `oidc provider` blocks, or provision credentials through the CLI.
  `caddyfile_oauth_application.go` delegates client parsing to
  `go-authcrunch/pkg/oidc/parser` and `Config.AddOAuthApplication`. Clients have
  explicit or persisted credentials. `caddyfile_oauth_registration_store.go`
  parses `oauth registration store`; app JSON uses `oauth_registration_store`.
  This holds application credentials and provider keys independently of user
  registration and sessions.
- Use [configuration-saml-providers](../configuration-saml-providers/SKILL.md)
  to configure SAML login identity providers, parsed by `caddyfile_identity.go`
  and `caddyfile_identity_provider.go`, implemented by `go-authcrunch/pkg/idp/saml`.
- Use [configuration-registrations](../configuration-registrations/SKILL.md) to
  configure user registrations, parsed by `caddyfile_user.go` and
  `caddyfile_user_registration.go`.
- Use [configuration-runtime-resolution](../configuration-runtime-resolution/SKILL.md)
  to configure runtime placeholder and secret resolution, applied by
  `caddyfile_resolve.go`.
- Use [configuration-secrets](../configuration-secrets/SKILL.md) to configure
  secrets managers and secret lookups, parsed by `caddyfile_secrets.go` and
  resolved by `caddyfile_resolve.go`.
- Use [configuration-sso-app](../configuration-sso-app/SKILL.md) to configure
  SSO app providers, parsed by `caddyfile_sso_provider.go`.

Portal JSON/admin API contracts belong to
[authentication-portal-api](../authentication-portal-api/SKILL.md), routed from
`configuration-authentication`. The upstream `go-authcrunch/pkg/authn/handle_*`
handlers implement them; authentication portal options enable them in Caddyfile.

Keep this map and its intermediate authentication routes synchronized with every
directory matching `.codex/skills/configuration-*`.

SAML identity-provider blocks are distinct from SSO app providers: the SAML
provider route configures external login, while the SSO app route configures
portal-provided SAML app endpoints.

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

## Acceptance criteria

- A requested login/provider combination has one owning route; external SAML
  login, SAML SSO apps, external OAuth login, and portal OIDC clients remain distinct.
- Complete examples include global security declarations, matching portal/policy
  names, and exact portal mounts. Fragments state the enclosing scope and missing
  wiring; successful adaptation alone is not reported as successful login.
- Runtime values are checked against the fields that actually resolve. Missing
  plugins or unsupported upstream behavior remain explicit qualification limits.
