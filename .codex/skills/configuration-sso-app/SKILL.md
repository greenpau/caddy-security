---
name: configuration-sso-app
description: "caddy-security SSO app Caddyfile configuration for Single Sign-On with SAML. Use when creating, reviewing, or modifying sso provider blocks, AWS SAML app drivers, SAML entity IDs, signing certificates, PKCS8 private keys, SSO metadata locations, authentication portal enablement, /apps/sso endpoints, and AWS role naming."
---

# Configuration SSO App

## Purpose

Use this skill to configure the SSO app feature, expressed in Caddyfile as
`sso provider <name>`. This is the Single Sign-On with SAML app path, not OAuth
login provider setup.

Use `configuration-oauth-providers` for `oauth identity provider <name>` blocks
such as Azure, GitHub, Google, LinkedIn, or generic OIDC.

For `saml identity provider <name>` login-provider blocks, inspect
`caddyfile_identity_provider.go` and local `go-authcrunch/pkg/idp/saml`; those
blocks are not the SSO app either.

The Caddyfile syntax is authoritative in `caddyfile_sso_provider.go`; the
provisioning behavior is authoritative in the local `go-authcrunch` source,
especially `pkg/sso/config.go`, `pkg/sso/provider.go`, `pkg/sso/request.go`,
`pkg/sso/metadata.go`, and `pkg/authn/handle_http_apps_sso.go`.

## Shape

```caddyfile
security {
	sso provider aws {
		entity_id caddy-authp-idp
		driver aws
		cert assets/sso/authp_saml.crt
		private key assets/sso/authp_saml.key
		location https://example.com/auth/apps/sso/aws
	}

	authentication portal myportal {
		enable sso provider aws
	}
}
```

The provider name must be unique and must match the portal's
`enable sso provider <name>` value.

## Supported Fields

The current Caddyfile parser supports only these lines:

- `disabled`
- `entity_id <name>` mapped to authcrunch `entity_id`
- `driver aws` mapped to authcrunch `driver`
- `cert <path>` mapped to authcrunch `cert_path`
- `private key <path>` mapped to authcrunch `private_key_path`
- `location <url>` appended to authcrunch `locations`

Although `driver` is syntactically optional in the Caddyfile parser, generate
`driver aws`. `go-authcrunch` rejects an empty driver and currently supports
only `aws`.

At least one `location <url>` is required by the Caddyfile parser, even for a
`disabled` provider. Multiple locations are allowed and become SAML
`SingleSignOnService` entries in generated metadata. Authcrunch embeds each
configured location verbatim, so use the externally reachable SSO POST URL,
including any portal base-path prefix such as `/auth`.

The certificate file must be PEM with block type `CERTIFICATE`. The private key
file must be PEM with block type `PRIVATE KEY` and parse as a PKCS8 private key.
Do not use `RSA PRIVATE KEY` examples unless the underlying authcrunch parser
changes.

If a provider is marked `disabled`, it is not added to the authcrunch
configuration. Do not enable a disabled provider from a portal; authcrunch
validation expects enabled portal SSO provider names to have matching provider
configuration.

## Portal URLs And Roles

The auth portal recognizes SSO app endpoints by the `/apps/sso/<provider>` path
inside the portal route. With the common `/auth` portal base path used by this
repo's configs and fixtures, external URLs are usually under
`/auth/apps/sso/<provider>`:

```text
/auth/apps/sso/aws
/auth/apps/sso/aws/metadata.xml
/auth/apps/sso/aws/assume/<account_id>/<role_name>
```

If the authenticate route is mounted at a different base path, keep that prefix
in the external URL. `go-authcrunch/pkg/sso/request.go` parses the first
`/apps/sso/` segment in the request path, so `/custom/apps/sso/aws` and
`/auth/apps/sso/aws` both map to provider `aws`.

Use `<base-path>/apps/sso/<provider>/metadata.xml` when a SAML service needs
generated IdP metadata. The configured `location` values are embedded in that
metadata as HTTP-POST SSO service locations.

Current authcrunch handling requires an authenticated portal session before
serving the SSO menu, metadata, or assume-role endpoint. Despite the metadata
handler comment, no admin role check is implemented for metadata in
`handle_http_apps_sso.go`.

For AWS role selection, user roles must use this shape:

```text
aws/<account_id>/<role_name>
```

For example, a local user might have:

```caddyfile
roles authp/user aws/123456789012/Administrator
```

The current local authcrunch assume-role handler returns a placeholder response
for `<base-path>/apps/sso/<provider>/assume/...`. Do not promise complete AWS
federation behavior from configuration alone unless the handler implementation
changes.

## Review Checklist

Check generated SSO app entries against these code-backed constraints:

- Use `sso provider <name>`, not `oauth identity provider <name>`.
- Keep SSO provider names unique; authcrunch server provisioning rejects
  duplicates.
- Include `entity_id`, `driver aws`, `cert`, `private key`, and at least one
  `location`.
- `cert` points to a PEM certificate file.
- `private key` points to a PKCS8 PEM private key file.
- The `location` URL is the service endpoint that should appear in SAML
  metadata, including the portal base path, usually
  `/auth/apps/sso/<provider>` on the auth portal host.
- The portal enables the same provider name with `enable sso provider <name>`.
- The portal has at least one identity store or login identity provider; SSO app
  providers do not count as authentication backends.
- Any AWS roles assigned to users use `aws/<account_id>/<role_name>`.
- No unsupported provider fields are generated.

## Fixtures

Use these examples:

- `caddyfile_sso_provider.go` for accepted Caddyfile subdirectives.
- `caddyfile_sso_provider_test.go` for parser examples and expected adapted
  JSON.
- `go-authcrunch/pkg/sso/config_test.go` for authcrunch validation behavior.
- `go-authcrunch/pkg/sso/request_test.go` for SSO URL parsing behavior.
