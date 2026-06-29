---
name: configuration-saml-providers
description: "caddy-security SAML login identity-provider Caddyfile configuration. Use when creating, reviewing, or debugging saml identity provider blocks for authentication portal login, especially Azure AD or JumpCloud SAML IdPs, ACS URLs, IdP metadata and signing certificates, entity IDs, SAML realms, clock-skew issues, role claims, and portal enablement. Do not use for sso provider app-side SAML SSO blocks."
---

# Configuration SAML Providers

## Purpose

Use this skill for `saml identity provider <name>` blocks that let users log
in to an authentication portal through a SAML IdP. This is distinct from
`sso provider <name>` blocks, which configure the portal as an IdP for SSO apps
and belong in `configuration-sso-app`.

Read these files when details matter:

- `caddyfile_identity.go` and `caddyfile_identity_provider.go` for parser
  dispatch and accepted provider fields.
- `../go-authcrunch/pkg/idp/saml/` for validation,
  metadata handling, assertion validation, and driver behavior.

## Shape

```caddyfile
security {
	saml identity provider azure {
		realm azure
		driver azure
		idp_metadata_location /etc/caddy/saml/azure_metadata.xml
		idp_sign_cert_location /etc/caddy/saml/azure_signing_cert.pem
		tenant_id {env.AZURE_TENANT_ID}
		application_id {env.AZURE_APP_ID}
		application_name "Example Portal"
		entity_id "urn:caddy:example-portal"
		acs_url https://auth.example.com/auth/saml/azure
	}

	authentication portal myportal {
		enable identity provider azure
	}
}
```

The provider name must match the portal's `enable identity provider <name>`.
The `realm` becomes the login realm and is commonly matched in transforms:

```caddyfile
transform user {
	match realm azure
	action add role authp/user
}
```

## Provider Notes

Keep the portal base path in SAML URLs. If the portal is mounted at `/auth` and
the SAML realm is `azure`, the ACS endpoint is usually
`https://auth.example.com/auth/saml/azure`. For JumpCloud and other custom
apps, configure the IdP ACS URL to the externally reachable portal URL, not the
upstream app URL.

SAML assertion validation is time-sensitive. When SAML login fails with
timestamp or assertion validity errors, check clock synchronization on the
Caddy host before changing IdP metadata or certificates.

For Azure AD, the docs use these common fields: `idp_metadata_location`,
`idp_sign_cert_location`, `tenant_id`, `application_id`, `application_name`,
`entity_id`, and one or more `acs_url` lines. Azure app roles can appear in
SAML assertions when configured under the Enterprise Application claims.

Current go-authcrunch SAML validation supports `driver azure` and
`driver generic`. There is no first-class `driver jumpcloud`; for JumpCloud,
use `driver generic`, configure a custom SAML app with SP entity ID, IdP entity
ID, ACS URL, NameID as email, RSA-SHA256 signing, and user attributes such as
email and display name. Download JumpCloud metadata and the IdP certificate and
point the Caddyfile at those files.

## Review Checklist

- Use `saml identity provider <name>`, not `sso provider <name>`.
- Include a stable `realm` and `driver`; current local go-authcrunch supports
  `azure` and `generic`.
- Configure IdP metadata and signing certificate paths or URLs accepted by the
  current parser and authcrunch validator.
- Include every externally reachable ACS URL with `acs_url`, especially when
  the portal is available on multiple hostnames or ports.
- Keep the portal route and ACS URL aligned with `authenticate` mount path.
- Enable the same provider name from the authentication portal.
- Map IdP role or group claims with `transform user` rules when portal tokens
  need `authp/user`, `authp/admin`, or application roles.
- Check host clock synchronization before diagnosing signed assertion failures.

## Fixtures

Use these references:

- `caddyfile_identity_provider.go` for current accepted Caddyfile fields.
- `go-authcrunch/pkg/idp/saml` for runtime validation and assertion behavior.
