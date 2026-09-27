---
name: configuration-saml-providers
description: "Configure external SAML login providers, ACS/IdP URLs, metadata, signing certificates, realms, and claims. Use for Azure or generic IdPs; portal SAML SSO app providers belong to configuration-sso-app."
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
- The selected go-authcrunch module's `pkg/idp/saml/` for validation,
  metadata handling, assertion validation, and driver behavior. Resolve its
  directory with `go list -m -json github.com/greenpau/go-authcrunch`; a sibling
  checkout may differ from the selected version.

## Shape

```caddyfile
{
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

The selected library binds the SAML response to its initiating browser using
the portal's SAML session cookie. Configure its name inside the portal with
`cookie saml session id name <name>` or the shared cookie prefix; see
[cookie names and attributes](../configuration-authentication-cookies/SKILL.md).
Keep this cookie distinct from access, OIDC and refresh cookies.
Login must start at the portal: unsolicited IdP-initiated responses are disabled.
The response must return the issued RelayState and matching request ID to the
same browser and ACS URL. Expired, missing, replayed or foreign-browser state
fails; start a new portal login rather than replaying the assertion.

`idp_metadata_location` accepts a filesystem path or HTTP(S) URL. In v1.3.4,
`idp_sign_cert_location` is a local PEM certificate path, read with
`pkg/util/file.ReadCertFile`; it does not fetch certificate URLs. The separately
configured certificate pins the signing trust anchor, so metadata cannot add
another trusted signing key. Provisioning reads these files and may fetch
remote metadata; adaptation alone does not check that they are usable.

Keep the portal base path in SAML URLs. If the portal is mounted at `/auth` and
the SAML realm is `azure`, the ACS endpoint is usually
`https://auth.example.com/auth/saml/azure`. For JumpCloud and other custom
apps, configure the IdP ACS URL to the externally reachable portal URL, not the
upstream app URL.

SAML assertion validation is time-sensitive. When SAML login fails with
timestamp or assertion validity errors, check clock synchronization on the
Caddy host before changing IdP metadata or certificates.

For `driver azure`, validation requires `tenant_id`, `application_id` and
`application_name`. It derives the login URL from them and defaults an omitted
metadata location to the tenant federation-metadata URL. Both drivers require
`realm`, a signing certificate path and at least one `acs_url`; set a stable
`entity_id` matching the IdP's SP configuration.

Current go-authcrunch SAML validation supports `driver azure` and
`driver generic`. There is no first-class `driver jumpcloud`; for JumpCloud,
use `driver generic`, configure a custom SAML app with SP entity ID, IdP entity
ID, ACS URL and RSA-SHA256 signing. Generic configuration also requires an
explicit `idp_login_url`; the login URL is not inferred from metadata. For
example, inside `security`:

```caddyfile
saml identity provider directory {
	realm directory
	driver generic
	entity_id urn:caddy:example-portal
	idp_login_url https://idp.example.com/saml/login
	idp_metadata_location /etc/caddy/saml/idp-metadata.xml
	idp_sign_cert_location /etc/caddy/saml/idp-signing.pem
	acs_url https://auth.example.com/auth/saml/directory
}
```

The assertion must supply attributes whose names end in
`identity/claims/emailaddress` and `identity/claims/displayname`; these populate
the required email and name claims. NameID alone, or attributes named only
`email` and `displayName`, do not satisfy the current consumer. Roles are read
from attribute names ending in `Attributes/Role`. Inspect
`pkg/idp/saml/authenticate.go` before assuming another IdP claim name maps to a
portal claim.

## Review Checklist

- Use `saml identity provider <name>`, not `sso provider <name>`.
- Include a stable `realm` and `driver`; selected go-authcrunch supports
  `azure` and `generic`.
- Configure readable metadata and a local PEM signing certificate; provide
  `idp_login_url` for generic providers and the required Azure fields otherwise.
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

`caddyfile_authn_test.go` contains an Azure parser example, but it does not read
metadata or perform a signed SAML exchange. This checkout has no complete SAML
login E2E. Before claiming a provider integration works, verify a portal-started
login through actual Caddy with synthetic signed assertions, the expected
email/name/roles, and protected-route access. Include missing generic login
URL, unreadable certificate, wrong signature, wrong ACS, replay and missing or
foreign browser cookie failures. Upstream SAML tests are implementation
evidence, not Caddy qualification.
