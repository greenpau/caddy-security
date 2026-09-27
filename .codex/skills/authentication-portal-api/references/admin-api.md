# Portal admin/server APIs

Read this reference for server metadata, local-user administration, API flags,
and authenticated private-key export. Profile APIs are a separate user boundary.

## Admin Server API

For the built-in administration client, use
[`security local`](../../scripts-and-automation/references/local-user-commands.md).
It delegates login to `go-authcrunch/pkg/authclient` and exposes realm/user
inspection, account CRUD, password reset, role/challenge updates, and reload
through the admin endpoints.

Add this inside `authentication portal <name>` to enable the server/admin API:

```caddyfile
authentication portal myportal {
	enable admin api
}
```

The documented endpoints include:

- `GET /api/server/metadata`: version, build, and server timestamp metadata.
- `POST /api/server/realms`: local realm discovery.
- `POST /api/server/info`: local identity database path, modification time,
  and password/user policy details for a realm.

Admin API requests require an active authorized session with an admin role.
When debugging, check both the Caddyfile directive and the authenticated user's
roles before suspecting handler bugs.

### Private Signing-Key Export

The portal accepts exactly these admin statements, with separate keywords:

```caddyfile
enable admin api
disable admin api
enable admin api private key export
disable admin api private key export
```

Choose at most one statement for each setting. Both settings default to false;
enabling export alone does not enable admin access. Boolean values, extra
arguments, grouped keywords such as `"admin api"`, and duplicate or conflicting
settings are errors, including when separated by unrelated portal directives.

The adapter collects the entire portal's admin statements and delegates to
`NewAdminAPIConfigFromDirectives`, then applies its `*authn.AdminAPIConfig` with
`PortalConfig.ConfigureAdminAPI`. Preserve `ProfileEnabled` and the existing
`api.admin_enabled` / `api.admin_fetch_private_keys_enabled` JSON fields; do not
replace the aggregate API configuration. Profile operations require a stored
portal session; the ordinary JSON access-token login does not create that
browser session.

`GET <mount>/api/server/private_keys` uses the existing `authenticate` route and
`Portal.ServeHTTP`. Export requires both flags and an authenticated portal admin.
For valid admin requests, the flag matrix is 404/404/404/200 (neither, admin
only, export only, both). Authentication failures precede the flag checks and
return 401 for invalid/expired tokens. With no token, authorization finds no
user: disabled export returns 404, while enabled export returns 403. A normal
authenticated user receives the same 404/403 export results. Authorized export
supports GET only; other methods return 405 with `Allow: GET` when both flags
are enabled. The library validates format and encoding selectors and sends
`Cache-Control: no-store` on success and errors.

Public access-token discovery at `GET` or `HEAD <mount>/.well-known/jwks.json`
precedes authentication and remains independent of both flags. It publishes
public signing keys only. OIDC setup does not require private export. Do not
add a public export route, another export serializer, or response-body logging.

Validation lives in `caddyfile_authn_admin_api_test.go`, the
`testcase_authenticate_with_admin_api` adaptation fixture, and
`TestCaddyAdminAPIE2E` in `admin_api_e2e_test.go`. The TLS tests exercise real
browser logins, both header and cookie credentials, root and nested mounts,
profile settings, methods/selectors, PKCS#8 key matching, public JWKS field
restrictions, and response/log redaction. Live reload coverage verifies that
existing tokens obey changed flags immediately, removed directives disable both
flags, and malformed configurations leave the active portal unchanged.
