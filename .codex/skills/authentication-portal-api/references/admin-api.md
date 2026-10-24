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

Admin API requests require a valid portal-admitted access token with an admin
role; stored profile-session evidence is not required. The metadata success
body contains JSON bytes served as `text/plain`, with a UTC RFC3339 timestamp.
Its version/build fields identify the linked identity library, not Caddy.
When debugging, check both the Caddyfile directive and the authenticated user's
roles before suspecting handler bugs.

### Local user selection

`POST <mount>/api/server/user` accepts `realm`, `operation` and a `user` object.
Existing-account operations are `info`, `delete`, `disable`, `enable`,
`reset_password`, `overwrite_roles`, `add_roles` and
`overwrite_auth_challenges`. For example:

```json
{"realm":"local","operation":"info","user":{"username":"stored-account-name","email":""}}
```

Empty or omitted email is eligible only for a currently stored, automatically
provisioned account with no local email aliases in a built-in local store.
The server checks the record kind and alias list while selecting the account
inside the read or mutation operation. Username prefixes, provider display
email and a previous lookup never establish eligibility. Ordinary accounts and
automatic accounts with a local alias require username and email to identify
the same account. A password reset alone does not add an alias. Creation
(`add`) always requires nonempty email; it cannot request automatic provisioning.

Use `POST <mount>/api/server/users` with `{"realm":"local","query":"all"}`
to obtain the stored username and ID. Listing does not promise the automatic
record-kind flag. Info for an automatic record includes `externally_provisioned`
and any `email_addresses`. Disabled accounts remain
listed but are absent from ordinary active-user selection. `enable` selects a
disabled record by its exact stored username and, when present, exact stored
local email spelling; enabling it again is an error. Keep selection and mutation
together in the server; clients must not preauthorize from a cached list/info
result or retry a stale write automatically.

Email, when present, must be a string: null, booleans and arrays return 400.
Empty username, creation without email and an empty selector for a non-local
backend also return 400. An ordinary/aliased record with an empty email fails
selection. Info selection failure returns a generic HTTP 500; mutation failures
can return HTTP 200 with `status:"failure"`. Check the body, not just status.
Successful info returns the user record; successful mutation confirms
`status:"success"` and may include operation-specific fields. Creation and reset
return a generated password; info can expose credential hashes. Preserve
`Cache-Control: no-store` and keep those bodies out of logs.

The built-in CLI permits the conditional selector and sends one operation,
with `"email":""` for both omission and `--email=`. It never invents an email,
changes the wire field to null, infers account kind or performs a prelookup.
Any sent mutation failure may have an uncertain outcome; inspect current state
before an explicit retry. File-backed administration retains the server's
revision-conflict behavior, not a new cross-process retry protocol.

`TestSecurityLocalUserSelectors`, `TestSecurityLocalSelectorValidation` and
`TestSecurityLocalEmptySelectorFailure` cover the client boundary.
`TestCaddyConnectedAccountsAdministrationE2E` qualifies the actual built command
and raw HTTP controls against attached, ordinary and aliased automatic accounts,
with unchanged-state checks and fresh signed-login evidence. Existing local
administration tests retain ordinary paired selectors and private response
handling. See [attached identity policy](../../configuration-identity-stores/references/connected-accounts.md)
for disable/delete and token-lifetime limits.

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
