# HTTP JSON external authorization

Use this for a required policy-service decision after authenticated local
authorization. Credential verification and local ACLs remain authoritative:
remote allow cannot override their denial. Omission preserves ordinary policy
behavior. Explicit bypass routes intentionally skip authentication and this
decision. This is separate from remote Basic/API-key credential authentication.

## Policy configuration

One flat block is allowed per authorization policy:

```caddyfile
authorization policy reports_policy {
	crypto key verify {env.JWT_SHARED_KEY}
	validate bearer header
	allow roles viewer
	external authorization httpjson {
		endpoint https://policy.example.test/decide
		policy reports
		version production
		issuer https://login.example.test/auth/login
		realm local
		attribute roles
		timeout 500ms
		tls ca file /etc/caddy/policy-ca.pem
		tls client certificate /etc/caddy/policy-client.pem /etc/caddy/policy-client-key.pem
	}
}
```

The example is a fragment inside the global `security` block. Mount it with
`authorize with reports_policy`. The local name `reports_policy` selects the
Caddy policy; `policy reports` and `version production` identify the service's
decision contract and must be echoed exactly in its response.

| Statement | Meaning |
| --- | --- |
| `endpoint <URL>` | Required fixed service URL; HTTPS, or HTTP on a literal loopback IP only. No URL credentials, query, fragment or invalid port. |
| `policy <name>`, `version <revision>` | Required remote decision contract; distinct from the local policy name and software release versions. |
| `issuer <value>`, `realm <value>` | Required exact authenticated issuer and origin. No URL normalization or discovery. Inspect the issued `iss`: native password login normally uses its login URL, while browser checkpoint completion can use its sandbox URL. Unmodified direct Basic/API-key authentication uses `authp`; direct OAuth sessions use their gatekeeper origin/provider realm. |
| `subject claim <name>` | Defaults to `sub`. Choose an authoritative identity claim; the signed value must be a nonempty string. |
| `tenant claim <name>` | Optional. When configured, requires a nonempty authenticated string, distinct from the subject claim; the service owns tenant policy. |
| `attribute <name>` | Repeat for up to 16 unique top-level authenticated claim names. Omission sends no attributes. Missing claims stay absent and JSON null stays null. |
| `timeout <duration>` | Defaults to 1s; 1ms through 30s. Sets the overall authorization deadline and the backend's per-call limit; request cancellation and credential expiry can shorten it. |
| `tls ca file <PEM-path>` | Optional exclusive trust roots for this backend. Without it, use system roots. |
| `tls client certificate <cert-PEM-path> <key-PEM-path>` | Optional mTLS service identity; both files required. Never substitutes an end-user credential. |

Scalars occur once; unknown settings, duplicate attributes, nested blocks and
quoted structural braces fail. Binding strings are bounded UTF-8 without
surrounding whitespace or control characters. Shared AuthCrunch parsers own
endpoint, identity and duration validation; Caddy owns the TLS statements.

These fields are literal. `{env.NAME}` and `secrets:...` are not expanded by this
adapter. Keep private key bytes in the referenced file, outside configuration
JSON. Normal Caddy configuration introspection can expose paths and selected
attribute names. Do not select bearer tokens, passwords or other credentials as
attributes. A signed user-editable field is not necessarily suitable for granting
access.

For browser login, configure an explicit stable issuer using the existing
portal transform and bind the external policy to the same value. This is an
operator-chosen claim, not request-derived normalization:

```caddyfile
authentication portal myportal {
	enable identity store localdb
	crypto key sign-verify {env.JWT_SHARED_KEY}
	transform user {
		match realm local
		overwrite iss https://login.example.test/auth/login
	}
}
```

This fragment also belongs inside `security`, with `localdb` declared there.
The transform can affect other authentication paths using that realm; verify
their resulting issuer before binding them. An unchanged per-login sandbox
issuer cannot match one fixed policy binding across logins. Do not weaken exact
issuer matching or infer it from an incoming Host/header to compensate.

## Native JSON and lifecycle

The security app accepts `external_authorization`, a list of bindings with:

- `policy`: exact existing local authorization policy name, unique in this list;
- `config`: typed AuthCrunch external configuration, with `policy`, `version`,
  `issuer`, `realm`, optional `subject_claim`, `tenant_claim`, `attributes`, and
  `timeout`;
- `backend`: `driver: "httpjson"`, `endpoint`, optional `timeout`, and optional
  `tls` containing `root_ca_file`, `client_certificate_file`, `client_key_file`.

Both timeouts default independently to 1s in native JSON. The binding bounds
all path decisions together; the backend timeout can impose a shorter per-call
limit. Caddyfile syntax sets both to the same value. Bindings are copied before
validation and module loading, preserving declarative JSON for introspection
and reload. The module ID is `security.external_authorization.httpjson`.

Validation performs no network or file I/O. Runtime construction reads regular
PEM files, at most 1 MiB each, and constructs an independent transport. Symlinks
to regular files are supported for operator-managed certificate rotation. Paths
are read again on replacement; the adapter does not watch or refresh files.
TLS options require HTTPS and retain hostname/certificate verification with a
minimum of TLS 1.2. No ambient proxy, cookie jar, redirect following, or incoming
credential/header forwarding is enabled. Additional service authentication
schemes are not configured by this adapter.

The app attaches the authorizer to its private AuthCrunch root before publishing
routes. A failed candidate disposes its acquired resources without changing the
active app. Persistent configuration defers runtime construction to `Start` and
retains the existing stop/start boundary. Retirement closes admission, drains
requests, closes the root, then closes backends in reverse construction order.
The HTTP wrapper adapts the reference backend's errorless `Close` to `io.Closer`
and closes injected transports; Caddy module cleanup does not own live backends.
Use the [host plugin contract](../../coding-directives/references/host-plugins.md)
when implementing another external authorization backend.

## Decisions and HTTP contract

After every local ACL pass, the service is consulted again, including JWT cache
hits, Basic/API-key authentication and existing direct OAuth sessions. Direct
OAuth also requires allow at callback admission before issuing a session.
Selected attributes come from the original authenticated claims. Claims
enrichment may affect local ACLs but cannot change external identity or selected
attributes.

The service receives POST JSON containing only `policy`, `version`, `identity`,
`action`, `resource`, and optional selected `attributes`. Identity contains issuer,
realm, subject and optional tenant; action is the HTTP method and resource is a
path. Incoming query strings, bodies, headers and cookies are not implicit input.
Every supported interpretation of an ambiguous path must allow under one shared
deadline. Encoded separators and invalid paths fail closed; do not replace the
upstream path handling with one cleaned string.

A valid response is HTTP 200, `application/json`, at most 4096 bytes including
decompressed content, and exactly the case-sensitive string fields `decision`
(`allow` or `deny`), `policy`, and `version`. Unknown/duplicate fields, unsupported
obligations, mismatched contract values, extra JSON, invalid UTF-8, redirects,
other statuses/media types, transport failures, cancellation and late allows
deny access. There is no decision cache or application retry. Denial uses the
policy's existing forbidden response without exposing endpoint/remote diagnostics
or clearing otherwise valid credentials merely because the service denied.

## Implementation and validation

`caddyfile_authz_external.go` delegates binding and transport parsing;
`app_external_authorization.go` prepares and attaches the typed binding;
`plugins/external-authorization-httpjson/plugin.go` owns the factory and TLS resources.
`app.go` owns publication, rollback and drain. HTTP handlers remain thin
delegates to AuthCrunch.

Unit coverage belongs in `caddyfile_authz_external_test.go`,
`app_external_authorization_test.go`, the companion's
`plugins/external-authorization-httpjson/consumer_test.go` and `tls_test.go`.
`external_authorization_httpjson_test.go` retains assembled shared TLS fixtures;
the independent companion tests use their own controlled HTTPS service.
The `testcase_authorize_external` and `testcase_authorize_external_invalid`
adaptation fixtures check both accepted output and rejection. Host E2E belongs
in `external_authorization_httpjson_e2e_test.go`: require trusted TLS/mTLS, real
login, protected-handler admission, changing decisions on cached credentials,
credential isolation, local denial precedence, composed enrichment, all response
failure classes, path interpretations, deadline/cancellation, outage, rejected
reload and drain-before-close. Qualify direct OAuth callback/session enforcement
through the real Caddy binary as well. Upstream consumer tests alone do not
establish those host behaviors.
