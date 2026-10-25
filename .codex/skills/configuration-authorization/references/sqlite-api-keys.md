# SQLite API-key authentication

## Configuration and policy selection

The bundled `security.credential_authenticators.sqlite` module provides fresh,
realm-bound API-key authentication without an authentication portal. Declare a
named factory inside global `security` and select it from each policy:

```caddyfile
{
	log {
		format filter {
			wrap json
			fields {
				request>headers>X-Api-Key delete
			}
		}
	}
	security {
		credential authenticator sqlite keys {
			path /private/auth/credentials.db
			realm staff
			timeout 500ms
		}
		authorization policy api {
			with api key auth portal keys realm staff
			allow roles viewer
			disable auth redirect
			enable strip token
		}
	}
}

https://api.example.test {
	log {
		format filter {
			wrap json
			fields {
				request>headers>X-Api-Key delete
			}
		}
	}
	route {
		authorize with api
		respond "authorized"
	}
}
```

The header supplies `name`. The body requires exactly one `path` and `realm`;
optional `timeout` defaults to `1s`, inclusive range `1ms` through `30s`.
Unknown fields, duplicates, nested blocks and extra arguments fail adaptation.
Fields are literal; runtime placeholders and secret lookup expansion are not
supported. Adaptation and module validation do no storage I/O. Normal app
construction requires an existing database; only trusted provisioning creates it.

Native app JSON uses `credential_authenticators`, an array of module objects:

```json
{"driver":"sqlite","name":"keys","path":"/private/auth/credentials.db","realm":"staff","timeout":"500ms"}
```

Names must be unique, distinct from authentication portal names, and cannot be
remote URLs. Every declaration needs at least one matching policy. All bindings
must use the exact configured realm and API-key authentication only. Basic,
mixed Basic/API-key, conflicting or duplicate realm declarations, mismatched
realms and unused factories fail provisioning. Ordinary portal and remote proxy
bindings retain their behavior. Raw declarations survive native JSON round trips;
each candidate restores runtime bindings into its private validated graph before
root construction. Root assembly checks all proxies before publication.

One app shares a backend across its matching policies. Each replacement app gets
its own handles. Failed candidates close only their resources; the serving app
remains usable. Retirement closes request admission, drains requests, closes the
root, and then closes injected backends in reverse construction order. Caddy's
module cleanup must not close a backend still in use. Persistent roots defer
opening handles until Start and retain their stop/start deployment boundary.

## Request behavior

Clients send `X-Api-Key` and `X-Auth-Realm: staff` over trusted TLS. Existing
`with api key header name` and `with auth realm header name` directives change
those header names. `enable strip token` removes the accepted credential from
its actual header before downstream handling. Caddy clones the original request
before handlers run, so stripping cannot redact host logs. Configure the shown
header deletion filters on both global diagnostic and site access log encoders;
add every custom API-key header name using its canonical HTTP spelling.
The default Caddy credential redaction does not include arbitrary API-key headers.
In particular, debug error logging of wrong realms, unavailable storage or revoked
keys can expose them without these filters. AuthCrunch component skip rules do
not affect Caddy's HTTP error logger. The filters preserve denial status and
diagnostics while removing only credential header fields.

API keys are considered after normal token sources fail. Successful verification
supplies the provisioned subject, email and roles, with origin set to the bound
realm and `amr` containing `api_key`. Existing ACLs still decide access: a valid
key with insufficient roles is denied. This module does not authenticate
passwords, enroll local users, or issue portal login/refresh sessions.

Every lookup reads current storage with the protected request context; credential
result caches are bypassed. Revoking a previously accepted key affects the next
lookup across all policies, without reload. Already admitted requests continue.
Wrong realms, malformed, expired or revoked keys and storage failures deny access;
failed Basic/API-key authentication returns `401`, and ACL denial returns `403`.
Use `disable auth redirect` for API clients that must receive an error when no
credential is supplied. Storage failure never reuses a previous successful result.

## Trusted offline provisioning

`security api-key issue` and `security api-key revoke` are local administrative
commands. They do not expose an HTTP issuance endpoint. Prepare a private JSON
file, mode `0600` in a `0700` directory with trusted ancestors, and pass only its
path to `--config`. The same path rules apply to key files. Symlinks and unsafe
ownership/modes are rejected. Input is bounded, exact-case JSON with no duplicate
or unknown fields; invalid Unicode, extra documents and incorrect types fail.

Issue input has this shape; replace the timestamp with a future RFC3339 value
within the next 30 days:

```json
{
  "config": {"name":"keys","path":"/private/auth/credentials.db","realm":"staff"},
  "subject":"alice",
  "email":"alice@example.test",
  "roles":["viewer"],
  "expires":"2030-01-01T12:00:00Z"
}
```

Run:

```sh
bin/authcrunch security api-key issue --config /private/auth/issue.json --output /private/auth/alice.key
bin/authcrunch security api-key revoke --config /private/auth/revoke.json
```

Issue generates a random 256-bit base64url key once. The output is a new `0600`
file containing the 43-character key followed by a newline. Existing destinations
are never overwritten. Raw keys are never printed, accepted in flags, or stored
in Caddy configuration. Deliver the private file only to the intended client.
Normal output reports completion without the credential or database path.

Revoke input contains only `config` and `key_file`:

```json
{"config":{"name":"keys","path":"/private/auth/credentials.db","realm":"staff"},"key_file":"/private/auth/alice.key"}
```

Revocation reads the private key file and removes only that realm's digest;
absence is idempotent success. It never creates a missing database. The input key
file remains under operator control. Local user-store API keys generated by
`security local generate api key` use a different credential model and cannot be
substituted for these SQLite credentials.

Subjects are bounded to 256 bytes, emails to 320 and must be bare addresses;
1–32 roles are required, each at most 128 bytes. Expiry must lie in the next
30 days; at most 10,000 live keys share one database. Issuance prunes expired keys.
Only key digests are stored; subject, email, roles and expiry remain plaintext.
Use a separate private local POSIX database file for each plugin category, with a
`0700` parent and `0600` file. This does not provide encryption, network-filesystem
support, schema migration or multi-host availability. The production build works
with CGO disabled.

## Mutation failures and recovery

Issuance commits before publishing the private output file. If publication then
fails with a known issued key, the command attempts one bounded compensating
revocation and reports whether it succeeded. An error may leave a published file
whose key was revoked; do not treat file existence as successful issuance.
If compensation cannot be confirmed, the command explicitly requires
reconciliation. It never retries issuance automatically.

`ErrCommitUncertain`, close failures after mutation, and result-output failures
are not proof of rollback. Reconcile the database and any private output before
retrying. A commit with no returned key may leave an unknown digest until expiry;
there is no public credential-list/recovery API. Protect and inspect the database
through a separately controlled recovery process; do not blindly issue again.

## Validation

`plugins/credential-authenticators-sqlite/consumer_test.go` covers public parsing, no-I/O validation,
consumer refusal to create storage, cancellation, rejected Basic authentication,
fresh revocation and closed handles. Its `ownership_test.go` adds independent
handles, setup cancellation, realm binding and unsafe storage rejection.
`app_credential_authenticators_test.go`
covers binding rejection, preserved declarations, shared handles, failure unwind,
request drain and persistent Start. `command_api_key_test.go` covers strict input,
private output, no overwrite, realm-bound idempotent revocation and redacted errors.
The registered `testcase_credentials_sqlite` fixture checks adaptation.

`TestCaddySQLiteCredentialsE2E` builds the production binary with CGO disabled,
uses trusted TLS, explicit Caddy header filters and the actual CLI, and checks
fresh revocation, ACLs, realm
errors, malformed/Basic credentials, custom header stripping, failed reloads,
storage failures, successful replacement, restart and private-output redaction.
A real request admitted before retirement is additionally protected by the
shared app lifecycle/drain tests.
