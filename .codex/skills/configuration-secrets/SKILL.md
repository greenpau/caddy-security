---
name: configuration-secrets
description: "caddy-security secrets manager Caddyfile configuration. Use when creating, reviewing, or modifying security secrets blocks, external security.secrets modules, static secrets manager examples, AWS secrets manager examples, secret IDs, secret-backed user data, authdbctl-generated password or API key hashes, secret-backed crypto keys, and integration with runtime replacement."
---

# Configuration Secrets

## Purpose

Use this skill to configure `secrets <plugin_name> <secret_id>` blocks and
secret-backed Caddyfile values. The parser is `caddyfile_secrets.go`; runtime
replacement is in `caddyfile_resolve.go`.

Secrets managers are external Caddy modules under the `security.secrets`
namespace. The `security` app loads them through `SecretsManagerConfigs`; each
module must expose `GetConfig(ctx)["id"]`, `GetSecret(ctx)`, and
`GetSecretByKey(ctx, key)`.

Authcrunch does not resolve `secrets:*:*` values itself. Caddy-security replaces
them during app provisioning, before the authcrunch config is validated and used
to build the server. A secret lookup must therefore resolve to the final string
that authcrunch expects, such as a bcrypt password hash, API key hash, OAuth
client secret, SMTP password, or crypto shared secret.

## Shape

```caddyfile
security {
	secrets static_secrets_manager access_token {
		shared_secret {env.JWT_SHARED_KEY}
	}

	authentication portal myportal {
		crypto key sign-verify "secrets:access_token:shared_secret"
	}
}
```

The block form is:

```caddyfile
secrets <secrets_plugin_name> <secret_id> {
	...
}
```

The third token is the manager ID, also called the secret ID in plugin logs and
docs. It must match the middle segment of every lookup:
`secrets:<secret_id>:<key>`. The inner block is owned by the external secrets
manager module; do not invent manager-specific fields.

## Static Secrets Manager

Use `static_secrets_manager` only when the Caddy binary is built with
`github.com/greenpau/caddy-security-secrets-static-secrets-manager`.

```caddyfile
security {
	secrets static_secrets_manager users/jsmith {
		name "John Smith"
		email "jsmith@localhost.localdomain"
		password "bcrypt:10:$2a$10$iqq53VjdCwknBSBrnyLd9OH1Mfh6kqPezMMy6h6F41iLdVDkj13I6"
		api_key "bcrypt:10:$2a$10$TEQ7ZG9cAdWwhQK36orCGOlokqQA55ddE0WEsl00oLZh567okdcZ6"
	}
}
```

The static plugin treats each inner line as one key with exactly one value and
stores an inline key-value map. Lookups read keys from that map:

```caddyfile
name "secrets:users/jsmith:name"
password "secrets:users/jsmith:password" overwrite
```

## AWS Secrets Manager

Use `aws_secrets_manager` only when the Caddy binary is built with
`github.com/greenpau/caddy-security-secrets-aws-secrets-manager`.

```caddyfile
security {
	secrets aws_secrets_manager access_token {
		region us-east-1
		path authcrunch/caddy/access_token
	}
}
```

The AWS plugin accepts only `region` and `path` in the block. Both are required,
and the ID is still the Caddyfile block ID (`access_token` above), not the AWS
path. The AWS secret value must be a JSON object; lookup keys read fields from
that object. For example, if the object contains `{"value":"..."}`, use:

```caddyfile
crypto key sign-verify "secrets:access_token:value"
```

## Secret Lookup Values

Resolved values use:

```text
secrets:<secret_id>:<key>
```

Examples:

```caddyfile
password "secrets:users/jsmith:password" overwrite
api key XnxJ5W0AAcDb2FO1nefd35fT "secrets:users/jsmith:api_key"
crypto key sign-verify "secrets:access_token:shared_secret"
```

Resolution is strict:

- The lookup must split into exactly three colon-separated fields; use slashes
  in IDs such as `users/jsmith`, not colons.
- `<secret_id>` must match `GetConfig(ctx)["id"]` from a loaded secrets manager.
- `<key>` is passed to `GetSecretByKey(ctx, key)`.
- The returned value must be a string. Non-string values cause provisioning to
  fail with `secret value is not a string`.

Use quotes around secret lookup strings when they contain characters that could
be parsed unexpectedly.

## Generated Secret Values

Use `authdbctl` when secret-backed local users need password or API key hashes.
The source guide is `../go-authcrunch/cmd/authdbctl/README.md`.

For local user passwords, generate a bcrypt value:

```bash
authdbctl generate password hash
authdbctl generate password hash --db-path assets/config/users.json
authdbctl generate password hash --cost 10 --password SomeFunkyPassword
```

Prefer the prompt form for real secrets; the CLI marks `--password` as
insecure. When `--db-path` points at the local users database, authdbctl checks
that database's password policy before printing the hash. Store only the value
inside the emitted `password "..."` directive:

```caddyfile
secrets static_secrets_manager users/jsmith {
	password "bcrypt:10:$2a$10$K9KksvjRCdjT1sYbecGCCu.Y33xpii94itQPgGVS6vShuEUB0On1q"
}

local identity store localdb {
	user jsmith {
		password "secrets:users/jsmith:password" overwrite
	}
}
```

For local user API keys, generate both the client secret and server-side bcrypt
payload:

```bash
authdbctl generate api key
```

The output includes `secret: <full-secret>` for the API client and
`api key <24-char-prefix> "<bcrypt-payload>"` for the Caddyfile. Do not store
the plaintext `secret:` value in the server config. If the payload is
secret-backed, keep the 24-character prefix in the Caddyfile and store only the
bcrypt payload in the secrets manager:

```caddyfile
secrets static_secrets_manager users/jsmith {
	api_key "bcrypt:10:$2a$10$2QKmYR9Q5wvl8UUNkICUoOf5KMVixTEhbUor5Y3oUfQsrz5iiG.K6"
}

local identity store localdb {
	user jsmith {
		api key XnxJ5W0AAcDb2FO1nefd35fT "secrets:users/jsmith:api_key"
	}
}
```

## Validation Notes

The fixture test binary may not register external secrets manager modules. The
`testcase_security_with_secrets` fixture intentionally expects a
`module not registered: security.secrets.static_secrets_manager` error even
though the Caddyfile shape is intentional.

The AWS plugin validates by fetching and caching the configured AWS secret during
plugin validation. The static plugin serves the configured inline map locally.
In both cases, caddy-security only consumes the common `SecretsManager`
interface after Caddy loads the module.

Use `configuration-runtime-resolution` when explaining how `{env.*}` and
`secrets:*:*` values are substituted after adaptation. Runtime replacement also
revalidates affected authcrunch config sections after substitution, so examples
must resolve to values acceptable to go-authcrunch parsers.

## Fixtures

Use these references:

- `testdata/caddyfile_adapt/testcase_security_with_secrets.Caddyfile` for
  static manager block and lookup shape.
- `caddyfile_resolve_test.go`.
