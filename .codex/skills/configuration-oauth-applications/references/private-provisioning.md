# Private provisioning and activation

## Storage and command contract

`security` is a Caddy command group registered when this module is
imported, including in `bin/authcrunch` and xcaddy builds. There is no remote
registration API. Existing Caddy admin configuration endpoints still require
protection as usual.

`security oauth init provisioning store` prepares private storage for OAuth application
credentials and OIDC provider signing keys. It creates the directory; the OAuth
and OIDC commands create its contents. User registration and sessions use their
own configuration and storage.

The provisioning commands are optional for deployments supplying explicit
application credentials and existing provider keys through their own provisioning
process. Configurations using `registration <revision>` require the selected
record to exist before loading;
normal starts and reloads do not run these commands or create missing records.

The dedicated parser is shared by the provisioning commands and the global
`security` block. The declaration includes the `oauth` namespace:

```caddyfile
oauth registration store {
	path /var/lib/caddy/security-private/registrations
}
```

Exactly one `path` is required. Storage identity is that explicit, clean absolute
path plus the exact nickname and revision, independent of the working directory.
The single store applies to every application using `registration <revision>`.
It can appear after the applications. Names are SHA-256 encoded in filenames;
the record preserves the original nickname and validates it on every load.
Client records and provider keys have separate filename namespaces.

Files require current-user ownership and mode `0600`; the store requires `0700`.
Ancestors must belong to the current user or root and must not be writable by
others, except trusted sticky directories such as the system temporary directory.
Symlinks in directory paths and record paths are rejected. Use a physical path
on systems where `/var` or `/tmp` is a symlink. The directory must already exist
on normal adapt/validate/run/reload. Provisioning input files also require `0600`
inside a `0700` directory. Their filenames may be relative or absolute, but must
already be clean: no `.`/`..` components or redundant separators. Run the command
and Caddy as the same service account.

This implementation supports Unix ownership and permissions. Other platforms
fail closed; an ACL-aware backend is separate work. Use a local filesystem with
hard-link and file/directory-sync support. Same-owner processes and administrators
are trusted; directory checks do not protect credentials from that owner.
The existing secrets-manager interface is read-only, so it is not used for writes.

The provisioning subcommands accept only a standalone file, with `oauth registration store`
and, for client operations, exactly one `oauth application <nickname>` block.
They do not accept a full server Caddyfile, imports, or environment expansion.
The application body uses the application grammar, without `registration`.
Success writes only the resulting absolute path to stdout; secrets and private
keys stay in files.

Provisioning inputs and stored records must be valid UTF-8. Records reject duplicate
JSON members, including case aliases, rather than choosing one credential silently.
Unpaired Unicode surrogate escapes are rejected before JSON decoding can repair
them and change credential bytes. Valid Unicode escapes and characters retain
their values.
Input files, encoded records, and key files are limited to 1 MiB each. JSON escaping
can enlarge a record beyond its input; oversized records fail before publication
and do not reserve the nickname.

| Subcommand under `security` | Required flags | Effect |
| --- | --- | --- |
| `oauth init provisioning store` | `--config` | Create the missing private store directory under an existing trusted parent; refuse existing paths. |
| `oauth create application` | `--config --name --revision` | First creation for that nickname; generate omitted ID/secret, validate, and persist. Any existing revision prevents recreation. |
| `oauth rotate secret` | `--config --name --revision --from` | Load the prior revision, retain its client ID, require an explicit different confidential secret, and persist a new revision. |
| `oidc create signing key` | `--config --name --revision` | Generate and persist a dedicated provider RSA key. Name identifies the provider, independently of applications. |

`oauth create application` uses `NewOIDCClientConfigFromDirectives` and
`NewOAuthApplicationConfig`. `oauth rotate secret` uses the non-generating named
parser. Public-to-confidential rotation needs an explicit secret. A confidential client
can become public through `oauth rotate secret` with
`token_endpoint_auth_method none` and no secret. Public-to-public secret rotation
is rejected. A different stored client ID requires a new nickname; rotation does
not change protocol identity.

Commands use separate words under `security`: domain, action, then resource.
Keep future commands in this hierarchy. For example, `oauth create application`
has three nested commands. Run `bin/authcrunch security --help` to list domains,
`bin/authcrunch security oauth --help` to list OAuth actions, or
`bin/authcrunch security oauth create application --help` for creation flags.
Each final command exposes only its relevant options; there is no `--operation`
selector. Help and incomplete command groups perform no provisioning.

## Minimal create and load workflow

These commands assume `/var/lib/caddy` already exists and is writable by the
Caddy service account. Keep the deployment paths outside the repository. The
same grammar is exercised with temporary absolute paths by
`TestCaddyRegistrationE2E` and the adaptation fixtures.

```sh
umask 077
install -d -m 0700 /var/lib/caddy/security-private
cat > /var/lib/caddy/security-private/oauth_store.Caddyfile <<'EOF'
oauth registration store {
    path /var/lib/caddy/security-private/registrations
}
EOF

bin/authcrunch security oauth init provisioning store \
  --config /var/lib/caddy/security-private/oauth_store.Caddyfile

cp /var/lib/caddy/security-private/oauth_store.Caddyfile \
  /var/lib/caddy/security-private/oauth_client.Caddyfile
cat >> /var/lib/caddy/security-private/oauth_client.Caddyfile <<'EOF'
oauth application website {
    redirect_uri https://app.example.com/oidc/callback
    scopes openid profile email
}
EOF

APP_RECORD=$(bin/authcrunch security oauth create application \
  --config /var/lib/caddy/security-private/oauth_client.Caddyfile \
  --name website --revision v1)
KEY_FILE=$(bin/authcrunch security oidc create signing key \
  --config /var/lib/caddy/security-private/oauth_store.Caddyfile \
  --name login --revision k1)

# A dedicated RP handoff file, still private; do not print these fields.
jq '.client | {client_id, client_secret}' "$APP_RECORD" \
  > /var/lib/caddy/security-private/rp-credentials.json
```

Deliver the RP handoff file through the RP's protected credential configuration.
The nickname `website` is not the generated `client_id`. No ID-token key belongs
to the RP application; the key is owned by the login provider.

Use this server configuration, setting `OIDC_KEY_FILE` to the returned key path
and supplying a separate access-token key and existing local users database:

```caddyfile
{
	security {
		oauth registration store {
			path /var/lib/caddy/security-private/registrations
		}
		oauth application website {
			registration v1
			redirect_uri https://app.example.com/oidc/callback
			scopes openid profile email
		}
		local identity store localdb {
			realm local
			path /var/lib/caddy/users.json
		}
		authentication portal myportal {
			enable identity store localdb
			crypto key sign-verify {env.ACCESS_TOKEN_KEY}
			oidc provider {
				issuer https://auth.example.com/auth
				realms local
				signing key files {$OIDC_KEY_FILE}
				applications website
			}
		}
	}
}

auth.example.com {
	route /auth/* {
		authenticate with myportal
	}
}
```

Write this as the service's protected Caddyfile. Ordinary Caddyfile environment
expansion is supported; supply `OIDC_KEY_FILE` consistently to adaptation/run/reload,
or write the literal absolute path. Neither ID nor secret needs to be copied into
that Caddyfile. Consent and S256 PKCE default to enabled. Repeated adapt, validation,
reload, or process restart reads the selected registration without creating anything
in the OAuth registration store. The host may still create ordinary TLS/session/backend
state during validation; that state is separate from registration storage.

The current host lifecycle rejects overlapping reloads using the same persistent
local identity database. For that configuration, stop the old process before
starting the new one. See [identity-file ownership](../../coding-directives/references/runtime-lifecycle.md#persistent-identity-files-current-reload-restriction).
The E2E suite uses an in-memory local identity store to test live credential
reload independently of that existing restriction.

## Stage, activate, and recover a rotation

Prepare a private `oauth_rotate.Caddyfile` containing the store block and application
body with the desired callbacks/policy and an explicit new `client_secret`.
Generate that secret with the deployment's password/secret tooling and write it
directly to the private file. Do not pass it on the command line. For example:

```sh
umask 077
cp /var/lib/caddy/security-private/oauth_store.Caddyfile \
  /var/lib/caddy/security-private/oauth_rotate.Caddyfile
{
  printf 'oauth application website {\n'
  printf '    redirect_uri https://app.example.com/oidc/callback\n'
  printf '    client_secret '
  openssl rand -base64 48
  printf '}\n'
} >> /var/lib/caddy/security-private/oauth_rotate.Caddyfile

NEW_RECORD=$(bin/authcrunch security oauth rotate secret \
  --config /var/lib/caddy/security-private/oauth_rotate.Caddyfile \
  --name website --from v1 --revision v2)
```

The returned `v2` file is a **candidate**. `v1` remains intact and the running
provider still uses its old snapshot. Prepare the RP's new secret from the
candidate using the same private handoff process. Change the server Caddyfile to
`registration v2`, retain its intended callbacks/scopes/PKCE/consent directives,
and perform the deployment's Caddy reload or stop/start. A successful activation
uses the new secret immediately; there is no dual-secret grace period. Coordinate
the RP cutover accordingly. The E2E test verifies a successful exchange with v2
and HTTP 401 for v1 after activation.

There is no mutable `active.json` pointer in the store. The active Caddy
configuration selects immutable revisions; Caddy owns activation and autosave.
Failed adaptation, provisioning, or app start cannot replace stored v1. A rejected
reload preserves the active provider and its autosave. Explicitly select v1 again
to roll back, while it remains retained and appropriate for use. Provider sessions
and outstanding grants are process-local and are not restored from registrations.

Writers hold an exclusive `.writer-lock` directory, bounded by the command's
30-second context. They sync a private temporary file, publish by hard link
without replacement, then sync the store directory. A crash can leave the lock
or `.pending-*` files. After confirming no provisioning process is running, remove
the abandoned empty lock and temporary files locally; never remove a live lock.
A directory-sync error after publication reports that durability is uncertain.
Keep the old configuration active, inspect and back up the complete candidate,
and resolve the filesystem failure before selecting it. No failure bootstraps a
replacement ID or secret. Preserve all revisions needed for recovery and never
overwrite them with an editor.

Result-path output can also fail after persistence has completed, for example
when stdout is unwritable. The command exits unsuccessfully; a returned output
write error reports `provisioning completed`. Inspect the selected nickname and
revision in the private store before retrying. The complete record remains
available for deliberate activation, and retrying the same revision cannot
overwrite it. Unit and Caddy E2E tests cover both this case and a directory-sync
failure after publication, including continued use of the prior active credentials.

## Provider settings and key rollover

See [Portal OpenID Provider](oidc-provider.md) for the complete grammar, disabled
validation, realm selection, safe issuer routes/cookie scope, JSON restoration,
and runtime key requirements. Adaptation never generates credentials or keys;
the explicit commands below stage durable material for later activation.

For rollover, create a new provider key using the same store file:

```sh
bin/authcrunch security oidc create signing key \
  --config /var/lib/caddy/security-private/oauth_store.Caddyfile \
  --name login --revision k2
```

Update `signing key files` to list the new path first and old path second.
The first key signs new ID tokens; both public keys appear in JWKS. After the
required token/cache overlap, remove the old path from configuration deliberately.
Client IDs and secrets remain unchanged. Retain private keys needed for rollback
under the same permissions; never reuse portal access-token keys for OIDC.

## Secret-bearing surfaces

Stored references remove generated application credentials from adapted JSON,
autosave, and admin configuration views. Runtime errors and CLI output omit
secret values. Explicit inline credentials, identity-store passwords, access-token
keys, and other modules can still make these surfaces secret-bearing. Keep full
Caddy configs and exported diagnostics private; protect or disable admin access
as appropriate. Back up registration revisions, provider keys, and their matching
deployment configuration with equivalent access restrictions and encryption at
rest. A generic configuration dump does not back up this OAuth registration store.
