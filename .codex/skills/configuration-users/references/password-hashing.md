# Local password imports and generation

## Ownership and representation

The existing local-user `password <value> [overwrite]` directive accepts trusted
`bcrypt:<cost>:<hash>` and `argon2:<PHC>` imports. Caddy preserves the value through
tokenization, JSON and runtime replacement. AuthCrunch owns parsing, resource
validation, algorithm dispatch, store-wide verification work, and credential
revocation. Do not introduce a password-hashing Caddyfile block, an independent
verifier or a verification cache. Portal Basic login uses the same library store;
Caddy's unrelated `basic_auth` hashing format is outside this contract.

Argon2 means **Argon2id v19**, with this exact schema:

```text
argon2:$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>
```

There is no outer cost field. Parameters must be canonical decimal values in
`m,t,p` order; salt and hash use canonical unpadded standard Base64. Argon2i,
Argon2d, other versions and malformed fields fail provisioning. Bcrypt imports
also require a canonical outer cost matching the encoded cost, supported headers,
correct separators, and canonical salt/checksum encoding. Fix malformed fixtures
instead of making the Caddy adapter permissive. Provisioning errors must not
include hashes or plaintext; even an unexpected password option is reported
without echoing its value.

Quote complete values. This is a real library-generated **test-only** password
for `Argon2FixturePassword42!`, with deliberately modest work factors. Inside a
`local identity store` block:

```caddyfile
user alice {
    email alice@example.test
    password "argon2:$argon2id$v=19$m=1024,t=2,p=2$mjBUxIgaxCd2UQA9tzdTUQ$z5MrHTVraToXYev67Zg47cpvqEWp/WufD0u4oyK+V+c"
    roles authp/user
}
```

Generate a new credential with the CLI defaults for a deployment. The existing
Caddy fixture `testcase_authenticate_with_argon2` also covers bcrypt and plaintext.

## Generate and supply a password

The existing offline generator prompts without echo:

```sh
bin/authcrunch security local generate password hash --algorithm argon2
```

It prints a complete quoted password directive. `--password-file` accepts a
private file, or `-` for stdin; never put plaintext in arguments. Optional
`--memory` (KiB), `--iterations`, and `--parallelism` use AuthCrunch's shared
password configuration parser. The defaults are 65536 KiB, three passes and four
lanes, with a random 16-byte salt and 32-byte output. `--cost` is bcrypt-only.
Algorithm names must match exactly; surrounding whitespace is invalid and is
rejected before the command reads the password.
See [offline generators](../../scripts-and-automation/references/local-user-commands.md#offline-generators)
for input rules, independent database policy checks, and compatibility details.

To keep hashes out of a Caddyfile, supply the entire generated import through
an environment variable or a supported secret lookup. These are alternative
lines inside the user block:

```caddyfile
password "{env.ALICE_PASSWORD_HASH}" overwrite
password "{$ALICE_PASSWORD_HASH}" overwrite
password "secrets:users/alice:password" overwrite
```

`{$NAME}` expands at adaptation; `{env.NAME}` expands at provisioning, including
native JSON. Literal dollar signs, plus signs and slashes in the substituted
hash remain unchanged. If setting a hash in a shell, single-quote its value to
avoid shell dollar expansion. Adapted JSON can contain credentials; protect it.

## Bounds and operational behavior

Import and generation enforce these limits together:

- Memory: at least `8 * parallelism` KiB and at most 262144 KiB.
- Iterations: 1–10; parallelism: 1–16.
- Memory times iterations: at most 1048576 KiB-passes.
- Imported salt: 8–64 bytes; output: 16–64 bytes; PHC: at most 256 bytes.

Custom settings can be weaker than defaults. Every active work profile adds
verification work to the store's padded schedule, including missing-user
attempts. Keep authentication delegated to the database. These bounds are not
a process-wide memory-admission guarantee.

New plaintext users remain bcrypt by default; there is no bulk conversion or
rehash-on-login. Argon2 users retain Argon2 at current generation defaults for
plaintext changes/resets. Explicit bcrypt imports switch back. API keys remain
bcrypt. Persistence stores `algorithm: argon2` and the PHC in `hash`, without
bcrypt `cost`; omitted algorithm in legacy records still means bcrypt.

`overwrite` intentionally reapplies the configured credential on provisioning.
An identical enabled import reuses its active hash and timestamp without adding
history, but the database credential version still advances. Omission preserves
an existing user's password. Use stop/start for file-backed configuration changes;
Caddy rejects overlapping runtimes owning the same identity file. Do not infer
session survival from persistence when the config requests overwrite.

## Public-input boundary

Imports belong to trusted provisioning. Profile password changes and public
registration reject reserved `bcrypt:`/`argon2:` prefixes, including malformed
and whitespace-padded inputs. Rejection leaves credentials and refresh eligibility
unchanged; a successful plaintext password change invalidates prior renewable
credential evidence. Never bypass this guard via generic trusted database APIs.
Raw login candidates remain plaintext: an encoded hash does not authenticate as
its underlying password, and plaintext containing a reserved prefix can still
match a legitimately created credential.

See [local identity compatibility](../../configuration-identity-stores/references/local-identity.md)
for mutation, refresh, stateless access-token and session boundaries.

## Qualification

Published go-authcrunch v1.3.6 contains feature commit
`a0928dbd146abfbb744438d4838436d846eea637`, including its public-input guards.
Check the effective module and `bin/authcrunch security version` for the actual
build; a sibling `VERSION` file or the presence of Argon2 symbols is insufficient.

The default suite covers:

- `TestPasswordImportAdaptAndResolve`: exact quoted imports, environment expansion,
  runtime replacement and JSON round trips, plus bcrypt/plaintext compatibility.
- `TestPasswordImportDirectiveErrorsRedact` and the malformed adaptation fixture:
  invalid password arity/options fail without echoing credentials.
- `TestPasswordImportProvisioningRejectsMalformed`: library store provisioning
  rejects invalid imports without storing a user or exposing credentials.
- `TestSecurityCredentialArgon2*`: shared options/defaults, random output,
  exact algorithm names, long plaintext, incompatible/excessive settings,
  private input, read-only policy
  selection independent of username constraints, and output failure.
- `TestCaddyPasswordArgon2E2E`: builds `cmd/authcrunch`, generates/imports a hash,
  and uses verified local TLS for HTML/native/Basic login, signed token and route
  authorization, wrong/missing/hash-as-password rejection, persistence, overwrite,
  profile rejection/change/refresh revocation, and registration import rejection
  with a local file-message positive control. Rate limiting stays enabled.

Routine fixtures use modest work factors; production defaults are exercised by
plaintext replacements. Resource-bound rejection never derives at invalid costs.
Library scheduling/vector tests remain upstream evidence; this suite does not
claim timing equivalence or complete user-signup approval/SMTP qualification.

```sh
go test -mod=readonly -run 'TestPasswordImport|TestSecurityCredentialArgon2|TestCaddyPasswordArgon2E2E' .
make ci-check
```
