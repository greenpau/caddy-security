# Profile Public Keys

These are user-owned keys stored through `/api/profile`, separate from portal
JWT signing keys, public JWKS, and privileged private signing-key export. The
selected go-authcrunch dependency uses the maintained ProtonMail OpenPGP parser for
historical armored public-key metadata. It adds no general OpenPGP encryption,
decryption, signing, verification, or new Caddy key-policy directive.

Consult upstream `pkg/identity/public_key.go`, `user.go`, `database.go`,
`pkg/authn/handle_api_profile.go`, `api_*user_*key.go`, and the
`identity-public-keys` skill as read-only references. Apply fixes here only
when the Caddy adapter breaks delegation; do not change sibling files or run
sibling test/build commands.

## Existing API Contract

An authenticated profile session uses `POST <portal>/api/profile`, JSON content
and `Accept: application/json`. The `kind` values include:

| Operation | PGP | SSH/RSA |
| --- | --- | --- |
| Upload | `add_user_gpg_key` | `add_user_ssh_key` |
| List | `fetch_user_gpg_keys` | `fetch_user_ssh_keys` |
| Fetch by ID | `fetch_user_gpg_key` | `fetch_user_ssh_key` |
| Delete by ID | `delete_user_gpg_key` | `delete_user_ssh_key` |

Uploads carry `content`, `title`, and `description`; individual fetch/delete
carry `id`. The profile owner comes from the stored login session, not arbitrary
username/email fields submitted in the body. Database writes check the
username/email pair. Duplicate uploads fail with HTTP 400. Unauthenticated
profile requests return 403 in the tested route configuration. Existing foreign
key fetch/delete failures return 500, not a newly invented API status.

Preserve the 1 MiB profile request limit and secret redaction. Malformed armor,
private armor, private RSA PEM, unsupported binary input, and unsupported SSH
types are rejected. Supported legacy payloads include PKCS#1 `RSA PUBLIC KEY`
PEM, `ssh-rsa` authorized_keys, and a single armored PGP public entity with
primary key and identities. Preserve existing algorithm policy and metadata,
including key ID, fingerprint, comment, normalized payload, and stored usage.
Do not turn this compatibility work into an algorithm-policy redesign.

The fixture `testdata/identity/legacy_pgp_public.pem` is copied unchanged from
go-authcrunch v1.2.5 `testdata/gpg/linux_gpg_pub.pem` (Apache-2.0 repository).
It is historical public test material: DSA key ID `a040830f7fac5991`, fingerprint
`4cca1eaf950cee4ab83976dca040830f7fac5991`. No private key fixture is committed;
RSA test keys are generated in private temporary test storage/memory.

`TestProfilePublicKeyParserCompatibility` consumes the public identity parser
to check historical metadata and rejection of actual decoded binary packets
without JSON's UTF-8 normalization. It also rejects malformed/private armor
and a valid Ed25519 SSH key outside the supported format boundary.
RSA cases check each historical fingerprint format and independently decode the
stored OpenSSH representation to verify the original public key is preserved.
`profile_public_key_e2e_test.go`, run by `TestCaddyLocalIdentityE2E`, exercises
uploads, inventories, duplicates, negative inputs, body limits, file reopening,
Caddy stop/start, and another user's fetch/delete isolation with untransformed
identities. It verifies historical PGP metadata and RSA/ssh-rsa behavior through
actual TLS profile routes. Body-limit assertions use a valid upload with ignored
JSON padding: exactly 1 MiB succeeds, one byte more fails without mutation.
Malformed oversized key content alone cannot establish that limit. Inventory
responses must contain an array, and foreign fetch failures must not return a
key entry. Successful owner fetch/delete requests are positive controls for
those failures. Two users can store the same PGP public material; deleting it
from one user's inventory must preserve the other's copy. These tests do not
exercise hardware authenticators or WebAuthn assertions.

## Canonical Profile Identity Regression

The go-authcrunch commit `3e28980b0f5a78463953b674241f154bb77c6679`, included
in selected v1.3.3, fixed the earlier v1.2.5 profile ownership defect. Profile access now uses the
canonical authenticated local identity and its current security version, even
when token transforms replace `sub` and `email` with another real account.
Caddy continues to delegate this decision to the library.

`local_identity_profile_regression_test.go` is now part of the default suite.
`TestCaddyProfileCanonicalIdentityRegression` logs in as Alice, applies colliding
Bob claims, reads Alice's profile and verifies that a public-key upload changes
only Alice's persisted record. Run it directly with:

```sh
go test -mod=readonly -race -count=1 -timeout=2m \
  -run '^TestCaddyProfileCanonicalIdentityRegression$' .
```

The old `identity_profile_regression` build tag is no longer required. Keep the
ownership assertions enabled; do not infer identity from transformed claims in
Caddy or duplicate the library's profile handler.
