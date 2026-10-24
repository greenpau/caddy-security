# Encrypted Documents API

Read this reference for Documents HTTP clients and browser encryption. The
[configuration owner](../../configuration-authentication/references/documents.md)
defines explicit enablement, eligible realms, SQLite storage and mount binding.
Use the selected AuthCrunch module's authored OpenAPI components and paths for
exact payloads; the feature is not a generic JSON proxy or a profile-key API.

## Authority and transport

All paths below are relative to the configured portal mount. The API requires
a valid portal-admitted access token **and the current cached browser session
associated with that exact token**. Its login evidence must identify the current
local account and credential epoch in an enabled realm, with user or admin
portal capability. Transformed `sub` or email claims do not select the owner:
storage uses the immutable account UUID. A JWT signature alone, native login or
native refresh, an external-provider attachment or an OP session is insufficient.
Admin capability does not grant access to someone else's documents.

Use the natural HttpOnly cookie jar from browser form login, or an access token
from that same current browser session. Keep the request's effective HTTPS origin
equal to the configured public origin. If `Origin` is supplied, it must be the
single exact origin; if `Sec-Fetch-Site` is supplied, it must be `same-origin` or
`none`. Preserving existing browser headers is required; do not strip them to
make a cross-site request pass.

Body-bearing operations accept `application/json`, including valid media-type
parameters, with a single Content-Type and no Content-Encoding. The decoder
rejects unknown/duplicate/case-aliased fields, null required members, multiple
JSON values and excessive nesting. Resource IDs and chunk indexes belong in
their canonical route positions. Other operations have no request body.
Only file listing accepts a query: its single exact `after=<id>` cursor.
Do not add `format=json` to these dedicated API routes.

The server reads the bounded body before taking the identity transaction. It
rechecks current account evidence and the exact browser session after the read.
A password reset or same-browser account switch during a slow upload therefore
denies the completed request before storage mutation. A concurrent recipient
key reset similarly invalidates a stale share envelope.

Responses use JSON, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`
and `Referrer-Policy: no-referrer`, without login redirects or newly issued
credentials. Success resources are direct objects; ordinary successful mutations
return `{"success":true}`. Errors use `{"status":<HTTP code>,"message":"..."}`,
not the ordinary portal boolean-error envelope. A disabled API returns 404.

## Operations and lifecycle

| Operation | Method and relative path | Purpose |
| --- | --- | --- |
| Bootstrap | `GET /api/documents/bootstrap` | Read protocol, portal/user IDs, chunk size and limits; reserves the user's key slot. |
| Own key | `GET /api/documents/keys/fetch` | Read the current encrypted private-key vault and public key. |
| Register/reset key | `PUT /api/documents/keys/register`; `POST /api/documents/keys/reset` | Register the key or explicitly reset the current user/key pair. |
| Recipient key | `GET /api/documents/key/{user_id}/lookup` | Obtain a public recipient key and fingerprint. |
| List/allocate | `GET /api/documents/files`; `POST /api/documents/files/allocate` | List owned pending files and authorized ready files, or reserve ciphertext bytes and chunk count. |
| Manifest/commit | `PUT /api/documents/file/{id}/manifest`; `POST /api/documents/file/{id}/commit` | Store the encrypted manifest, then publish only after all chunks exist. |
| Read/delete | `GET /api/documents/file/{id}/fetch`; `DELETE /api/documents/file/{id}/delete` | Read an authorized ready file or delete an owned file. |
| Chunk | `PUT /api/documents/file/{id}/chunk/{idx}/put`; `GET /api/documents/file/{id}/chunk/{idx}/fetch` | Write an immutable encrypted chunk or read an authorized one. |
| Share/revoke | `PUT /api/documents/file/{id}/share/{user_id}/put`; `DELETE /api/documents/file/{id}/share/{user_id}/delete` | Let the owner add or revoke a recipient envelope. |
| Shares | `GET /api/documents/file/{id}/share/list` | Let the owner list granted recipient IDs. |

Allocation reserves quota before upload. A pending file has an absolute expiry;
later upload activity does not extend it. Expired pending files disappear from
access and release quota when reclaimed. Identical chunk retries are idempotent;
changing a stored chunk conflicts. Commit requires every declared chunk and
publishes the file to eligible recipients. An empty plaintext still has one
authenticated ciphertext chunk. The protocol's plaintext chunk size is 1 MiB;
byte quotas include the AES-GCM tag for every chunk.

Recipients can read but cannot redistribute or delete the owner's file. An
unauthorized resource is hidden with 404. Revocation prevents future server
fetches; it cannot erase plaintext or keys a recipient already obtained. Key
reset invalidates the old key context and does not release its permanent user
slot. Confirm recovery material before destructive key operations.

Common failures are 400 for malformed protocol inputs, 401 for missing/stale
session evidence, 403 for origin/identity/realm/role restrictions, 404 for absent
or hidden resources, 405 for the wrong method, 409 for state/key conflicts,
413 for excessive bodies, 415 for unsupported body encoding/media, 507 for
quota exhaustion and 503 for unavailable storage. Keep original status and
operation context when diagnosing failures. A storage failure is not permission
to generate a replacement key, retry an uncertain mutation blindly or fall back
to plaintext.

## Browser cryptography and recovery

The selected AuthCrunch source ships `pkg/authn/documents/client/crypto.mjs`.
Serve an intentionally selected, immutable copy with your client application;
enabling the API does not expose that module or create a document-management UI.
Use its public operations for enrollment, recovery-key unlocking, upload
preparation, chunk encryption/decryption and recipient envelopes. The server
stores ciphertext, encrypted metadata/private-key vaults, public keys and
wrapped document keys; never send plaintext, the recovery secret, an unwrapped
private key or a raw document key to the API or diagnostics.

Pin the bootstrap portal/user/protocol context, obtain the recipient's current
fingerprint before wrapping, and keep each document's key and authenticated
context together. Do not reuse a chunk nonce to encrypt different plaintext.
The helper snapshots caller buffers across asynchronous crypto operations and
reserves chunk numbers before encryption; preserve those protections when
building a client. Authentication-tag failure must stop decryption, not produce
partial plaintext.

Keep recovery material outside the server's document store. A fresh browser
context can recover its nonextractable private CryptoKey from the stored vault
and the recovery secret, then unwrap retained document keys. This is independent
of portal session persistence: after root replacement, reauthenticate and unlock
again. Losing both usable browser keys and recovery material makes ciphertext
unrecoverable through this API.

## Qualification through Caddy

`TestCaddyDocumentsE2E` checks the selected authored schemas and real TLS
protocol/authority behavior, malformed input, method/path ownership, slow-body
revocation, quotas and an actual upload deadline. Its browser journey uses the
selected module in trusted headless Chrome with natural form login and cookies,
two users plus an unauthorized administrator, multichunk and empty documents,
sharing, tamper rejection, revocation and fresh-context recovery after root
replacement. Private evidence is checked against logs, database bytes and
captured requests to catch plaintext/key leakage.

This is a bounded integration client, not a shipped Documents UI, a cryptographic
audit, or an OS-process restart test. The generic OpenAPI matrix samples other
portal routes; Documents has its own dedicated acceptance surface. Preserve
independent signature, authority, privacy and byte-equality assertions alongside
schema checks.
