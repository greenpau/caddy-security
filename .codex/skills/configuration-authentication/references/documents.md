# Documents API configuration

Read this reference to enable encrypted document storage for a portal. HTTP
clients and browser cryptography use the [Documents API contract](../../authentication-portal-api/references/documents.md).
This feature has an independent API switch and SQLite database; enabling admin,
profile or private-key export does not enable it.

## Declare the feature

Put flat statements directly inside an `authentication portal` block:

```caddyfile
enable identity store localdb
enable documents api
documents api database /var/lib/caddy/documents/myportal.db
documents api public origin https://auth.example.com
documents api base path /company/auth
documents api realms local
```

Define `localdb` as a local identity store with realm `local`, and mount the
portal with `authenticate with myportal at /company/auth`. The database's parent
directory must already exist with owner-only permissions. The database is a
regular file with mode `0600`; it must be outside every served file root. The
backend can create the file, but not its parent directory. Keep account storage
private too. No CLI provisioning command or document browser is created by
these directives.

The complete optional limit grammar is:

```caddyfile
documents api max file bytes 268435456
documents api max user bytes 1073741824
documents api max total bytes 10737418240
documents api max user files 1000
documents api max total files 10000
documents api max keys 10000
documents api max recipients 100
documents api upload ttl seconds 86400
```

Those numbers are the defaults. Zero selects the corresponding default. Byte
quotas count ciphertext, including authentication tags and unfinished uploads.
User bytes must cover one maximum file; total bytes must cover the user quota.
Total file count must cover the user file count. Upload TTL is 60–604800 seconds.
Use the selected shared validator for the remaining upper bounds rather than
duplicating them in a Caddy-only validator.

Every setting occurs at most once, including the opposing `enable documents api`
and `disable documents api` forms. Nested blocks, joined keywords, empty values,
negative numbers and unknown statements fail. Quotes preserve an individual
path or realm containing spaces; multiple realm arguments remain separate
values. Imports contribute to the same portal statement collection and duplicate
checks. Host adaptation delegates the complete collection to AuthCrunch's public
Documents parser, then applies its result through `ConfigureDocumentsAPI`.

Omission, explicit disable and storage-only declarations leave the API disabled.
Disabled configuration still obeys directive grammar, duplicate and numeric
syntax checks, but does not validate storage semantics, open the database or
constrain the handler mount. Native disabled storage likewise retains the
shared opt-out semantics. Do not apply an empty Documents configuration to a
portal that never declared the feature. Preserve its other API switches.

## Identity, origin and mount

Enabled storage requires an absolute database path, an already serialized HTTPS
origin and at least one distinct realm. The origin has no path, trailing slash,
userinfo, query or fragment; reject browser-normalized aliases rather than
silently changing a permanent binding. The base path defaults to `/` and uses
the shared [portal mount rules](../../configuration-http-integrations/references/portal-mounts.md).
An explicit handler's mount must equal the resolved Documents base path.

Each realm must select exactly one transactional identity store attached to
this portal. A declared but unselected store does not qualify. The current HTTP
contract additionally requires the `local` login method and current browser
session evidence: transactional support in a custom or SQLite store alone does
not grant Documents access. That restriction governs browser-session admission,
not an additional Caddy declaration allowlist. OAuth/SAML/ticket login, a native access token,
refresh credentials and an administrator role are not substitutes. See the API
owner for exact authority and request checks.

The app cannot establish a deployment's external origin merely by reading its
route declaration. The operator must align HTTPS, trusted proxy handling,
origin and mount; the runtime checks the request's effective origin. Preserve
the full path through a non-stripping handler.

## Runtime values and native JSON

Literal statements adapt to `authentication_portals[].api.documents_enabled`
and `authentication_portals[].documents`. When any Documents value contains a
runtime reference, Caddy retains the entire Documents collection in
`portal_documents_directives`, keyed by portal name. Provisioning resolves each
original argument once, reparses the collection and applies it before portal
validation. Include that app-level snapshot when copying adapted JSON.

Native `documents.database`, `public_origin`, `base_path` and individual `realms`
values resolve once too. Native limits remain typed numbers. Deferred values,
including numeric limits, may resolve from environment or whole-value secret
references. Keep directive keywords literal. Supplied disabled values still resolve, but
disabled storage receives no semantic validation or defaults. Reject unknown or
ambiguous portal targets, empty snapshots and conflicting native Documents
settings. Returned secret values are data and must not be expanded a second
time. App provisioning uses private copies, preserving declarations and
snapshots for introspection and later candidates.

## Storage and replacement

The database permanently binds protocol, portal name, public origin and mount,
and retains a generated portal identifier. Reopening it under another binding
fails; changing configuration is not a migration. Account UUIDs also bind to
their original store name and realm, so copying accounts into a differently
named store does not transfer access to existing documents. Keep those bindings
stable when restoring storage.

The host checks Documents databases and SQLite sidecars against all known
bundled storage categories, local identity files and registration dropboxes,
and keeps them outside runtime-state and OAuth-registration directories. These
checks apply even when no ticket provider exists. They compare candidate
storage with the active Caddy graph in both directions, protecting old storage
when the candidate removes or relocates the feature. One candidate cannot bind
two portals to the same Documents file. A normal reload can reuse the same
canonical Documents file with the same immutable binding; local account-file
overlap and persistent-root restrictions still apply independently.

Read-only namespace checks precede live backend construction and run again for
deferred startup. Earlier secret and client-registration resolution may already
perform their own reads. Custom plugins own undeclared storage separation.
These checks do not coordinate another process or external filesystem/path
replacement. Keep filesystem permissions and backup procedures in place.
The [runtime lifecycle owner](../../coding-directives/references/runtime-lifecycle.md)
defines request drain and storage disposal. Documents data durability is
independent of volatile portal sessions: after root replacement, log in again
and recover the browser key before accessing retained ciphertext.

## Acceptance

`TestPortalDocuments*`, `TestAppDocuments*`, `TestDocumentsStorage*` and
`TestPortalMountDocumentsBindings` cover grammar, exact replacement, native
parity, disabled behavior, snapshots, storage aliases and binding constraints.
The `testcase_authenticate_with_documents` adaptation/resolution fixture covers
literal, deferred, disabled and storage-only portals; separate fixtures reject
blocks and duplicate settings.

`TestCaddyDocumentsE2E` exercises actual TLS at root and nested mounts, current
local-session authority, concurrent revocation during an unfinished body,
quotas/expiry, failed replacement and retained storage. Its real Chrome journey
qualifies encryption, sharing, revocation and recovery after root replacement.
Keep parser acceptance distinct from that runtime evidence, and do not claim
OS-process restart coverage from the in-process replacement journey.
