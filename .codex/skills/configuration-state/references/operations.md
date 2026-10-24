# Keeping sessions across Caddy restarts

Enable the root [`state` block](../SKILL.md#configuration) with a stable private
directory, and keep that directory on a durable volume when replacing a
container. Restart at the same public origin with unchanged security
configuration. Allow the previous Caddy process to stop fully before starting
its replacement. Persistent-to-persistent `caddy reload` is rejected; the active
deployment keeps serving. A service manager or orchestrator must use stop/start,
with a brief availability gap, instead of overlapping instances on that volume.

The directory has one live AuthCrunch root owner. It requires a local Unix
filesystem with reliable advisory locking, atomic rename and directory sync.
Network filesystems and active/active replicas are unsupported. Windows opt-in
persistence fails closed. Missing storage is created privately (0700 directory,
0600 files); existing storage must retain those private permissions and the
service account's access.

First enabling state creates a new persistent runtime; it does not import live
volatile sessions, grants, pending requests, or replay history. Plan for fresh
login. Existing stateless access JWTs retain only the continuity provided by
unchanged verification keys and policy. Keeping the same directory matters for
subsequent durable restarts, not migration from an in-memory root.

A rejected live reload leaves the old deployment serving. A failed cold start
after a complete stop has no old serving process to preserve: retain the state
and failure evidence, correct the startup condition, and follow the recovery
rules below. Do not promise automatic rollback or uninterrupted availability.

## Retained authority

| Resource | Restart behavior |
| --- | --- |
| Completed direct OAuth sessions | With an explicit durable identity attachment, original opaque cookies work without another provider exchange; current identity/origin/ACL checks still apply |
| Portal browser sessions and generated signing keys | Completed users and generated keys persist; unexpired old JWTs still verify against the same public JWKS |
| Portal native/browser refresh | Omitted backend selection persists the owned memory store through root snapshots; selected SQLite retains families, deadlines and spent history in its own database with root namespace/generation binding. Provider families additionally require durable local attachment |
| Downstream OIDC | Browser sessions, consent, codes, access grants and rotating refresh families persist |
| Revocation/logout | Successful revocations and replay-triggered descendant denial survive restart |
| Local account security | Current account/credential versions still gate refresh, profile and OIDC; identity-file-only rollback invalidates old proof |

Restart does not extend expiration. Root state does not preserve unfinished
login, MFA/enrollment or interactive consent transactions. Upstream OAuth
callbacks also need a new attempt unless their separate selected
[pending-login store](../../configuration-oauth-providers/references/shared-login-storage.md)
preserves the transaction within its own expiry. Provider discovery and JWKS
verification still run normally; provider tokens are not retained for upstream
renewal. Stateless JWTs keep their existing
expiration/revocation semantics; persistent sessions do not make all signed
tokens immediately revocable.

Keep identity databases, explicit signing/TLS keys, provider credentials and
provisioned OAuth application registrations through their existing storage
owners. The runtime directory is not a configuration, user or registration
store. Protect Caddy configuration/autosave too: explicit secrets there remain
secret-bearing configuration.

Local identity stores in a persistent runtime must use file-backed databases;
`:memory:` cannot preserve the identity proof epoch and fails startup. For direct
OAuth and portal provider-snapshot restart continuity, declare a file-backed local
store and select it in the
provider with `attach to local identity store NAME`. Root state alone preserves
the session but cannot restore an implicit provider-private memory identity;
that old session or refresh family is denied after restart. Provider renewal
reuses the captured sanitized upstream identity without a new token/userinfo
exchange, while current local proof and policy still gate issuance. Keep both the identity file and runtime
state, with their matching proof epochs. Adaptation/validation does not open
runtime storage, so filesystem health and exclusive ownership are startup checks.

A changed normalized security configuration creates a new session epoch,
including removing and later restoring a component. Unrelated changes or
reordering may conservatively require login. The root-state directory itself and
diagnostic logging are excluded from the binding; selected backend configuration
and actual loaded public trust participate. Generated keys persist independently;
explicit key-configuration or material trust changes still apply. A directory only observes
configurations opened against it: temporarily omitting state or switching to
another directory does not revoke authority in the dormant directory.

## Named refresh database

Retain the [selected refresh database](../../configuration-authentication/references/refresh-storage.md)
alongside the root directory and identity/signing inputs. Its session/rotation
limits apply to the whole file across portals and namespaces; every declaration
and selected portal must use equal limits. Do not put the file inside a managed
state or OAuth-registration directory. Do not reuse its base/sidecar namespace
as a key, account, messaging, pending-login or other backend file.

The root namespace remains stable through compatible restarts. A changed complete
configuration generation transactionally retires that namespace's families and
spent history, releasing their capacity without modifying other namespaces.
Every immutable view rejects retired authority before mutation. Earlier committed
activation/migration is not undone if another database later fails startup; there
is no cross-database atomic startup or automatic rollback.

Losing/replacing the root directory is not repaired by retaining only the SQLite
file. Old namespaces may still occupy file-wide capacity, but new root state
does not adopt their credentials. Retain evidence and restore a complete matching
backup or plan fresh installation/revocation deliberately. Do not delete rows,
reuse namespace identifiers or raise capacity to conceal an unexplained failure.
Standalone legacy empty-scope records remain separate after supported migration;
named portal activation does not import them.

## Failures and recovery

Startup fails for competing owners, lost/corrupt encryption keys, catalogs or
committed records, unsafe permissions and unavailable storage. It never falls
back to memory. Caddy returns a redacted startup error describing the ownership
and storage requirements; inspect private storage and deployment ownership
without dumping keys, records or complete credential-bearing configurations.

A failed durable write disables state-backed decisions in that runtime.
Clients receive failure without a new credential. A recoverable snapshot-size
refusal retains the library's 503 or `temporarily_unavailable` protocol result;
existing credentials and unrelated components remain usable, and logout can
still commit. Do not treat it as a reason to retry a refresh automatically,
change directories or recreate the runtime.

Successful mutations are durable before the HTTP success response; shutdown
is not a final flush. Abrupt process death is covered, though an interrupted
commit can retire the affected component's ambiguous snapshot and require new
login. A lost response after successful rotation remains ambiguous to a client;
strict replay rules still apply.

Selected SQLite distinguishes cancellation before an attempted commit from a
failed attempted commit. The latter quarantines that handle and reports commit
uncertainty; a successful commit followed by cancellation or a late expiry check
can also be uncertain without poisoning unrelated families. HTTP failure must
withhold staged access/refresh/downstream credentials. A client cannot infer
rollback from 503, and must not replay the same exchange automatically. Restore
backend availability and use fresh authentication. Stateless access JWTs retain
their independent expiry/verification behavior.

Back up the entire directory together with configuration, identity databases,
registrations and explicit keys while Caddy is stopped/drained. Preserve the
matching `master.key` and all permissions. Never merge/edit individual records.
The encryption key lives beside the ciphertext, so protect/encrypt complete
backups as credentials. Restoring a whole matching older backup may restore
old authority; preventing operator/storage rollback requires an external
monotonic authority and a deliberate revocation/relogin plan. Deleting the
directory creates a new installation, not an ordinary recovery procedure.
