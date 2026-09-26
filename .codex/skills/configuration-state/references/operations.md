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

## Retained authority

| Resource | Restart behavior |
| --- | --- |
| Completed direct OAuth sessions | Original opaque cookies work without another provider exchange; current origin/ACL checks still apply |
| Portal browser sessions and generated signing keys | Completed users and generated keys persist; unexpired old JWTs still verify against the same public JWKS |
| Portal native/browser refresh | Families, deadlines, current credentials and spent-token replay history persist |
| Downstream OIDC | Browser sessions, consent, codes, access grants and rotating refresh families persist |
| Revocation/logout | Successful revocations and replay-triggered descendant denial survive restart |
| Local account security | Current account/credential versions still gate refresh, profile and OIDC; identity-file-only rollback invalidates old proof |

Restart does not extend expiration. Pending OAuth callbacks, unfinished login,
MFA/enrollment and interactive consent transactions must start again. Upstream
provider discovery and JWKS verification still run normally; provider tokens
are not retained for upstream renewal. Stateless JWTs keep their existing
expiration/revocation semantics; persistent sessions do not make all signed
tokens immediately revocable.

Keep identity databases, explicit signing/TLS keys, provider credentials and
provisioned OAuth application registrations through their existing storage
owners. The runtime directory is not a configuration, user or registration
store. Protect Caddy configuration/autosave too: explicit secrets there remain
secret-bearing configuration.

Local identity stores in a persistent runtime must use file-backed databases;
`:memory:` cannot preserve the identity proof epoch and fails startup. A direct
OAuth policy needs no identity database. Adaptation/validation does not open
runtime storage, so it cannot establish filesystem health or exclusive ownership;
those checks happen at startup.

A changed normalized security configuration creates a new session epoch,
including removing and later restoring a component. Unrelated changes or
reordering may conservatively require login. Storage path and diagnostic
logging are excluded from the binding. Generated keys persist independently;
explicit key-configuration changes still apply. A directory only observes
configurations opened against it: temporarily omitting state or switching to
another directory does not revoke authority in the dormant directory.

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

Back up the entire directory together with configuration, identity databases,
registrations and explicit keys while Caddy is stopped/drained. Preserve the
matching `master.key` and all permissions. Never merge/edit individual records.
The encryption key lives beside the ciphertext, so protect/encrypt complete
backups as credentials. Restoring a whole matching older backup may restore
old authority; preventing operator/storage rollback requires an external
monotonic authority and a deliberate revocation/relogin plan. Deleting the
directory creates a new installation, not an ordinary recovery procedure.
