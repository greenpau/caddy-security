# Named Refresh Storage

## Selection and configuration

Declare the backend in the global `security` block and select it inside each
participating portal. Keep the database outside the managed root-state directory:

```caddyfile
security {
    state {
        directory /var/lib/authcrunch/runtime
    }
    token refresh store sqlite sessions {
        path /var/lib/authcrunch/refresh.db
        max sessions 10000
        max rotations 1024
        timeout 1s
    }
    authentication portal myportal {
        enable identity store employeesdb
        token refresh {
            store sessions
            realms employees
            public origin https://auth.example.com
            base path /auth
            max sessions 10000
            max rotations 1024
        }
    }
}
```

This is a global-block fragment; supply the named local identity declaration,
ordinary crypto configuration and matching portal route in the full Caddyfile.
The SQLite parent directory must already exist with private permissions; newly
created database files use mode `0600`. Do not place it inside root-state or OAuth
registration directories or reuse another backend's database, journal, key or
local user file. Existing physical aliases and SQLite sidecars participate in
admission checks before live backend constructors. A later filesystem change
can still invalidate storage; keep serving paths stable.

The global header is exactly `token refresh store sqlite NAME`. Its flat body
accepts `path`, `max sessions`, `max rotations` and `timeout` once each. `path`
is a required absolute file path. Defaults are 10000 families, 1024 rotations
and a 1-second operation timeout. Each limit is within 1–100000; timeout accepts
Go durations within 1ms–30s. The backend parser rejects explicit zero limits;
omission supplies defaults. Portal integer zero retains its existing default
semantics, and the resulting values must equal the backend limits. Capacity and
spent-digest uniqueness apply to the whole database, not separately per portal,
realm or namespace. Changing timeout does not change persisted capacity limits.

The module is `security.refresh_stores.sqlite`; native app JSON uses
`refresh_stores` entries with `driver`, `name`, `path`, `max_sessions`,
`max_rotations` and `timeout`. Native portal JSON selects it with
`refresh_tokens.store`. Backend fields stay literal, apart from Caddy's lexical
`{$ENV}` expansion. Portal selections support existing runtime environment and
secret replacement once; an originally nonempty selection may not become empty.
An empty or omitted native selector preserves the existing memory default.
Unknown, duplicate or disabled selections fail before opening a backend.

## State, generations and ownership

Selected storage requires root [state](../../configuration-state/SKILL.md).
Retain the root state, stable signing keys and file-backed identities as well as
the refresh database across a complete stop/start. The database alone does not
retain identity policy, implicit in-memory provider identities, pending login
checkpoints, OIDC grants or direct OAuth application sessions. The exclusive
root-state deployment boundary still rejects overlapping persistent reload;
local SQLite storage is not an HA or distributed ownership mechanism.

The app prepares an immutable factory and scalar core descriptor without I/O.
Provisioning validates references, limits and physical file ownership; deferred
Start rechecks the original opening paths before construction. Runtime metadata
must match the frozen descriptor. The root checks readiness without writing a
probe and activates a namespace/generation only after final configuration
normalization and persistent epoch admission. The selected portal remains
unavailable until its one manager is ready; it never falls back to memory.

Same-generation activation preserves completed families and deadlines. A changed
configuration generation atomically retires that namespace's families and spent
hashes across its portals, reclaiming capacity while leaving other namespaces
alone. Each view captures its generation. Its operations transactionally reject
a retired view before inspecting replay state, purging expiration or deleting
families. The marker is not a replacement for the root's exclusive state lock.
Restoring an earlier configuration does not revive retired credentials.

The root borrows the exact backend and activated views. The app collects optional
closers even from partially failed constructors, sanitizes plugin boundary
errors and closes in reverse order after admitted requests drain and the root
closes. Modules and prepared factories do not own opened handles. SQLite refresh
families are not duplicated into legacy portal-refresh snapshots.

## Migration and recovery

Opening a recognized older database verifies its complete schema, configured
limits, canonical records and replay history before a transactional migration.
Existing local and provider evidence remains in the legacy empty namespace;
activation never adopts those records as managed credentials. Migration keeps
spent hashes and uses new table names so an already-open older SQL client cannot
mutate the migrated families. Unknown or modified schemas, inconsistent history,
incompatible limits and invalid records fail without publishing a store.
Perform backups and schema recovery while the application is stopped; do not
copy or open/close raw database file descriptors alongside serving SQLite handles.

Transaction lock acquisition can wait within the configured timeout. Cancellation
before an attempted commit preserves a healthy handle. A failed attempted commit
has an uncertain outcome: the backend is quarantined, and the request must not
publish staged access, refresh or downstream OIDC credentials. A successfully
committed transaction followed by request cancellation or a late expiry check
is also uncertain to the client, without necessarily poisoning other families.
The core sentinel takes precedence over ordinary denial/cancellation branches.

Do not retry an ambiguous exchange automatically. Keep the original failure
visible, reopen unhealthy storage only after resolving its condition, and require
fresh authentication. Browser recovery and native clients must discard uncertain
continuation state; stateless access tokens retain their own expiry and policy.
The separate [refresh HTTP contract](../../authentication-portal-api/SKILL.md#portal-refresh-transports)
owns request transport and response details.

## Validation surfaces

Pure module/parser tests cover defaults, duplicate grammar, literal fields,
no-I/O preparation, descriptor normalization and native/deferred one-pass
selection. App tests cover malformed bindings, input snapshots, partial handles,
root rejection, deferred Start, lease draining and exact cleanup order. Storage
admission tests exercise all known file categories, hardlinks, symlinks, sidecars,
managed directories and candidate/active ownership without requiring a ticket or
Documents declaration.

Acceptance must exercise the selected store through actual Caddy TLS routes:
local and provider login, browser/native rotation, exact JWT/protected-resource
checks, replay and logout across processes/restarts, namespace isolation,
configuration generation retirement at capacity, current identity/MFA policy,
real attempted-COMMIT failure, unavailable storage and fresh-login recovery.
Library tests and adaptation alone do not establish those host guarantees.
