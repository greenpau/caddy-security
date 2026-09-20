# Conditional login and profile authentication flows

## Ownership and selection

The selected go-authcrunch v1.3.3 owns checkpoint selection, credential evidence
and the profile handlers. Caddy exposes
[`require auth challenges`](../../configuration-authentication-user-transforms/SKILL.md)
in portal transforms and [`auth challenges`](../../configuration-users/SKILL.md)
in static local users. No new HTTP route or profile API enable directive is
needed. Existing `enable/disable profile api` controls access.

A matching portal policy replaces the backend/user selection with its first
eligible rule. With no eligible rule, login fails without issuing credentials.
Legacy `require` actions add checkpoints. Availability is server-owned enrolled
credential inventory. Follow the returned challenge sequence; do not assume
that password is first or present. Never reuse a rotated sandbox secret.

Stored user rules also fail closed when no rule matches the enrolled inventory.
Deleting the only factor required by a stored rule does not clear that rule or
automatically allow password-only recovery. An administrator can explicitly
replace the stored rules with `password`; an additive portal `require mfa`
still requires enrollment afterward. The server API requires a nonempty
replacement and rejects `[]`, unlike the profile reset described below.
The local-identity mutation E2E covers this boundary.

The public Go authclient handles password/TOTP-only flows, including a missing
password when the selected policy does not request it. It rejects unsupported
WebAuthn assertions. A WebAuthn client must sign the returned challenge for the
actual origin and RP ID; wrong origin/signature is rejected.

Tokens contain verified `amr` methods (`pwd`, `otp`, `hwk`), not the available
methods or user-supplied transform values. Current policy also applies to direct
Basic/API-key login, portal refresh, OP sessions and OIDC refresh. Backchannel
policy evaluation uses current request context, including issuer and address.
A configuration that depends on request context can invalidate an older session.
Caddy rejects `match any` transforms with enabled refresh/OIDC or System API keys because upstream
checks lack the timestamp that matcher uses; use explicit realm matchers. See
the [compatibility restriction](../../configuration-authentication-user-transforms/SKILL.md#unconditional-matcher-restriction-in-v133).

## Profile API

Send JSON POSTs to `<portal-base>/api/profile` with an authenticated local
user, the normal profile transport/origin requirements, and
`Accept: application/json`. Identity comes from the bound authenticated user;
a body-supplied username cannot target another account. Existing profile access,
credential-version and request checks still apply.

Fetch with:

```json
{"kind":"fetch_user_auth_challenges"}
```

The successful response includes arrays `entries` (stored rule bodies),
`registered_methods` (enrolled methods), `effective_challenges` (current login
checkpoints), and `additional_challenges` (legacy transform requirements).
`policy_source` is `default`, `user`, or `portal`. Empty arrays remain arrays.
This is a preview for a login in the current request context, not a universal
policy simulation. An unresolvable effective policy returns 409.

Replace with an ordered array of shared-parser rule bodies:

```json
{"kind":"overwrite_user_auth_challenges","challenges":["u2f","password totp if u2f not available"]}
```

Reset the stored rules to defaults with:

```json
{"kind":"overwrite_user_auth_challenges","challenges":[]}
```

Missing/null/scalar arrays, non-string or empty entries, malformed/duplicate
rules, email checkpoints, or a candidate with no selectable supported flow
return 400 before mutation. The handler validates a detached candidate against
registered credentials and the current portal policy, then commits through the
bound identity's credential version. An explicit portal policy still overrides
a saved user policy. A static Caddyfile policy can reapply its configured rules
on the next provisioning.

Successful replacement/reset returns the preview and
`reauthentication_required: true`. Discard prior login evidence and perform a
fresh login. Credential-version changes invalidate stale profile operations,
refresh families and OIDC evidence. Do not automatically retry an uncertain
mutation or treat a 200 response as a refreshed session.

## Caddy validation

`TestCaddyAuthenticationChallengesE2E` verifies fetch, candidate rejection
without mutation, owner isolation, replacement/reset, stale profile/refresh
rejection and fresh login through actual Caddy TLS. It also verifies
root/nested HTML/JSON selection, public authclient TOTP-only login, password
fallback, signed WebAuthn with origin/signature rejection, AMR authorization,
portal refresh and independently verified OIDC tokens. Sources are
`api_fetch_user_auth_challenges.go`, `api_overwrite_user_auth_challenges.go`,
`profile_auth_challenges.go` and the transformer/challenge parsers under the
selected module's `pkg/authn` and `pkg/authchal` directories.
