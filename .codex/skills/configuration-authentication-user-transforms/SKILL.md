---
name: configuration-authentication-user-transforms
description: "caddy-security authentication portal transform configuration. Use for transform user matchers, typed custom claims, role changes, conditional authentication challenge policies, MFA requirements, deny actions, UI links, and claim placeholders."
---

# Configuration Authentication User Transforms

Use for `transform user` or `transform users` inside an authentication portal.
`caddyfile_authn_transform.go` forwards the complete block to the selected
module's `pkg/authn/transformer/parser`; provisioning resolves individual
arguments and compiles the result again. Inspect `go list -m -json github.com/greenpau/go-authcrunch` before relying on sibling source. The
published v1.3.3 supports the grammar below.

Use [portal configuration](../configuration-authentication/SKILL.md) for wiring,
[static users](../configuration-users/SKILL.md) for stored challenge rules, and
[authentication flows](../authentication-portal-api/references/authentication-flows.md)
for login and profile API contracts.

## Matchers and actions

Every block needs at least one matcher and one action. Conditions combine as
match-all. Ordinary bare `match` retains the historical `exact match` spelling
in adapted JSON; `match any` stays unconditional. Classification uses the
shared parser, so a claim value containing the word `match` remains an action.
These are alternative statements inside a transform, not a complete config:

```caddyfile
match any
match realm local
field email exists
field picture not exists
partial match email @example.com
no regex match any role ^authp/(admin|user)$
action add role authp/user
action overwrite roles authp/user
action drop matched role
action delete org
require mfa
deny
ui link "User Profile" /auth/profile/ icon "las la-cog" target_blank
```

ACL strategies are `exact`, `partial`, `prefix`, `suffix`, and `regex`, with
optional `no` and `any` according to `pkg/acl/condition.go`. Field aliases come
from `pkg/acl/acl.go`: for example `role`/`group`/`groups` → `roles`, `mail` →
`email`, and `subject` → `sub`. `amr` is a list of verified methods.

`action` is optional before `add`, `overwrite`, `delete` and `drop`; it does
not prefix `require`. `block` and `deny` are synonyms. Actions and matching
transforms retain declaration order. `overwrite` accepts known claim fields; `delete` also removes custom fields.
Custom claims use `add` with an explicit type:

```caddyfile
add matrix_id "@{claims.sub}:matrix.example.com" as string
add teams "operations team" support as string list
add nested metadata label with "literal value" as string
add nested empty as map
```

A custom scalar needs exactly one value. List aliases are `list`, `string_list`
and the two keywords `string list`. Nested paths need at least one key; values
follow `with`, and an empty map uses `as map`. Nested values are literal;
ordinary string/list actions expand claim placeholders. Follow
`pkg/authn/transformer/parser/custom_fields.go` and its runtime consumer rather
than inferring grammar from JSON.

`{env.*}` and whole-value `secrets:<id>:<key>` resolve during Caddy provisioning.
`{claims.*}` templates survive that pass only in transform arguments and expand
at authentication time in action values. ACL matcher values remain literal.
Quotes, spaces and secrets remain a single argument;
empty resolved tokens and unknown Caddy placeholders in configured arguments
fail provisioning. Encoded native JSON actions and matchers must each contain
one line; reject CR/LF before decoding so a later CSV record cannot disappear.
Resolved multiline transform values also fail shared validation. Caddy does not
recursively expand inserted replacement data. See
[runtime resolution](../configuration-runtime-resolution/SKILL.md).

## Unconditional matcher restriction in v1.3.3

`match any` is accepted for access-only portals without System API keys. Caddy
rejects it when portal refresh or the OIDC provider is enabled, or a portal
crypto key has `system` usage. This provisioning check covers Caddyfile and
native JSON, including quoted or runtime-resolved matcher encodings and
runtime-resolved key usage. The check follows the ACL's decoded argument meaning,
not the serialized spelling. Disabled/absent renewable
features remain supported when no System API key is configured.

The upstream ACL implements this matcher through the `exp` field. Ordinary
login provides it, but refresh/OIDC identity checks and encrypted System API
assertions transform fresh backend claims before timestamps exist. That can silently skip claims or challenge
requirements. Use an explicit `match realm local` (or the intended realm list)
with those features. Caddy does not rewrite matchers or fabricate timestamps.

`TestPortalTransformMatchAnyIdentityContext` records the upstream behavior and
checks the guard for each feature independently; `TestPortalTransformMatchAnyEncoding`
checks equivalent native JSON encodings. The challenge E2E verifies
access-only matching and rejected replacement while the active refresh/OIDC
session remains usable. The adapt/resolution fixture
`testcase_authenticate_with_match_any_refresh` and
`testcase_authenticate_with_match_any_system` accept syntax and reject runtime
resolution. System API E2E checks encrypted password assertions, realm-based
claims, rejected replacement and denial when the selected policy requires TOTP. See the [upstream work needed](../configuration/references/authcrunch-compatibility.md#upstream-match-any-limit)
before removing this restriction.

## Conditional authentication

Inside a portal, this policy prefers an enrolled security key, then an enrolled
TOTP token, then the account password:

```caddyfile
transform user {
	match realm local
	require auth challenges u2f
	require auth challenges totp if u2f not available
	require auth challenges password if u2f and totp not available
}
```

Rule bodies are parsed by `pkg/authchal/parser`:

```text
<method> [<method>...] [if <method> [and <method>...] not available]
<method> [or <method>...] [if <method> [and <method>...] not available]
```

Methods are `password`, `totp`, `u2f`, and `mfa`. Adjacent methods require all;
`or` selects the first available alternative. `mfa` represents an available
second factor. Conditions require the named credentials to be unavailable.
Do not mix an `or` choice with adjacent-method requirements. Duplicate rules,
unknown methods and email methods/conditions are rejected: the portal has no
email checkpoint. Method keywords are literal configuration, not placeholders.

The first eligible rule across matching transforms replaces backend/user
challenge selection. Credential availability comes from server-owned inventory,
never `roles`, `amr`, or transformed claims. If a matched conditional policy has
no eligible rule, authentication fails; it does not fall back to a password.
Without a matching conditional policy, stored user rules/defaults apply.

Legacy `require password|mfa|totp|u2f` remains additive after selection; it can
force MFA enrollment when appropriate. Replacing the backend policy can remove
the password checkpoint: a TOTP-only or U2F-only rule is a deliberate policy
choice. Use adjacent `password totp` when both proofs are required.

Successful tokens receive authoritative AMR evidence: password → `pwd`, TOTP →
`otp`, WebAuthn/U2F → `hwk`. Transform actions cannot fabricate completed
methods. Direct Basic and API-key login, portal refresh, OP sessions and OIDC
refresh reevaluate current policy and cannot bypass unmet requirements.
Request-context matchers (such as issuer/address) evaluate current request
context, including backchannel requests; use stable realm/identity selectors
unless that context dependence is intentional.

## Validation

`caddyfile_authn_transform_test.go` covers shared parsing, custom claims,
canonical JSON, conditional selection, errors and runtime replacement.
`testcase_authenticate_with_challenges` supplies adapt/resolution fixtures.
`TestCaddyAuthenticationChallengesE2E` exercises actual verified Caddy TLS:
root/nested mounts, HTML/JSON and native clients, TOTP/U2F-only selection,
password fallback, AMR authorization, refresh/OIDC, Basic/API-key rejection, no eligible
rule, stored policies and profile edits. WebAuthn uses signed assertions and
rejects wrong origin and signature. Keep these boundaries when extending syntax.
