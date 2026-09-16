# Portal OpenID Provider

Use `oidc provider` to let a portal issue OIDC tokens to selected named OAuth
applications. External login through an upstream OIDC service belongs to
`oauth identity provider`, a separate configuration surface.

## Collection and validation

`caddyfile.go` registers every named application before parsing portals,
independent of declaration order and Caddy file/snippet imports.
`caddyfile_authn_oidc.go` collects the flat provider body and preserves quoted
values with the shared directive codec. `caddyfile_authn.go` attaches it with
`Config.ConfigureOIDCProvider` after collecting the complete portal and before
`AddAuthenticationPortal` validates it. Do not add a second field parser or
validate the portal before attaching OIDC. AuthCrunch v1.2.4, pinned in `go.mod`,
provides `pkg/oidc/parser.NewOIDCProviderConfigFromDirectives` and
`PortalConfig.ConfigureOIDCProvider`.

Only one provider block is allowed per portal, including disabled blocks and
blocks expanded from repeated imports. An absent block remains nil. A present
block defaults enabled; an empty block fails enabled-provider validation.

Inside `authentication portal myportal`, each setting occurs at most once:

| Setting | Arguments |
| --- | --- |
| `enabled` / `disabled` | Standalone, mutually exclusive; no boolean value. |
| `issuer` | One canonical HTTPS URL including the portal mount, without a trailing slash. |
| `realms` | One line with one or more distinct local realm names. |
| `applications` | One line with one or more distinct registered nicknames, in selection order. |
| `signing key files` | One line with one or more distinct absolute paths to dedicated private RSA PEM files. |
| `session lifetime`, `token lifetime` | One decimal integer in seconds. |
| `max sessions`, `max pending requests`, `max grants` | One decimal integer count. |

Multiword keywords are separate tokens; `"signing key files"`,
`signing_key_files`, and `max "pending requests"` are invalid. Quote key paths
containing spaces. Nested blocks, extra scalar values, unknown fields, empty
arguments, and repeated settings fail. Zero numbers retain library defaults:
28,800 seconds for sessions, 300 seconds for tokens, 10,000 sessions, 1,024
pending requests, and 10,000 grants. Negative or excessive enabled values fail
the library's bounds checks.

Check the enclosing portal's closing boundary as well as the provider body.
Caddy's segment collection counts quoted brace-valued arguments as braces;
such a value must not make a truncated portal pass adaptation.

A standalone `disabled` requires no issuer, realms, keys, or applications.
Syntax and explicitly selected applications still validate: unknown or nil
registrations, repeated nicknames, and duplicate selected protocol client IDs
fail even when disabled. Other disabled values retain AuthCrunch's semantic
validation opt-out. Nicknames differ from client IDs; distinct registrations
may share an ID only if one provider does not select both.

## Realm and issuer boundaries

Every selected realm must identify exactly one local store attached to that
portal, with no conflicting upstream identity provider. LDAP and other upstream
realms are unsupported for OIDC participation. More than one local realm may
participate. `enable identity store` controls portal login availability; it does
not add those realms to OIDC. An attached but unselected realm can log in to the
portal without receiving an OIDC session or a silent authorization code.
Switching realms in one browser must revoke the preceding OIDC session, including
when the new realm is unselected. Assert this by replaying the saved session
cookie, not just checking that the browser received a deletion cookie. Verify
realm-specific UserInfo and stable, distinct subjects for users with the same
username in different realms.

Use a separate portal for each provider. `oidc_config.go` rejects identical or
nested issuer mounts on the same hostname, during both adaptation and runtime
restoration. Cookie scope ignores ports and equivalent host spellings: DNS
trailing dots, Unicode/punycode names, and IPv6 compression do not bypass this
check. This comparison leaves the configured issuer unchanged. Use standard
dotted-decimal IPv4 addresses; shortened, octal, and hexadecimal forms are
rejected because browsers and Go clients interpret them differently.
Disjoint paths such as `/auth` and `/other`, or distinct hostnames, provide
separate provider scopes. Match the Caddy `authenticate` routes to the issuer
mounts. Use separate portal cookie prefixes and paths when sharing a host:

```caddyfile
# Inside the first portal, serving /auth/*:
cookie prefix FIRST
cookie path /auth
oidc provider {
    issuer https://login.example.com/auth
    realms employees contractors
    signing key files "/var/lib/caddy/security-private/first key.pem"
    applications website
}

# Inside a second portal, serving /other/*:
cookie prefix SECOND
cookie path /other
oidc provider {
    issuer https://login.example.com/other
    realms employees
    signing key files /var/lib/caddy/security-private/second.pem
    applications second_website
}
```

Each referenced realm/store and application must also be declared and attached
in its proper scope. OIDC cookies are host-only, Secure, HttpOnly, SameSite=Lax,
and scoped to the issuer mount. Portal-owned reserved paths such as `/api`,
`/sandbox`, and `/oauth2` cannot be issuer mounts. Noncanonical URLs, query
strings, fragments, credentials, encoded paths, and trailing slashes fail.
Explicit ports must be nonempty decimal values within 0–65535.
Enabled issuers must already use the origin spelling browsers send: ASCII
punycode for internationalized DNS names, compressed hexadecimal IPv6,
standard IPv4 without a trailing dot, and ports without leading zeroes.
Omit the default HTTPS port `443`. A single DNS trailing dot is allowed;
empty or overlong DNS labels are rejected. AuthCrunch compares origins exactly,
so accepting spellings that browsers rewrite can replace a working provider
with one that rejects its own discovery and login requests. Reject these
configurations before construction; never silently rewrite an issuer.

If refresh is enabled through native JSON `refresh_tokens`, its canonical HTTPS
`public_origin` and `base_path` must agree with the OIDC issuer origin and mount.
There is no refresh Caddyfile block in this wrapper yet; do not invent one.

## Keys and saved JSON

The parser never generates client credentials or signing keys and does not read
key files. Runtime construction checks and loads existing keys. The first key
signs and all listed public keys appear in JWKS. Keys must be dedicated to OIDC,
not reused for portal access-token signing. Missing or invalid key material
fails candidate provisioning, leaving the active deployment usable.

Host key checks require clean absolute paths, private `0700` directories and
current-user-owned `0600` files, without symlinks or traversal. See
[private provisioning](private-provisioning.md#storage-and-command-contract)
for ancestor permissions and the optional explicit provisioning commands.
These checks apply even without an OAuth registration store. Use Caddyfile
`{$VARIABLE}` substitution or literal paths; the provider body does not expand
runtime `{env.*}` or `secrets:*` references.

Adapted JSON retains `apps.security.oidc_provider_directives`, keyed by portal
name, and omits copied provider client snapshots. During `App.Provision`,
`resolveOAuthRegistrationConfig` loads all stored applications and reattaches
the providers to a private config copy before root/runtime validation. Native
JSON may instead supply `authentication_portals[].oidc_provider`; do not supply
both forms for the same portal. Explicit client credentials remain sensitive
JSON. Disabled and absent states survive both restoration paths. Provider
sessions and grants are process-local and do not survive successful replacement.

## Validation surfaces

- `caddyfile_authn_oidc_test.go`: all settings/defaults, quoted paths, malformed
  syntax, duplicates, forward references, imports, disabled references, JSON
  restoration, and adaptation with a failing randomness source.
- `testcase_authenticate_with_oidc_provider.Caddyfile` and `.json`, registered
  in `TestCaddyfileAdaptAuthenticationToJSON`: complete adapter fixture with two
  providers, selected/unselected realms, all settings, zero defaults, disabled,
  and absent providers. Key paths are synthetic; adaptation performs no key I/O.
- `testcase_authenticate_with_oidc_unterminated.Caddyfile` and `.json`: a
  negative adapter fixture for quoted braces concealing a missing portal close.
- `testcase_authenticate_with_oidc_noncanonical_issuer.Caddyfile` and `.json`:
  a negative adapter fixture for a port that browsers rewrite.
- `oidc_config_test.go`: issuer route and cookie-path conflicts, including
  different ports, hostname aliases, canonical origins, DNS label validity,
  root mounts, and declaration order.
- `TestCaddyOIDCProviderE2E`: real TLS Caddy provisioning and discovery, two
  participating local realms plus an unselected realm, signed token exchanges,
  realm-specific identities, switching realms in one browser with replay of
  revoked sessions, two independent issuers, native JSON, disabled/absent
  endpoints, refresh alignment, and rejection of invalid replacements while
  existing sessions work.
  Rejection cases assert the expected error, so a duplicate block cannot mask
  the malformed setting a test intends to exercise.

The older `TestResolveRuntimeAppConfig` extracts only `security.config`; it does
not restore host-owned provider statements. Use the full App/Caddy coverage
above when changing this integration.
