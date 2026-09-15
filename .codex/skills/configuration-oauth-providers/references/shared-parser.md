# Shared Upstream OAuth Parser

## Ownership

`caddyfile_identity_provider_oauth.go` collects the complete Caddy provider body,
encodes statements with `cfgutil.EncodeArgs`, calls
`pkg/idp/parser.NewOAuthIdentityProviderConfigFromDirectives(name, statements)`,
and registers the result with
`Config.AddIdentityProvider(result.Name, result.Kind, result.Params)`.
The selected go-authcrunch v1.2.3 dependency provides this API. The sibling
checkout is a read-only reference; no local replacement is needed for this API.

The shared adapter reuses `pkg/idp/oauth/parser` and retains the identity-provider
dispatcher's allowlist. `pkg/oidc` configures downstream providers and does not
own these settings. Parsing applies typed driver defaults and semantic
validation but does not instantiate providers, start workers, bind sockets, or
fetch metadata/JWKS. Static PEM validation can read local files when explicit
endpoints and keys are supplied. Runtime provisioning owns network discovery.

## Caddy Grammar Inventory and Translation

This table inventories the former combined Caddy parser and its compatibility
mapping. Shared scalar/list keys also accept separate words, for example
`client id` and `access token audience`.

| Existing Caddy grammar | Shared grammar / handling |
| --- | --- |
| `realm`, `driver`, `tenant_id`, `domain_name`, `client_id`, `client_secret`, `server_id`, `base_auth_url`, `metadata_url`, `identity_token_field_name`, `authorization_url`, `token_url`, `region`, `user_pool_id`, `user_info_roles_field_name` | Forward one exact value. |
| `logout_url <logout_url>` (also `logout url <logout_url>`) | Recognized by `pkg/idp/oauth/parser/fields.go`, but rejected by the OAuth allowlist in `pkg/idp/config.go` in v1.2.3. Forward it unchanged to that validation. Never remove it from Params to make registration succeed. |
| `scopes`, `user_group_filters`, `user_org_filters`, `response_type` | Preserve the old append behavior for repeated identical legacy spellings, combining them into one list statement. Mixing a spaced alias with the old spelling fails as a duplicate. |
| `required_token_fields <fields...>` | Forward one nonempty list. Repetition fails instead of silently replacing the previous list. |
| `delay_start`, `retry_attempts`, `retry_interval` | Forward one integer. Library validation retains driver/retry defaults and exact integer values. |
| `disable metadata discovery`, `key verification`, `pass grant type`, `scope`, `nonce`, `pkce`, `email claim check`, `tls verification` | Translate to the corresponding separate-word setting plus `disabled`. Underscores in these legacy keywords remain supported. |
| `disable response type` | `response type parameter disabled`. This state is distinct from the `response_type` list. |
| `enable accept header`, `enable js callback`, `enable logout` | Translate the corresponding setting plus `enabled`; legacy underscore spellings remain supported. |
| `enable id token cookie [field [name]]` | `identity token cookie enabled`, optionally `identity_token_field_name` and `identity_token_cookie_name`. The field must be `id_token` or `access_token`. |
| `extract <fields...> from userinfo` | `user_info_fields <fields...>`. `all` remains supported. |
| `icon <label> [class [color [background]]] [text <color> [background]] [priority <number>]` | Translate each positional field into its own `login icon <attribute> <value>` statement, including priority zero. Preserve repeated modifiers for shared duplicate detection; reject missing and surplus arguments. |
| `jwks key <kid> <public-PEM-path>` | Forward every record. Distinct IDs may repeat; duplicate IDs fail. Quote paths containing spaces. |
| `oauth identity provider github/google/facebook <client-id> <secret>` | Emit realm, driver, client ID, and secret statements, then use the same shared parser as blocks. |
| `disabled` | An empty disabled block registers an omission marker without requiring credentials. A populated disabled definition passes shared validation before omission. Extra arguments and repeated markers fail. |

New direct fields include `issuer`, `access_token_audience`,
`identity_token_cookie_name`, and `user_info_fields`. New direct state syntax
uses separate keywords followed by `enabled` or `disabled`, including
`identity token cookie enabled` and `response type parameter disabled`.
`login icon` supports class name, color, background color, text, text color,
text background color, and priority. Attribute snake_case aliases also work.

The full block is parsed once. Scalar aliases, conflicting states, cookie
arguments versus explicit fields, icon attributes, and key IDs share duplicate
tracking. The four historical append lists above are the deliberate exception.
Legacy icon `text` and `priority` modifiers may appear in either order and can
be used without positional label/class fields. Each modifier needs a value;
repeated `text` or `priority` modifiers must not be collapsed before shared
validation. The generic legacy icon parser silently overwrites or drops some
arguments, so the OAuth adapter translates these fields directly.
Earlier scalar/list replacement behavior is rejected when it would hide a
second configuration of the same setting. Malformed grouped keywords, empty or
multiline tokens, and nested blocks fail before registration. Quoted values keep
their spaces, commas, and trailing Unicode whitespace; errors do not echo
supplied secrets or PEM paths. The adapter checks the shared argument codec's
round trip and explicitly quotes CSV fields if it would trim a value (notably a
final tab, NBSP, or EM SPACE). Do not replace this with unchecked `EncodeArgs` or
trim individual values: issuer/audience comparisons and credentials are exact.

The former parser's `strings.HasPrefix` cookie matching also accidentally
accepted malformed `id_token`/`cookie_suffix` token combinations. Those are not
compatible cookie forms; use the documented spaced form or the shared state
syntax. SAML-only fields remain unsupported for OAuth.

## Runtime References

Literal input and unresolved input both pass the complete shared parser during
adaptation. For a provider containing runtime references, the app also retains
its translated statements in `oauth_provider_directives`, keyed by provider
name. During provisioning, resolve each original argument once and reparse the
complete block through the same shared dispatcher before using its Params.
The snapshot replaces that provider's adapted parameters; JSON configurations
without a snapshot retain ordinary parameter-map replacement.

Do not resolve a normalized parameter map when its original statements exist.
Driver defaults can alter an unresolved lookup: Google appends its client-ID
suffix to `secrets:oauth:client`, and Nextcloud derives endpoint URLs from a
secret-backed base URL. Resolving those derived strings asks for different
secret keys. Recomputing defaults after replacement preserves driver behavior
without rewriting the reference or expanding substituted values twice.

Snapshots must match exactly one OAuth provider with a valid shared parameter
map; a snapshot cannot hide unsupported fields in that map. Missing/duplicate targets,
malformed records, empty or multiline replacements, duplicate aliases, and
unsupported typed-only fields fail before provider startup. Existing shared
validation still runs during adaptation; retaining a snapshot does not make
previously invalid unresolved driver names or static PEM paths parseable.
Keep the snapshot with `apps.security.config` when moving adapted Caddy JSON.
See [runtime resolution](../../configuration-runtime-resolution/SKILL.md).

## Issuer and Audience Trust

```caddyfile
oauth identity provider corporate {
 realm corporate
 driver generic
 client_id {env.CORPORATE_CLIENT_ID}
 client_secret {env.CORPORATE_CLIENT_SECRET}
 base_auth_url https://login.example/authorization-base
 metadata_url https://login.example/.well-known/openid-configuration
 issuer https://Issuer.example/Exact/
 access token audience resource-api
}
```

An explicit issuer is exact and authoritative, including case and trailing slash.
Otherwise the discovered issuer is used. `base_auth_url` does not imply issuer.
Without either explicit or discovered issuer, the library retains its existing
optional issuer checking.

The access-token audience applies only to a supplemental JWT access token.
Identity tokens, including an access token selected as the identity token, use
the client ID. Without explicit access audience, the existing access-token `azp`
fallback remains. Explicit audience mismatch cannot use that fallback.

An invalid identity token rejects login. An invalid optional access JWT adds no
claims; a valid identity token can still produce a portal session. In particular,
resource roles from an invalid access token must not appear in the portal token
or authorize protected resources. Opaque access tokens and UserInfo retain their
existing behavior.

Static `jwks key` entries accept Ed25519 SPKI, RSA SPKI, and RSA PKCS#1 public PEM.
EC retains its existing JWKS discovery support; the upstream static PEM loader
does not accept EC. Static IDs take precedence over colliding discovery keys.
A remote same-ID key rollover can refresh on signature failure; a static pin
failure cannot fall back to a remote replacement. Invalid or unknown JWKS
siblings do not discard valid supported keys.

Use normal TLS, nonce, PKCE, and signature checks for discovery, static, and
combined sources. Static mode uses explicit authorization and token URLs plus
public keys; it does not need `disable key verification` or TLS bypasses.

## Validation

- `TestOAuthSharedParserFields`, `TestOAuthLegacyTranslations`, and adjacent tests
  in `caddyfile_identity_provider_oauth_test.go` cover the grammar, defaults,
  duplicate/argument errors, public PEM validation, and no discovery while parsing.
- `testcase_authenticate_with_oauth_parser` covers Caddy adaptation and runtime
  replacement of issuer/audience, credentials, lists, keys, retry settings, and
  icon/cookie translation. `testcase_authenticate_with_oauth_icon_malformed`
  rejects repeated legacy text-color modifiers.
  `testcase_authenticate_with_oauth_quoted_values` covers literal trailing
  whitespace through adaptation and runtime resolution.
  `testcase_authenticate_with_oauth` retains Discord defaults and its configured
  authorization URL. `FuzzOAuthDirectiveEncoding` checks lossless argument
  encoding for arbitrary validated tokens.
- `TestOAuthRuntimeDriverDefaults`, `TestOAuthRuntimeSnapshotValidation`, and
  `TestOAuthRuntimeExactValues` cover original secret keys, derived endpoints,
  snapshot ownership, whole-block validation, and one-time replacement. The
  parser fixture includes a Google client ID resolved from the environment.
- `TestCaddyOAuthE2E` in `oauth_e2e_test.go` runs real TLS Caddy routes against an
  independently signed local upstream, with code/state/nonce/PKCE checks. It
  tests identity versus supplemental access trust, discovery/static/combined
  keys, both Ed25519 labels, RSA/EC compatibility, mixed JWKS, same-ID rollover,
  static pin precedence for identity and supplemental tokens, protected resource
  roles, rendered legacy login icons, exact quoted secrets/issuer/audience,
  rejected duplicate icon reconfiguration, and trust changes on reload.
  A Google journey uses a secret-backed client ID, secret, issuer, and audience;
  rejected runtime secret/snapshot reloads must preserve the active login flow. Negative
  journeys assert exact redirect/forbidden status codes. Missing `kid` preserves
  candidate-key verification; explicitly unknown IDs still fail.

The E2E subprocess installs a synthetic root pool through the crypto/x509
system-root hook retained for rootcerts (Go issue 67401). Caddy initializes its
fallback roots before tests, so `SetFallbackRoots` cannot be called a second
time. The hook is confined to the test child, initialized before any test TLS
clients, and never changes the OS trust store or skips certificate verification.
The repository pins Go 1.26; check this hook when upgrading the toolchain.

Run the focused suite, then the repository's race/report workflow:

```sh
go test -mod=readonly -run 'TestOAuth|TestParseCaddyfileIdentity|TestCaddyOAuthE2E|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig' .
make test
```
