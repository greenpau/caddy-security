# Typed custom ACL fields

## Caddyfile and JSON

Inside `security { authorization policy <name> { ... } }`, bind a policy-local
alias to an exact top-level authenticated claim key:

```caddyfile
acl field external_roles {
	claim "https://example.org/roles"
	type string list
}
acl field department {
	claim "https://example.org/department"
	type string
}
acl rule {
	match external_roles admin
	match department engineering
	allow stop
}
acl default deny
```

This is a policy fragment; configure verification/login separately and keep
`authorize with <policy>` before the protected handler. Both attributes must
match in this single rule. Separate allow rules express alternatives. The
explicit `allow stop` preserves the successful decision before later rules.
See the default-action limitation below before relying on a later default deny.

Only `acl field` is new syntax. A declaration requires exactly one name and one
flat block. The body requires one `claim <key>` and one `type string` or
`type string list`, in either order. There are no defaults. Reject duplicate
settings, extra arguments, empty tokens, unsupported types (`string_list` is
not Caddyfile spelling), nested blocks and missing/malformed braces.

Names are case-sensitive ASCII identifiers of 1–128 characters: initial letter
or underscore, followed by letters/digits/underscores/hyphens. Standard fields,
their aliases, temporal/path internals and conflicting ACL keywords are reserved;
let the library validate the list. Standard undeclared fields such as `roles`,
`role`, `method` and `path` keep their existing meaning. Undeclared custom
value-match names fail policy compilation before a listener accepts traffic.

Claim keys are literal: dots, slashes, colons, pipes, commas and spaces neither
traverse objects nor fetch URLs. Quote keys containing spaces. Caddy runtime
`{env.*}` and `secrets:*` text stays literal; no new runtime replacement path is
provided. Caddy's existing lexical `{$ENV}` expansion still belongs to Caddy.
Its import arguments also expand before adaptation. Imported declarations retain
their complete literal binding and remain local to the importing policy;
repeated imports do not bypass duplicate-name validation.
Claim keys cannot contain control characters or surrounding whitespace.
Existing standard claims may already have been normalized by `User`; namespaced
custom claim values retain their original types.

Native JSON uses the library's typed `access_list_fields` collection on each
policy, alongside `access_list_rules`:

```json
{
  "access_list_fields": [
    {"name": "external_roles", "claim": "https://example.org/roles", "type": "string_list"},
    {"name": "department", "claim": "https://example.org/department", "type": "string"}
  ]
}
```

This is a policy JSON fragment, not a complete Caddy document. Null fields and
null rules are rejected during app structural validation; field semantics remain
upstream-owned. JSON reload constructs new definitions, including changed claim
bindings; aliases never enter a shared registry. A rejected candidate preserves
the serving app.

## Adapter ownership

`caddyfile_authz_acl.go` uses Caddy's flat-block traversal, checks tokens before
encoding, encodes complete statements with `cfgutil.EncodeArgs`, and delegates
to `acl/parser.NewACLFieldConfigFromDirectives`. Lossy codec round trips are
rejected, so trailing Unicode whitespace cannot become a valid key or keyword.
Errors add policy/source context without echoing field values or body text.
An extra block is rejected at its opening brace. Caddy can reject malformed
structural syntax before invoking the policy parser, with its own source
diagnostic. Policy compilation errors also carry a Caddyfile source location;
the existing rule compiler owns their diagnostic text. Preserve the underlying
error identity when adding that location with Caddy's error wrapper.
Check the enclosing policy's opening and closing braces too: the dispenser can
treat a quoted brace token as structural, so field-block checks alone do not
establish a well-formed policy. Reject incomplete/quoted boundaries before
publishing either the policy or deferred settings.

`caddyfile_authz.go` collects every parsed field and calls
`PolicyConfig.ConfigureAccessListFields` once, before `AddAuthorizationPolicy`
compiles rules. Rules can precede declarations. This prevents last-value-wins
behavior and leaves previous policies unchanged on failure. The library snapshots
validated definitions and preserves rules and unrelated settings.
Publish deferred OAuth statements only after the policy passes validation as
well: a rejected ACL must not leave an orphaned per-policy entry or prevent retry.

`app_config.go` owns the typed collection null check. Keep the existing app/root
server and gatekeeper path. Do not add claim projection, token rewriting, new ACL
constructors or `AllowWithClaims` calls to Caddy request handlers. The released
v1.3.10 module contains these APIs; inspect the selected module and replacement
before using a newer sibling contract. Sibling sources remain read-only.

## Runtime semantics and trust

- Scalars must be strings; empty strings are valid. Lists must contain only
  strings. Null, scalar/list mismatches, mixed lists, objects and booleans reject
  the entire ACL evaluation before any rule, including an early stopping allow.
- Missing claims do not match ordinary positive or negative comparisons.
  Explicit `field <alias> not exists` retains absence semantics. Empty nonnil
  lists exist but never match a value comparison, including negation.
- Only referenced definitions project/validate their source claims. An unused
  malformed custom claim cannot invalidate unrelated standard-role policies.
- Request method/path and source-address/path-claim restrictions still apply to
  fresh and cached credentials. Token `method`/`path` claims cannot replace the
  current request. Signature, expiry and existing trust requirements still apply.
- Aliases are not canonical roles. They do not rewrite the JWT, normalized user
  data or injected role headers. Binding an authenticated but user-editable
  attribute does not make it a trusted privilege source.

## Default-action limitation in v1.3.10

The shortcut adapter retains `allow log debug` and `deny stop log warn`, with
existing rule order. Its intended contract is that a later `acl default deny`
overrides a non-stopping allow. Actual signed-token Caddy E2E exposes an upstream
limitation: `match any` compiles against `exp`, but `User.GetData()` omits temporal
claims. The generated rule checks field presence before evaluating the always-match
condition. Consequently default rules are skipped: a compact allow followed by
`acl default deny` grants access, and `acl default allow` alone cannot grant it.
This also affects standard fields; it is not fixed by declaring custom fields.

The required ordering regression stays failing in the default suite until the
library corrects unconditional evaluation independently of timestamp presence.
Do not change its expected denial to a success, skip it, insert fictitious
claims, or rewrite shortcut/default actions in the adapter to hide this failure.
That runtime correction is separate upstream work. Explicit positive rules with
`allow stop` and implicit denial for unmatched requests remain qualified by the
Caddy journey. Do not advertise the whole handoff as passing while ordering fails.

## Validation surfaces

`TestAuthorizationACLFields`, `TestAuthorizationACLFieldRejects`, and
`TestAuthorizationACLFieldLiteralResolution` cover typed mapping, quoted keys,
policy isolation, declaration ordering, shortcut preservation, redaction,
malformed input and atomic failure, including deferred OAuth settings.
`TestAuthorizationACLFieldNames` exercises valid identifier boundaries through
rule compilation. `TestAuthorizationACLFieldPolicyBoundaries` rejects quoted
policy braces through both direct parsing and public adaptation;
`TestAuthorizationACLFieldImports` checks literal import arguments, duplicate
declarations and unavailable aliases in another policy. The `testcase_authorize_acl_fields`,
`testcase_authorize_acl_fields_duplicate` and
`testcase_authorize_acl_fields_blocks` fixture pairs cover public adaptation;
`testcase_authorize_acl_fields_policy_brace` covers the enclosing policy boundary.
The app lifecycle malformed-JSON matrix includes null fields and rules.

`TestCaddyAuthorizationFieldsE2E` runs the actual public adapter, Caddy app,
verified TLS and a counted reverse-proxy upstream in the default Go suite.
Count upstream calls separately for each request, including concurrent traffic:
every denied request must have zero calls and every allowed request exactly one.
A suite-wide total can conceal an unexpected grant paired with an unexpected denial.
Independent HS512 signing preserves malformed JSON types. The journey includes
all eight guardian combinations, observed cache misses/hits, standard-role and
subject headers, malformed deny inputs, concurrent policy isolation and
invalid/expired signatures. Caddyfile `validate path acl` also enables method/path
validation, so two path-claim-only combinations require native JSON with
`validate_method_path` false. Assert the adapted and provisioned option tuples;
eight policy names alone do not prove eight distinct guardians ran.
The same cached token is checked against different
current trusted client addresses as well as methods/paths. Caddyfile errors and
native JSON errors reject startup/reload; changed/restored JSON bindings take
effect in the serving runtime. Imported declarations also authorize real TLS
requests and reject a token whose only value is under the alias rather than its source.
Its default-rule ordering failures expose the limitation above; sibling test
success cannot substitute for this Caddy evidence.
