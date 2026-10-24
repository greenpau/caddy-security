# Portal and OIDC localization

## Configuration and validation

Set `ui { language <value> }` inside an authentication portal. Supply exactly
one value on the directive's line. Repeated declarations on separate lines use
the last value. Native JSON uses the portal's `ui.language` string. Both paths
reach the selected AuthCrunch portal factory; Caddy does not translate strings
or maintain another catalog.

| Code | Accepted English name | Reading direction |
| --- | --- | --- |
| `en` | English | LTR |
| `de` | German | LTR |
| `fr` | French | LTR |
| `ja` | Japanese | LTR |
| `zh` | Chinese | LTR |
| `he` | Hebrew | RTL |
| `ar` | Arabic | RTL |
| `ru` | Russian | LTR |

Code/name lookup trims surrounding whitespace and ignores case. Caddy preserves
the original spelling in adapted JSON. An omitted or exactly empty value uses
English; whitespace alone, regional tags such as `fr-FR`, localized language
names such as `français`, and unknown values fail portal construction. Syntax
adaptation alone does not establish support. Nonpersistent roots are constructed
during provisioning; persistent roots are constructed during Start.

The UI language is fixed per portal. Opposing `Accept-Language` headers do not
change it, and one portal's argument snapshot does not inherit another portal's
language. `ui.language` is not among the fields expanded by runtime secret or
replacer resolution. Caddy's lexical environment substitution is separate.

The portal passes its normalized language to its OIDC provider; there is no
second OP language directive. Default login labels, metadata, logo descriptions,
consent and browser error pages use the catalog. Explicit operator branding,
client/account names, provider copy and policy hints retain their existing
owners and must not be treated as translation keys.

## Custom templates and scripts

The embedded Go templates use these methods:

- `.LanguageCode` returns the normalized language for the document's `lang`.
- `.Direction` returns `rtl` for Arabic/Hebrew and `ltr` otherwise.
- `.Translate "message_id"` returns plain text; an optional argument supplies
  the catalog's `Value` placeholder.
- `.Messages "message_id" ...` returns a JSON string for an HTML data attribute.

Preserve `html/template` contextual escaping. Never cast translated or
interpolated data to trusted HTML/JavaScript. For example, a custom session
page can retain the selected message map on the existing embedded script:

```gotemplate
<html lang="{{ .LanguageCode }}" dir="{{ .Direction }}">
<!-- Keep the complete selected template's session controls and metadata. -->
<script src="{{ pathjoin .ActionEndpoint "/assets/js/refresh.js" }}"
        data-i18n="{{ .Messages "session_browser_unsupported" "session_incomplete" "session_interrupted" "session_logout_failed" "session_logout_unconfirmed" "session_sign_in_again" }}"
        data-base="{{ .ActionEndpoint }}"
        data-action="{{ .Data.session_action }}"
        data-next="{{ .Data.session_next }}"></script>
```

This is a Go template fragment, not Caddyfile syntax. Attribute escaping occurs
before the browser decodes the attribute and the script parses JSON. Embedded
clients place messages through `textContent` or text nodes, not `innerHTML`.
Retain the selected script's complete message set and operational metadata.
Older filesystem templates without message maps retain the scripts' English
fallbacks; they do not acquire translated client messages automatically.
Unknown catalog identifiers remain identifiers, not invented success messages.

Keep numeric/credential material such as MFA passcodes, matching codes,
activation URLs and displayed JSON explicitly LTR. Account/client display names
use `dir="auto"`. Test actual phone/desktop wrapping and list markers in RTL;
a document-level direction attribute alone does not establish usable layout.
Retain native control focus, labels and recovery actions. Use the
[cross-device presentation contract](cross-device.md) for those template hooks,
and [browser refresh](../../authentication-portal-api/references/browser-refresh.md)
for session coordination and uncertain-state recovery.

The separately built React profile application is outside Go-template
localization. Custom filesystem templates and provider-authored copy require
separate qualification. Language snapshots do not establish independent custom
asset registries; the UI skill's global custom-asset/header caveat still applies.

## OIDC protocol boundary

Translate visible consent, permission descriptions and browser error copy while
preserving action URLs, CSRF fields, machine values `allow`/`deny`, state, issuer,
authorization codes and tokens. Preserve HTTP status, content type, cache policy,
CSP and consent's `Referrer-Policy: same-origin`; the latter supports the actual
Origin on a native form POST. Do not rewrite Origin or synthesize a successful
callback to make a browser test pass.

An explicit HTML preference can select a localized browser error page. JSON
clients retain protocol error codes. Error pages are not consent and must not
gain credentials, forms or unvalidated return links. Form-post responses can
carry either success or a registered error; retain their nonce-bound script and
manual continuation. Use
[configuration-oauth-applications](../../configuration-oauth-applications/SKILL.md)
for provider/client wiring and consent protocol ownership.

## Required Caddy acceptance

`TestPortalUILanguage` and `TestPortalUILanguageArity` own the narrow parser
contract. The UI and invalid-language-arity adaptation fixtures join the public
adapter suite; the UI resolved fixture retains the literal language spelling.
`TestCaddyLocalizationE2E` assembles independent portals, actual TLS HTTP checks
and a trusted Chrome journey. Run them together with the existing provider
regression:

```sh
make test TEST='^(TestPortalUILanguage|TestPortalUILanguageArity|TestCaddyfileAdaptAuthenticationToJSON|TestResolveRuntimeAppConfig|TestCaddyLocalizationE2E|TestCaddyOIDCProviderE2E)$' TEST_DIR=.
```

Optional visual captures use `CADDY_SECURITY_LOCALIZATION_SCREENSHOT_DIR` and
the same private, fresh repository-local sink rules as the cross-device browser
suite. Captures supplement geometry and interaction assertions; they are not
required to run the suite. Keep them outside tracked source.

Exercise parser arity, raw spelling, omission, explicit empty and repeated
language declarations, plus adapted JSON. Use actual Caddy TLS to interleave
English, French and RTL portal requests with conflicting language headers and
literal branding. Reject unsupported replacement configuration and verify that
the old portal remains healthy. Check real wrong-password recovery and access.

In trusted Chrome, qualify French/RTL phone and desktop pages, native OP denial
and approval, escaped markup-shaped client names, and a translated client-side
message after an actual cross-device cancellation. Verify returned protocol
state/issuer and redeem the real authorization code. Keep isolated contexts,
normal certificate verification, actual Origin, private input/output and awaited
cleanup. Upstream catalog/all-template tests complement these host journeys;
they do not replace mounted Caddy evidence or qualify arbitrary custom themes.
