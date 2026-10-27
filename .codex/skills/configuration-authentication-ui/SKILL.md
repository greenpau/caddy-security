---
name: configuration-authentication-ui
description: "Configure portal UI templates, static assets, themes, languages, links, and custom CSS/JS/HTML. Use for branding and refresh-aware templates; transform-generated links belong to user transforms."
---

# Configuration Authentication UI

## Published UI contract

The selected embedded portal and OIDC pages supply their themed layouts and
browser color preference behavior automatically. `theme basic` remains the
only registered Caddy theme; do not invent `theme dark` or `theme light`.
Profile assets include `profile/favicon.svg` and `profile/logo.svg`.
Custom static PNG assets remain supported. Avoid pinning internal
hashed assets when customizing templates; inspect the selected embedded UI.
Conditional flow selection and profile policy editing need no extra UI setting;
see [authentication flows](../authentication-portal-api/references/authentication-flows.md).

The embedded apps use `<mount>/profile/` (User Profile), `<mount>/operator/`
(Security Manager) and `<mount>/documents/` (File Vault). The profile shell is
always available; its APIs retain their independent enablement. Security Manager
requires the admin API and an administrator role. File Vault requires an enabled,
initialized Documents API and an administrator or user role; the same roles
permit profile access. The portal adds links for enabled apps the user may access.
Only each enabled app's exact `manifest.json` is public; other assets require
authorization. Keep the full portal mount when routing these apps: the library
supplies the HTML base path and embedded assets without separate Caddy handlers.

## Purpose

Use this skill for `ui` blocks inside `authentication portal <name>` blocks.

Read these files when details matter:

- `caddyfile_authn_ui.go` for accepted Caddyfile UI syntax.
- `../go-authcrunch/pkg/authn/ui/params.go` for
  authcrunch UI parameters.
- `../go-authcrunch/pkg/authn/portal.go` for UI
  defaults, template loading, static assets, theme and language validation.
- `../go-authcrunch/pkg/authn/ui/static.go` for
  static asset loading and content-type handling.

The surrounding portal belongs to
[configuration-authentication](../configuration-authentication/SKILL.md).
Transform-generated `ui link` entries belong to
[configuration-authentication-user-transforms](../configuration-authentication-user-transforms/SKILL.md);
they are separate from static links in this UI block.

## Supported UI Forms

The Caddyfile `ui` parser supports templates, metadata, private links, static
assets, themes, languages, logos, `auto_redirect_url`, and custom CSS,
JavaScript, or HTML-header injection. Use parser-supported forms:

```caddyfile
authentication portal myportal {
	ui {
		theme basic
		language en
		meta title "Example Authentication Portal"
		meta author "Example"
		meta description "Example sign-in portal"
		template login ui/login.template
		static_asset "assets/images/logo.png" "image/png" ui/logo.png
		logo url "/auth/assets/images/logo.png"
		logo description "Example"
		auto_redirect_url /auth/portal
		links {
			"My Identity" "/auth/whoami" icon "las la-user"
			"Docs" "https://docs.example.com/" target_blank
		}
	}
}
```

`links` entries use a title as the subdirective token and require a target URL.
Optional keys are `target_blank`, `icon <class>`, and `disabled`.

## Custom Assets

`static_asset` URIs must start with `assets/`; the content type is passed
through as provided, and authcrunch loads the file from the filesystem path:

```caddyfile
static_asset "assets/images/banner.jpg" "image/jpeg" ui/banner.jpg
```

Custom CSS and JavaScript are registered at fixed asset paths:

```caddyfile
custom css path ui/custom.css
custom js path ui/custom.js
```

These become `assets/css/custom.css` and `assets/js/custom.js`. `custom html
header path <path>` injects file content into the built-in templates immediately
in the parser path. That injection mutates process-global template data; custom
CSS/JS and static assets also use a global asset registry. Do not promise
independent branding for portals registering the same asset paths or repeatable
header injection across adaptations. Qualify coexistence and reload behavior
before relying on that isolation; adaptation success alone does not prove it.

Do not invent UI directives from authcrunch struct fields unless
`caddyfile_authn_ui.go` parses them. The Caddyfile parser does not currently
support a top-level `ui title` or `allow settings for role` subdirective.

## Cross-device Custom Templates

The selected embedded login template shows the cross-device action only when
the portal enables it. Keep that action outside the ordinary provider-link
visibility condition: a single local realm can hide ordinary links while still
offering cross-device login. Preserve the dedicated request/confirmation pages
and their embedded script instead of copying runtime assets into Caddy. Use
[configuration-authentication-cross-device](../configuration-authentication-cross-device/SKILL.md)
to check explicit approval, matching-code/account display, navigation,
cancellation and embedded-browser compatibility when customizing those pages.
Read [cross-device presentation](references/cross-device.md) for template hooks,
clipboard feedback, keyboard focus, responsive layout and Caddy browser evidence.

## Refresh-Aware Custom Templates

The built-in portal and session templates already load the matching embedded
client. Custom portal templates must retain its conditional inclusion:

```gotemplate
{{ if .Data.refresh_enabled }}
<script src="{{ pathjoin .ActionEndpoint "/assets/js/refresh.js" }}"
        data-base="{{ .ActionEndpoint }}"
        data-session="{{ .Data.refresh_session }}"
        data-expires="{{ .Data.refresh_expires }}"></script>
{{ end }}
```

Custom session continuation/confirmation templates use the action metadata:

```gotemplate
<p id="session-message">{{ .Message }}</p>
{{ if eq .Data.session_action "logout" }}
<button id="session-logout" type="button">Sign out</button>
{{ end }}
<a href="{{ pathjoin .ActionEndpoint "/login" }}?fresh=1">Sign in</a>
<script src="{{ pathjoin .ActionEndpoint "/assets/js/refresh.js" }}"
        data-base="{{ .ActionEndpoint }}"
        data-action="{{ .Data.session_action }}"
        data-next="{{ .Data.session_next }}"></script>
```

These are fragments inside the corresponding HTML template, not Caddyfile
syntax. Keep the served `refresh.js` name stable and use the library's
`AuthCrunchSession.refresh()`/`.logout()` for custom controls. Do not substitute
an independent client, inline credentials or mark untrusted return URLs safe.
Session/expiry attributes are hints; the coordinator verifies signed access
state before using them. Preserve the continuation page's CSP and no-store
headers and offer fresh login when browser coordination is unavailable.
See [browser refresh](../authentication-portal-api/references/browser-refresh.md)
for Web Locks, pending-state recovery, top-level navigation and Caddy TLS tests.

## Languages

Use one `language <code-or-English-name>` value per line in the `ui` block:

```caddyfile
ui {
	language fr
}
```

Omission or an exact empty value selects English. Codes and English language
names are trimmed and case-insensitive at portal construction; adaptation
preserves the literal value. Repeated declarations on separate lines use the
last value. Extra arguments are rejected. Unsupported values fail construction;
there is no request-specific `Accept-Language` negotiation or runtime placeholder
resolution for this field.

Read [localization](references/localization.md) for the supported languages,
portal/OP propagation, escaped template and script messages, RTL behavior,
custom-template limits and Caddy acceptance. Check the selected module's
`pkg/translate/language.go` and `data/messages.json` when changing that contract.

## Client Integration Patterns

Custom JavaScript can implement post-login behavior that `auto_redirect_url`
cannot express, such as calling `/whoami`, checking the referrer from a
`/sandbox/` path, inspecting roles, and redirecting users to a role-specific
dashboard. Treat such scripts as application code: review same-origin
assumptions, JSON `Accept` headers, role checks, and failure behavior.

## Fixtures

Use this fixture as the main example:

- `testdata/caddyfile_adapt/testcase_authenticate_with_ui.Caddyfile`

## Acceptance and qualification limits

The UI fixture proves parser/adapted JSON behavior. It does not qualify custom
CSS/JS/HTML execution, missing-file failures, or simultaneous portal branding;
this repository has no dedicated Caddy E2E coverage for those customizations.
When changing them, verify served paths/content types, intended page inclusion,
missing-input failure, and behavior across two portals and reload. Keep global
asset/template effects visible rather than asserting per-portal isolation.

For custom refresh templates, preserve the embedded client's conditional script
and metadata plus fresh-login recovery. Existing browser-refresh journeys cover
the built-in templates; a custom template needs its own actual browser evidence.
