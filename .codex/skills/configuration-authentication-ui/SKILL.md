---
name: configuration-authentication-ui
description: "caddy-security authentication portal UI Caddyfile configuration. Use when creating, reviewing, or modifying authentication portal ui blocks, templates, metadata, private links, static assets, themes, languages, logos, auto_redirect_url, custom CSS, custom JavaScript, or custom HTML header injection."
---

# Configuration Authentication UI

## Published UI contract

The v1.3.3 embedded portal and OIDC pages supply their themed layouts and
browser color preference behavior automatically. `theme basic` remains the
only registered Caddy theme; do not invent `theme dark` or `theme light`.
Profile assets include `profile/images/banner.svg`, `favicon.svg` and
`logo.svg`. Custom static PNG assets remain supported. Avoid pinning internal
hashed assets when customizing templates; inspect the selected embedded UI.
Conditional flow selection and profile policy editing need no extra UI setting;
see [authentication flows](../authentication-portal-api/references/authentication-flows.md).

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

Use `configuration-authentication` for the surrounding portal and
`configuration-authentication-user-transforms` for `ui link` entries emitted by
user transforms.

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
in the parser path.

Do not invent UI directives from authcrunch struct fields unless
`caddyfile_authn_ui.go` parses them. The Caddyfile parser does not currently
support a top-level `ui title` or `allow settings for role` subdirective.

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

Use `language <id>` inside the `ui` block for portal localization:

```caddyfile
ui {
	language fr
}
```

The supported language set and message keys come from local go-authcrunch
translation data, especially `pkg/translate/data/messages.json`. Check that
file when validating whether a language or message is available; do not infer
support from screenshots alone.

## Client Integration Patterns

Custom JavaScript can implement post-login behavior that `auto_redirect_url`
cannot express, such as calling `/whoami`, checking the referrer from a
`/sandbox/` path, inspecting roles, and redirecting users to a role-specific
dashboard. Treat such scripts as application code: review same-origin
assumptions, JSON `Accept` headers, role checks, and failure behavior.

## Fixtures

Use this fixture as the main example:

- `testdata/caddyfile_adapt/testcase_authenticate_with_ui.Caddyfile`
