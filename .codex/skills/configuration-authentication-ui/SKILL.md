---
name: configuration-authentication-ui
description: "caddy-security authentication portal UI Caddyfile configuration. Use when creating, reviewing, or modifying authentication portal ui blocks, templates, metadata, private links, static assets, themes, languages, logos, auto_redirect_url, custom CSS, custom JavaScript, or custom HTML header injection."
---

# Configuration Authentication UI

## Purpose

Use this skill for `ui` blocks inside `authentication portal <name>` blocks.

Read these files when details matter:

- `caddyfile_authn_ui.go` for accepted Caddyfile UI syntax.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/ui/params.go` for
  authcrunch UI parameters.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/portal.go` for UI
  defaults, template loading, static assets, theme and language validation.
- `~/dev/src/github.com/greenpau/go-authcrunch/pkg/authn/ui/static.go` for
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
		static_asset "assets/images/logo.png" "images/png" ui/logo.png
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
static_asset "assets/images/banner.jpg" "images/jpg" ui/banner.jpg
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

## Fixtures

Use this fixture as the main example:

- `testdata/caddyfile_adapt/testcase_authenticate_with_ui.Caddyfile`
