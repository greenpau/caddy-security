# caddy-security

<a href="https://github.com/greenpau/caddy-security/actions/workflows/build.yml" target="_blank"><img src="https://github.com/greenpau/caddy-security/actions/workflows/build.yml/badge.svg"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-security" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>

Security App with Authentication and Authorization Plugins
for [Caddy v2](https://github.com/caddyserver/caddy).

It includes:

* Authentication Plugin for implementing Form-Based, Basic, Local, LDAP, OpenID
  Connect, OAuth 2.0, SAML Authentication
* Authorization Plugin for HTTP request authorization based on JWT/PASETO tokens
* Credentials Plugin for managing credentials for various integrations

To retain sessions and generated signing keys across restarts, enable
[persistent runtime state](.codex/skills/configuration-state/references/operations.md).
It supports portals and direct OAuth policies without a portal. Persistent
deployments require a complete stop/start; overlapping reload is rejected.

Please show your **appreciation for this work** and :star: :star: :star:

Please consider **sponsoring this project** via Github Sponsors!

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau

Documentation for this project was previously hosted at
https://docs.authcrunch.com. As AI agents become part of the development
workflow, this repository is moving to skill-based documentation that helps both
humans and AI agents work with the codebase.

See [Runtime ownership and reload behavior](.codex/skills/coding-directives/references/runtime-lifecycle.md)
for request draining, failed replacement cleanup, and the restriction on
overlapping runtimes that use the same local identity file.

For standalone command-line portal login with named profiles, see
[`caddy-authenticator`](cmd/caddy-authenticator/README.md) for release downloads,
Go installation and usage. Its release archives support Linux, macOS and Windows
on amd64 and arm64.

Run `bin/authcrunch security version` to display the linked go-authcrunch version.
See [version diagnostics](.codex/skills/scripts-and-automation/SKILL.md#security-dependency-version)
for module replacement details.

Download Caddy with the plugins enabled:
* <a href="https://caddyserver.com/api/download?os=windows&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-security%40v1.2.2&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.13" target="_blank">windows/amd64</a>
* <a href="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-security%40v1.2.2&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.13" target="_blank">linux/amd64</a>

## Tests and Reports

Run `make dep` to download module dependencies and resolve the pinned `tested`
tool, then `make test` for race-enabled Go tests and coverage. Open
`.coverage/index.html` for the report dashboard. `make run-reports` rebuilds
reports from recorded evidence without rerunning tests.

`make ci-check` runs version checks, automation fixtures, the full Go suite,
and the Caddy binary build. GitHub Actions uploads the complete report bundle
with a versioned name, including failure evidence, and retains it for 14 days.
Release publication requires the same CI gate.

See [Testing and CI](.codex/skills/testing-and-ci/SKILL.md) for focused runs and
report files, and [Release and Versioning](.codex/skills/release-and-versioning/SKILL.md)
for artifact names and release procedures.
