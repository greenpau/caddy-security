---
name: break-fix-troubleshooting
description: "caddy-security break-fix triage and support-report workflow. Use when diagnosing reported configuration, deployment, or runtime failures; analyzing Caddyfiles, Caddy logs, redirect loops, login failures, authorization denials, OAuth/OIDC/SAML/LDAP/local-user issues, module-version mismatches, or secret/runtime placeholder problems; preparing GitHub issue Markdown files for .github/ISSUE_TEMPLATE/break-fix.md under tmp/breakfix/; or identifying gaps in repository skills after troubleshooting."
---

# Break-Fix Troubleshooting

## Purpose

Use this skill to turn a failing caddy-security deployment into either a
concrete fix or a high-quality break-fix report. Treat the repository skills in
`.codex/skills` as the primary task documentation; `https://docs.authcrunch.com`
is legacy context, not the source of truth.

## Workflow

1. Identify the intended auth flow, protected routes, observed symptom, expected
   behavior, and whether the failure happens during Caddyfile adaptation,
   provisioning, login, callback handling, authorization, upstream proxying, or
   token/session validation.
2. Gather evidence before diagnosing:
   full Caddyfile, relevant Caddy logs, browser or HTTP status details,
   `caddy version`, `caddy list-modules --versions | grep -E "(auth|security)"`,
   operating environment, recently changed config, and last known working
   version when available.
3. Redact secrets while preserving directive names, route structure, identity
   provider names, policy names, cookie names, issuer URLs, redirect paths,
   roles, claim names, and module versions.
4. Load the relevant repository skills:
   `configuration` for Caddyfile analysis, then the specific domain skills for
   authentication portals, authorization policies, identity stores, OAuth
   providers, SSO/SAML, credentials, messaging, users, secrets, registrations,
   or runtime resolution. Use `testing-and-ci` when validation requires tests,
   fixtures, or CI reproduction.
5. Compare the configuration to the parser files and fixtures named by the
   loaded skills. Prefer the smallest valid corrected configuration over a broad
   rewrite.
6. Validate with the narrowest available command. Use Caddy adaptation or
   focused Go tests when local context supports it; otherwise describe the exact
   command the reporter should run.
7. Report the root cause, the minimal fix, validation performed, remaining
   uncertainty, and any repository-skill gap discovered during the work.
8. Write a GitHub-issue-ready Markdown report under `tmp/breakfix/` unless the
   user explicitly asks not to create files.

## Symptom Checks

- Adapt or provision errors: check directive placement, block nesting, argument
  counts, module availability, external plugin registration, and env or secret
  placeholder resolution.
- Login failures: check enabled identity stores/providers, portal path routing,
  credentials, user transforms, cookie settings, crypto keys, and clock skew.
- Portal API failures: check `Accept: application/json` or `format=json`,
  portal base path, latest `sandbox_secret` in challenge flows, token source
  headers/cookies, `/beacon` versus `/whoami` semantics, and whether admin
  endpoints have `enable admin api` plus an admin session.
- Sandbox or MFA lockouts: check checkpoint order, `require mfa` transforms,
  registered TOTP/U2F tokens, sandbox expiration, repeated password failures,
  MFA failure counters on the user record, and whether the user is being forced
  to register an MFA token during login.
- OAuth/OIDC callback failures: check redirect URI, issuer/discovery URL,
  client ID/secret, scopes, PKCE settings, state/cookie behavior, trusted
  redirects, reverse-proxy headers, and provider-specific constraints.
- SAML failures: check entity IDs, ACS URLs, certificates, signing keys,
  metadata, role attributes, and whether the issue is an identity-provider flow
  or an SSO app-provider flow.
- LDAP failures: check bind credentials, search base, filters, username and
  group attributes, realm, TLS settings, network reachability, exact one-user
  search results, role-producing group mappings, and the service-bind then
  user-rebind flow.
- Registration failures: check messaging provider delivery, confirmation link
  base URL, passcode expiry, domain/MX restrictions, dropbox path, admin email,
  target identity store, and whether manual approval or database transfer is
  still required.
- Authorization denials: check route order, `authorize with <policy>` wiring,
  token cookie/header availability, verify keys, ACL rules, roles, claim names,
  bypass rules, and injected identity headers.
- Basic/API-key auth failures: check `X-Auth-Realm` or configured realm header,
  API key header name, one `with ... realm ...` line per accepted realm,
  System API keys for remote portals, and whether the response is a `401` auth
  failure or a browser-style redirect due to missing credentials.
- Redirect loops or missing sessions: check cookie domain/path/security flags,
  auth URL, same-site behavior, source address validation, TLS termination, and
  whether authn and authz use matching crypto material.
- Runtime replacement or secrets issues: check unresolved `{env.*}` tokens,
  secret IDs, configured secrets manager modules, fallback behavior, and
  resolved fixture expectations.

## Response Shape

When solving the issue directly, include:

- Root cause and confidence level.
- Minimal config change or explanation of the required deployment change.
- Evidence used, including relevant log lines or module versions.
- Validation commands run or recommended.
- Security notes about redacted or unsafe material.
- Remaining questions only when they block a reliable fix.

When helping a reporter file a break-fix issue, fill or request the fields from
`.github/ISSUE_TEMPLATE/break-fix.md`: issue description, skill-guided
troubleshooting prompt and findings, full redacted Caddyfile, logs/errors,
version information, expected behavior, actual behavior, skill/documentation
gap, and additional context.

## Issue Report File

For break-fix issue preparation, create `tmp/breakfix/` if it does not exist
and write a Markdown file named with this pattern:

```text
YYYYMMDD_HHMM_<short-issue-slug>.md
```

Use the local timestamp at report creation time. Keep the slug short,
lowercase, and hyphen-separated, such as `oauth-callback-loop` or
`ldap-bind-failure`.

The Markdown file must contain enough information to create a GitHub issue from
`.github/ISSUE_TEMPLATE/break-fix.md` without reconstructing context from the
chat. Include these sections:

- `# breakfix: <concise title>`
- `## Describe the issue`
- `## Skill-guided troubleshooting`
- `## Configuration`
- `## Logs and errors`
- `## Version information`
- `## Expected behavior`
- `## Actual behavior`
- `## Skills or documentation gap`
- `## Additional context`

Preserve fenced code blocks for Caddyfiles, logs, commands, and version output.
Redact secrets, tokens, cookies, passwords, and private keys, but keep names,
routes, roles, claims, issuer URLs, redirect paths, and module versions needed
for diagnosis. Use `TODO` only for fields the reporter still needs to provide.

## Skill Gap Feedback

If repository skill guidance was missing, incorrect, ambiguous, or not specific
enough for the issue, capture:

- The exact prompt or task that produced the weak guidance.
- The smallest redacted Caddyfile and log excerpt that demonstrates the gap.
- The correct behavior or configuration pattern, with parser or fixture
  references when possible.
- The skill file that should be updated, if identifiable.

Prefer turning repeated support issues into skill improvements so future agents
can generate secure, production-ready guidance on the first attempt.
