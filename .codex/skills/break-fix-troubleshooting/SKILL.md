---
name: break-fix-troubleshooting
description: "Diagnose caddy-security deployment and runtime failures from configs, logs, versions, and HTTP evidence. Use for focused fixes, unresolved support handoffs, or preparing break-fix issue reports."
---

# Break-Fix Troubleshooting

## Purpose

Use this skill to turn a failing caddy-security deployment into either a
concrete fix or a high-quality break-fix report. Treat the repository skills in
`.codex/skills` as the primary task documentation; `https://docs.authcrunch.com`
is legacy context, not the source of truth.

Follow the [repository scope](../coding-directives/SKILL.md#repository-scope)
when reproducing or fixing a report. A failure traced to go-authcrunch or an
external plugin does not permit sibling edits or sibling build/test commands.
Keep reproductions and reports here, identify the required upstream fix as
separate work, and continue any correction that can be completed in this module.

## Workflow

1. Identify the intended auth flow, protected routes, observed symptom, expected
   behavior, and whether the failure happens during Caddyfile adaptation,
   provisioning, login, callback handling, authorization, upstream proxying, or
   token/session validation.
2. Inspect supplied evidence first and gather only missing details that can
   distinguish the likely causes: relevant Caddyfile, logs, HTTP/browser status,
   `caddy version`, `caddy security version`,
   `caddy list-modules --versions | rg '(auth|security)'`, operating environment,
   recent changes, and last known working version. Use the actual installed
   binary name; older binaries may lack `security version`.
3. Redact secrets while preserving directive names, route structure, identity
   provider names, policy names, cookie names, issuer URLs, redirect paths,
   roles, claim names, and module versions.
4. Use [configuration](../configuration/SKILL.md) to analyze Caddyfiles and
   select the affected authentication, authorization, identity, or runtime domain.
   Test selection and fixture/CI mechanics follow the
   [testing contract](../testing-and-ci/SKILL.md).
5. Compare the configuration to the parser files and fixtures named by the
   loaded skills. Prefer the smallest valid corrected configuration over a broad
   rewrite.
6. Validate with the narrowest available command. Use Caddy adaptation or
   focused Go tests when local context supports it; otherwise describe the exact
   command the reporter should run. Adaptation does not prove runtime behavior;
   `validate` and `run` may open identity files or contact providers. Reproduce
   with disposable local data before provisioning a supplied deployment config.
7. Report the root cause, the minimal fix, validation performed, remaining
   uncertainty, and any repository-skill gap discovered during the work.
8. For an issue-preparation request or a useful unresolved handoff, write the
   report under `tmp/breakfix/`. A direct explanation or completed small fix does
   not automatically require an issue artifact; honor the requested deliverable.

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
- OIDC consent POST `403 invalid_request` in a real browser: compare the
  consent response's `Referrer-Policy` with the POST's actual `Origin`. In
  go-authcrunch v1.2.6, `no-referrer` produces `Origin: null`, which its own
  same-origin check rejects. HtmlUnit/HTTP-client success does not rule this
  out. Preserve headless Chrome screenshots and network evidence; do not
  rewrite Origin or relax CSRF/origin validation. Apply the explicit Caddy
  [consent response policy](../configuration-oauth-applications/references/oidc-provider.md#consent-response-policy-for-v126)
  for this version, then verify both successful consent and rejection of
  cross-origin/forged-CSRF submissions. The library default needs a separate
  upstream fix. If the consent Origin is correct but Chrome aborts the callback
  with `net::ERR_ABORTED`, inspect `form-action`: its source list must permit the
  registered callback origin as well as self. Keep the exact redirect checks;
  do not replace the source list with a wildcard. See the
  [conformance workflow](../configuration-oauth-applications/references/oidc-conformance.md).
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

## Acceptance criteria

- A supplied reproduction leads to the smallest evidence-backed correction or
  an explicit unresolved boundary; observed facts and hypotheses stay distinct.
- A missing plugin, provider outage, or upstream defect is not described as
  fixed by parser success. Sensitive inputs remain redacted in any handoff.
- A report request produces a self-contained issue artifact. A quick explanation
  can finish without one, and diagnosis does not activate a live deployment.
