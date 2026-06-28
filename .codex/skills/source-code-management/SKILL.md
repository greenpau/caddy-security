---
name: source-code-management
description: caddy-security source code management and commit message rules. Use when creating, reviewing, or updating commit messages, especially when the user asks to create a commit message for a change in this repository.
---

# Source Code Management

## Commit Message Rules

All commits must have a proper commit message.

A hand-written commit message subject line must conform to the following
rules:

- The first line of each commit message is the subject.
- The subject line MUST be less than 87 characters long.
- The subject line MUST NOT terminate with a period (`.`).
- The subject line MUST start with a change indicator followed by a colon (`:`).

## Change Indicators

This repository uses change indicators as a mix of product-surface labels and
maintenance labels. Prefer the most specific product surface when the change is
clearly about one Caddy security directive, parser, provider, or runtime path.
Use a maintenance label when the change is repository plumbing, documentation,
testing, release work, or a bug fix that cuts across multiple surfaces.

Selection rules:

- Use exactly one indicator. Do not combine indicators or add parenthesized
  scopes.
- Prefer public Caddyfile and module names over internal abbreviations. For
  example, use `authenticate` instead of `authn`, and `authorize` instead of
  `authz`.
- Use `caddyfile` for parser/adaptation infrastructure that affects several
  directives, Caddyfile fixture changes, or generic config loading.
- Use provider indicators such as `ldap`, `oauth`, or `saml` only when the
  change is provider-specific. Use `identity` when the change is shared by
  identity stores or identity providers.
- Use `breakfix` for a reported regression, panic, or shipped behavior that is
  visibly broken for users. Use `fix` for narrower correctness fixes that are
  not tied to a known user breakage.
- Use `tests`, not `unittest`, for Go tests, Caddyfile adapt fixtures, and
  `testdata` changes whose primary purpose is coverage.
- Use `skills` for AI agent skills, skill metadata, or agent-facing repository
  instructions. Prefer it over `docs` or `ops` when the primary purpose is
  helping AI agents work with this repository.
- Use `ops` for dependency or toolchain version bumps. Use `build` only
  when the build behavior itself changes.
- Release automation creates subjects like `ops: released v1.1.62`; keep that
  form for Makefile-generated release commits. For hand-written release
  workflow changes, use `ops`.
- Use `various` only when a commit intentionally spans unrelated surfaces and no
  more specific indicator is honest.
- Normalize older repository labels when creating new messages: use
  `authenticate` for `authn`, `authorize` for `authz`, `ldap` for `ids/ldap`,
  `local` for `ids/local`, `feat` for `feature`, and `tests` for `unittest`.
  Replace `misc` or `chore` with a more specific indicator when possible, or
  `ops`/`various` when it is truly general maintenance.
- Use colon form for new dependency bumps, such as
  `ops: go-authcrunch to v1.1.40`, even though older history has subjects
  like `upgrade to github.com/greenpau/go-authcrunch v1.1.39`.

Use one of these product-surface indicators:

- `app`: Caddy `security` app provisioning, lifecycle, config validation, or
  runtime config resolution
- `authenticate`: `authenticate` handler behavior, authentication portals,
  cookies, crypto, transforms, or authentication Caddyfile directives
- `authorize`: `authorize` handler behavior, authorization policies, ACLs,
  bypass rules, crypto, claim extraction, or header injection
- `caddyfile`: global `security` Caddyfile parsing, directive ordering, adapt
  behavior, parser helpers, or Caddyfile fixtures spanning multiple surfaces
- `credentials`: credential directives and credentials config
- `identity`: shared identity store or identity provider behavior
- `ldap`: LDAP-specific identity store or provider behavior
- `local`: local identity store or local user behavior
- `messaging`: messaging directives and messaging config
- `oauth`: OAuth or OpenID Connect provider behavior
- `registration`: user registration directives and registration policy behavior
- `saml`: SAML provider behavior
- `secrets`: secrets manager directives and secret resolution behavior
- `sso`: SSO provider directives and single sign-on provider config
- `ui`: portal UI directives, labels, icons, metadata, themes, or UI assets
- `cmd`: `cmd/authcrunch` wrapper behavior

Use one of these maintenance indicators:

- `breakfix`: reported regression, panic, or user-visible breakage fix
- `fix`: correctness fix without a known production breakage
- `feat`: user-facing capability that does not fit a more specific product
  surface indicator
- `docs`: documentation-only changes
- `tests`: test additions, fixture updates, or coverage improvements
- `refactor`: behavior-preserving code restructuring
- `skills`: AI agent skills, skill metadata, `AGENTS.md`, or agent-facing
  repository instructions
- `ops`: dependency, Caddy, Go, toolchain, release, version-reference, or
  repository maintenance changes
- `build`: Makefile, build output, xcaddy, packaging, or local build behavior
- `github`: GitHub Actions, issue templates, CLA workflow, or repository GitHub
  metadata
- `security`: vulnerability, dependency audit, hardening, or disclosure-policy
  changes
- `various`: intentionally mixed changes that do not fit one indicator

The commit message body must contain the following sections in this order:

1. `Before this commit:`
2. `After this commit:`
3. `Tests:`
4. `More info:`

The body may also contain the following optional sections:

1. `Resolves:`
2. `Partial Resolution:`
3. `See also:`
4. `Links:`

The following rules apply to the body of a commit message:

- Separate sections with one blank line.
- Each section title MUST end with a colon (`:`).
- Lines MUST NOT exceed 87 characters, except in `Links` and `More info`.
- Use `Resolves` ONLY when the PR or commit resolves an issue completely.
- Use `Partial Resolution` when the PR or commit addresses an issue partially.
- Use `See also` for additional related references.
- `Resolves`, `Partial Resolution`, and `See also` MUST contain valid links.
- Multiple links in those reference sections MUST be separated by comma and
  space (`, `).
- `Tests` MUST describe the command or manual check performed.
- If no smoke test was run, `Tests` MUST say `not run` and include the
  reason.
- `More info` MUST summarize the implementation details or notable decisions.

The `Links` section must contain a list of valid links or references, e.g.:

```text
  - Text reference
  - [HTTP link](http://google.com/)
```

Use this template for commit messages:

```text
indicator: concise subject under 87 characters

Before this commit: describe the previous behavior, limitation, or state.

After this commit: describe the new behavior, implementation, or state.

Tests: describe the command or manual check performed.

More info: summarize important implementation details or decisions.
```

For example, a commit message may look like this:

```text
docs: add contributing guidance

Before this commit: the repository had no guidance related to open-source
contributions.

After this commit: contribution guidance is documented in `CONTRIBUTING.md`.

Tests: reviewed the rendered Markdown manually.

More info: added a focused contributor workflow and repository etiquette notes.
```

## Commit Message File Workflow

When asked to "create commit message for the change", create a file in
`tmp/commits` and place the commit message in that file. Commit message files in
`tmp/commits` are working artifacts and should not be committed unless explicitly
requested.
