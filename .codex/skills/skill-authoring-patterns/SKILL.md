---
name: skill-authoring-patterns
description: Create, port, rewrite, review, or validate caddy-security repo-local skills, agents/openai.yaml metadata, AGENTS.md routing, and focused configuration, implementation, or workflow guidance.
---

# Skill Authoring Patterns

## Scope and Structure

Use this skill with the default `$skill-creator`; read that skill completely
first. Locate it through the active skills catalog rather than embedding a
developer-specific home directory. Apply `coding-directives` when the task
also changes or reviews application code, and `testing-and-ci` when selecting
repository tests or updating fixtures. Skill-only changes need metadata and
source checks, not a Go build or broad source regeneration.

Apply the [repository scope](../coding-directives/SKILL.md#repository-scope) to
skill work as well as code. Read sibling agent files and skills as references;
port or adapt guidance into `.codex/skills` here. Do not edit the source
repository's skills, metadata, `AGENTS.md`, or automation when porting. Preserve
both the read-only boundary and the named `../xcaddy-caddy-security` build
workspace exception in new skills. Audit imported commands for working
directories, cleanup, generated output, and any instruction to change or test
another repository; the xcaddy exception does not authorize upstream edits.

Default repo-local skills to `.codex/skills`. Use lowercase hyphen-case names
under 64 characters, with matching folder and frontmatter names. New
frontmatter needs `name` and a concise `description` that distinguishes the
requests the skill handles. Preserve supported existing metadata when editing.

Use `agents/openai.yaml` for quoted `display_name`, `short_description`, and
`default_prompt` values. Keep the short description within 25–64 characters
and have the prompt name the exact `$skill-name` and a useful task. Follow the
default skill-creator's metadata reference and generator for new interfaces;
preserve existing invocation policy and dependencies when updating a file.

Keep routers short and leaf skills focused. Add a `references/` file only for
substantial conditional detail and link it where its use becomes relevant.
Add scripts or assets only when the workflow uses them; do not add scaffolding,
TODO/TBD content, creation history, or an extra README to a skill directory.

## Ownership and Routing

Route from `AGENTS.md` and broad concern skills to narrow owners. Keep generic
repository rules in concern skills and concrete grammar, config mapping,
runtime contracts, and validation in the owning feature skill. Split a concern
only when distinct behavior justifies it. Avoid leaf-to-router reloads and
duplicating the same rule across skills.

Use the existing ownership map when extending guidance:

- `configuration` routes Caddyfile requests to the appropriate
  `configuration-*` skills. Keep its Domain Map and intermediate authentication
  routing synchronized when adding or moving a configuration skill.
- `coding-directives` owns Caddy module boundaries, runtime lifecycle, and parser
  conventions; `testing-and-ci` owns unit and E2E coverage requirements and
  parser, adapt, and runtime-resolution test mechanics.
- `scripts-and-automation` owns general Make targets, generated outputs, and
  local go-authcrunch replacement/sync work. Route release-specific behavior
  to `release-and-versioning`.
- `break-fix-troubleshooting` owns support triage and issue artifacts;
  `authentication-portal-api` owns programmatic portal integration;
  `source-code-management` owns commit-message rules and files.

Update `AGENTS.md` and the relevant parent routing whenever discoverability
changes. Keep `AGENTS.md` to repository orientation, shared invariants, and
routing; keep `README.md` and `CONTRIBUTING.md` useful for human onboarding.
Keep repository documentation in the relevant repo-local skill under
`.codex/skills` or its linked `references/` files. Do not create or retain
Markdown documentation in `docs/` or `assets/docs/`. When moving existing
guidance, preserve its useful content in the owning skill and update inbound
links. Extend an existing skill when its scope fits; create a focused skill and
update routing when no existing owner fits. Keep README/CONTRIBUTING onboarding
and AGENTS routing brief, with links to the owning skills for details.

`assets/docs/` may hold non-Markdown assets such as images. Preserve those assets
unless their relocation or removal is part of the task.

## Ground Guidance in This Repository

When authoring a configurable feature skill, trace its Caddyfile directive
from `caddyfile.go` through the relevant root-level `caddyfile_<domain>.go`
parser and into the authcrunch config constructor, field, raw instruction, or
`Add*` method it uses. Route-level `authenticate` and `authorize` parsing lives
in `plugin_authn.go` and `plugin_authz.go`. Identify concrete grammar/defaults,
argument errors, Caddy JSON shape, and provisioning behavior as relevant.

Use `coding-directives` for parser conventions and the
[syntax maintenance workflow](../configuration/references/syntax-maintenance.md)
for grammar ownership. Cookie, admin API, and OAuth configuration use shared
parsers; crypto, messaging, registration, ACLs, transforms, and auth proxy
settings also delegate grammar or validation. Inspect both the Caddy wrapper
and the selected upstream parser, shared dispatcher, and runtime consumer.
Do not infer all syntax from a local switch or an upstream struct. Preserve
recognized-but-restricted syntax with a precise status and source; keep it out
of runnable examples until the full validation path accepts it.
An upstream config field or HTTP handler alone does not prove that a matching
Caddyfile directive exists. Likewise, an adapted placeholder does not prove
runtime replacement support: verify `ResolveRuntimeAppConfig` in
`caddyfile_resolve.go` or the route plugin's provisioning path.

Use `myportal` or a descriptive portal name in configuration examples, fixtures,
and tests. Avoid the confusing repetition in `authentication portal portal`;
write `authentication portal myportal` and match its `authenticate with myportal`
reference. Preserve this convention when porting upstream examples.

Anchor examples and checks in existing `caddyfile_*_test.go` tests and
`testdata/caddyfile_adapt/` fixtures. Distinguish parsed JSON (`.json`) from
runtime-resolved expectations (`_resolved.json`) and identify the tests that
actually exercise the fixture. Feature guidance must identify the unit and E2E
test surfaces required by [testing-and-ci](../testing-and-ci/SKILL.md#required-coverage-for-code-changes),
plus adaptation cases for Caddyfile directive changes. Do not imply E2E coverage
solely from parser/adapt fixtures or sibling-module tests. Preserve the
app/plugin boundary: `app.go` provisions shared authcrunch objects; the HTTP
integrations delegate to them.

For upstream behavior, inspect the version selected by `go.mod` and any active
replacement. Treat `../go-authcrunch` as useful source context whose state may
differ from the required module version. State that distinction when describing
new upstream capabilities or porting sibling skills. Verify commands, paths,
tool pins, CI gates, artifact names, and side effects against this checkout;
document missing automation as missing until it is implemented.

## Maintenance and Validation

Keep public API and security-contract reasoning beside Go declarations.
Keep implementation rationale and operational procedures in the narrow skill.
Before retiring standalone guidance, audit inbound links and move each durable
statement to its declaration or owning skill, then remove obsolete prose and
links. Avoid requiring unrelated validation, release operations, or renewed
approval for actions already authorized by the user.

Validate every changed skill with the default skill-creator's
`scripts/quick_validate.py`. Also parse UI metadata, check the exact skill
invocation, inspect relative links and concrete source paths, and verify
command semantics against the Makefile/scripts. The quick validator does not
establish those behavioral claims. Review likely requests for routing gaps,
unsupported commands, sibling-only contracts, and unintended side effects.

Run added or changed automation with checks proportional to its effects. Use
disposable repositories and local bare remotes for release behavior; never
publish as a validation step. For skill-only edits, metadata/link checks,
source comparison, and `git diff --check` are sufficient. Report validation
performed and any behavior that could not be verified.
