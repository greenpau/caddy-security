---
name: skill-authoring
description: "Create, port, revise, or audit repo-local skills and their metadata, engineering contracts, and task routes. Use for skill discovery, ownership, source grounding, and session-derived guidance; diagrams are optional."
---

# Skill Authoring

## Inherit the default authoring workflow

Use the installed `$skill-creator` skill to apply the default authoring workflow. Read it completely and apply its initialization, naming, frontmatter, progressive-disclosure, metadata, validation, and testing guidance.

Apply this skill after `$skill-creator`. Where the two differ, retain the default requirements and add the repository hierarchy and engineering-contract requirements below.

## Apply repository guidance

Read [the caddy-security supplement](references/caddy-security.md) for repository
scope, documentation ownership, parser/source grounding, examples, and local
validation. The requirements in this skill and its hierarchy contract take
precedence over the supplement wherever they differ.

## Build a routed skill hierarchy

Store every discoverable skill as a direct child of `.codex/skills/<skill-name>/`; do not nest discoverable skill directories inside one another.

Express hierarchy as actionable routing at any depth:

```text
AGENTS.md --Use A to do X--> skill A --Use B to do Y--> skill B --> ...
```

Write each repo-local route in this form:

```markdown
Use [skill-name](relative/path/to/SKILL.md) to perform a specific task.
```

Make the action specific enough that an agent can decide whether to load the linked skill. Put routes to broad skills in `AGENTS.md`. Put routes to narrower skills in the broad skill that delegates the work. A leaf skill needs no hierarchy boilerplate.

Do not add structural ancestry sections or require a downstream skill to link back to its router. The forward `Use ... to ...` statements define the hierarchy.

Read [the skill routing contract](references/hierarchy-contract.md) when creating, moving, routing, or auditing a skill.

Treat cross-skill references that do not tell the agent to use a skill for a task as supporting links, not hierarchy routes.

## Author project engineering contracts

Capture durable behavior and workflows needed to develop, review, operate, and verify caddy-security. Treat the Go source, tests, and skills as cooperating project authorities; update the owning skill when implementation work changes its contract.

Prefer observable, language-neutral contracts:

- responsibility and boundaries
- inputs, outputs, and data shapes
- state and lifecycle transitions
- ordering, concurrency, and timing behavior
- invariants and decision rules
- error, cancellation, retry, and recovery behavior
- user-visible behavior and integration boundaries
- edge cases and acceptance scenarios

Keep contracts focused on behavior and ownership instead of duplicating source listings or private-symbol inventories. Link relevant source or tests when that helps contributors navigate the current repository, but state durable rules in the skill itself.

Put shared concepts in the broadest skill that needs them. Put specialized behavior in the narrowest routed skill that owns it. Do not duplicate the same rule across routing and routed skills.

## Keep skills current after code changes

After implementing a feature, fixing a bug, or changing dependencies, scripts,
or CI behavior, review the final code diff against the relevant repo-local
skills before considering the work complete. Update the owning skills and
linked references in the same change whenever their guidance is affected;
do not wait for a separate documentation request.

Capture the resulting behavior and the guidance another contributor needs:
changed inputs, defaults, contracts, lifecycle, failure modes, compatibility
limits, operational steps, examples, and validation commands or acceptance
scenarios. Remove obsolete instructions and repair affected source/test links.
Ground updates in the final implementation and actual test evidence, retaining
explicit limits where behavior remains partial or unverified.

Use the narrowest existing owner and its relevant references. Add a skill and
its routes only when a new concern has no suitable owner. Keep session logs
and one-off results in working artifacts. If a refactor or other code change
leaves the guidance accurate and complete, leave it unchanged and briefly state
why no skill update was needed. Validate changed skills and affected links using
the scoped workflow below.

## Derive revisions from a working session

When asked to analyze a session and update skills, first inventory:

- explicit asks and requested changes;
- observed failures, logs, and reproduction commands;
- user corrections and stated operating preferences;
- implementation changes already made during the session.

Classify each item as a durable product contract, reusable troubleshooting
workflow, implementation evidence, current conformance gap, or transient
artifact. Do not preserve session IDs, timestamps, credentials, temporary
paths, one-off outputs, or implementation-library choices unless they are part
of a public compatibility contract.

Map each durable item to the narrowest existing owner. Compare its source,
tests, current contract, and conformance profile before editing. State desired
behavior and acceptance evidence in the owner; when source does not yet satisfy
the new requirement, mark that boundary partial or unavailable instead of
silently describing it as implemented. Preserve user intent as observable
behavior—for example level selection, diagnostic evidence, recovery, and
remediation—not as a transcript of the conversation.

## Optional diagrams

Diagrams are not required for this repository. Do not create diagram assets,
install rendering tools, or block a skill audit on missing diagrams. Prose,
examples, and acceptance scenarios must carry the engineering contract.

When the user requests a diagram, apply the
[diagram contract](references/diagram-contract.md) to that asset. Render and
inspect changed pages with tools available in this checkout; keep previews in
`tmp/`. A diagram task does not authorize sibling tooling or source changes.

## Workflow

1. Read `AGENTS.md` and follow the routes relevant to the task. Inventory the full catalog when adding/moving ownership or performing an explicit repository-wide audit.
2. Choose the narrowest existing file that should route to the new or moved skill. Route directly from `AGENTS.md` only when no existing skill owns the concern.
3. Define the new skill's responsibility so it is cohesive, non-overlapping, and small enough to load independently.
4. For a new skill, initialize it with the default `$skill-creator` workflow under `.codex/skills/<skill-name>/`. Edit an existing skill in place.
5. Write the project engineering contract. Use references only for detailed material that would otherwise bloat `SKILL.md`.
6. Add a precise `Use [skill](path) to ...` statement to the selected routing file. Add no backlink solely to represent routing.
7. Add further routes inside the new skill only when it delegates narrower work.
8. Create or update `agents/openai.yaml` only when its interface changes; preserve existing invocation policy and dependencies. Run the default skill validator.
9. For routing/ownership changes or a repository-wide audit, traverse all routes from `AGENTS.md` and repair broken targets, cycles, ambiguous actions, and unreachable skills. For an isolated prose correction, check affected links and behavior without imposing unrelated catalog work.
10. Report the new or changed routing chain using repository-relative paths.

## Route skills by task

When a task matches a routing statement, read and apply the linked skill. Continue following narrower routing statements only while they match the requested work.

Interpret routed skills as focused workflows:

- Routing skills define shared vocabulary, invariants, and dispatch decisions.
- Routed skills add narrower behavior without repeating unrelated routing context.
- A specialized skill must not silently weaken requirements already applied earlier in the route.

## Completion criteria

Finish only when:

- the default skill validator passes for every changed skill
- every new or moved skill is reachable through an actionable route from `AGENTS.md`; repository-wide audits verify the whole catalog
- every `Use ... to ...` target exists and its action is unambiguous
- no routing chain is cyclic
- no structural ancestry metadata or routing-only backlinks remain
- the authored knowledge gives contributors actionable ownership, behavior, and verification guidance
- examples and acceptance scenarios cover normal behavior and material edge cases
- no diagram is required to understand or validate the skill; any requested diagram follows its optional contract

## Acceptance scenarios

- A narrow correction updates its existing owner and necessary links; it does
  not initialize another skill, replace invocation policy, or demand diagrams.
- A new domain has a specific discovery description and an actionable route
  from the narrowest appropriate owner. A representative request reaches it
  without loading unrelated leaves or returning to a parent router.
- Retiring guidance preserves durable contracts in the new owner and updates
  every inbound reference. Dated outcomes and temporary evidence stay in working
  artifacts; unresolved product limits retain explicit acceptance requirements.
- Metadata and routing checks can pass while behavior guidance is wrong. Compare
  representative outputs with the selected source/tests, report missing E2E
  evidence, and distinguish unsupported features from implemented contracts.
