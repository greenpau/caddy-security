# Skill Routing Contract

Keep discoverable skills as sibling directories under `.codex/skills/`. Build the hierarchy with task-oriented routing statements, not ancestry metadata.

## Root routing in AGENTS.md

```markdown
## Repo-local skills

- Use [root-skill](.codex/skills/root-skill/SKILL.md) to perform a specific broad task.
```

Route only broad concerns from `AGENTS.md`. Route specialized work from the skill that owns the broader concern.

## Skill-to-skill routing

```markdown
## Specialized workflows

- Use [specialized-skill](../specialized-skill/SKILL.md) to perform a narrower task.
```

Every route must:

1. Start with the imperative `Use`.
2. Link the skill name to its `SKILL.md`.
3. Include `to` followed by a concrete task or trigger.
4. Be placed in the narrowest file that can make the routing decision.

A leaf skill contains no hierarchy section or placeholder. Add a routing section only when the skill actually delegates work.

A route delegates a task; a supporting link identifies a collaborating contract
or source without requiring a reload. Do not make every dependency into a route.
In particular, a leaf may name its surrounding portal, policy, or store owner
without telling the agent to reload that parent. Cross-cutting test, scope, and
release constraints can be cited at the boundary where they govern behavior.
Do not disguise task delegation with unlinked skill names or lowercase `use`
to avoid route validation.

## Skill content contract

Provide the minimum project knowledge needed for implementation:

1. Responsibility and exclusions
2. Inputs and outputs
3. State model and lifecycle, when applicable
4. Behavioral rules and invariants
5. Failure and recovery behavior
6. Interactions with routed or collaborating skills
7. Language-neutral acceptance scenarios

Prefer externally meaningful behavior and clear ownership over copied code descriptions. Name a specific algorithm only when it is part of the required contract.

## Routing audit

For every `.codex/skills/*/SKILL.md`:

- Confirm the directory name equals the frontmatter `name`.
- Confirm frontmatter contains only `name` and `description`.
- Confirm no structural ancestry metadata or routing-only backlinks exist.
- Start at `AGENTS.md` and follow repo-local `Use [skill](path) to ...` routes.
- Confirm every route resolves to an existing `SKILL.md`.
- Confirm every repo-local skill is reachable from `AGENTS.md`.
- Reject cycles and routes whose action is too vague to select the skill reliably.
- Review informal `Use`/`Load`/`Read` instructions naming skills as well as formal
  routes; a graph check alone can miss unlinked delegation or a parent reload.
- Walk realistic requests from the root. Reachability is insufficient if every
  incoming route has the wrong trigger, such as requiring a Caddyfile edit for
  an HTTP-only client task.
- Distinguish supporting links from hierarchy routes by requiring the `Use ... to ...` form.
- Confirm implementation-critical guidance is present in the routed skill and remains consistent with source and tests.
- Run the default `$skill-creator` validator for every changed skill.

## Contract review

Examples and acceptance scenarios describe observable results, including material
failure paths. A test filename alone is not an acceptance criterion. Identify
what parser/unit evidence proves, which Caddy E2E verifies the user flow, and
which behavior remains unqualified. Do not invent runtime coverage to satisfy
a documentation checklist.

Keep reusable mode-specific detail in linked references when it would otherwise
force unrelated tasks to load a long entrypoint. Each supporting file needs a
real caller and a task trigger. Skill-only validation checks metadata, links,
routing, and source truth; runtime suites are selected only when their behavior
is actually changed or needs qualification. Diagrams are optional here.
