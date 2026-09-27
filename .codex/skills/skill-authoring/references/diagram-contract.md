# Architecture Diagram Contract

## Contents

1. Purpose and authority
2. Required context on every page
3. Visual grammar
4. Layout and routing rules
5. Boundary and lifecycle representation
6. Generated overview pages
7. Review and acceptance scenarios

## Purpose and authority

Use a diagram to answer a concrete implementation question, not merely to enumerate components. A reader who sees one rendered page without its filename or surrounding Markdown must still be able to locate it in the product, identify its owner, follow its arrows, and find the authoritative prose.

`ARCH-DGM-001` — Numbered prose contracts, schemas, tables, and acceptance scenarios remain authoritative for exact values, timing, ordering, errors, and compatibility behavior. A diagram is authoritative only for the topology, ownership, state relation, or lifecycle position explicitly named in its visible authority note. A contradiction is an audit failure; prose governs until the diagram is repaired.

`ARCH-DGM-002` — Every diagram page states the implementation question it answers. A page may be a context map, responsibility flow, state machine, sequence, trust boundary, durability view, or ownership view; it must not silently mix those meanings.

## Required context on every page

`ARCH-DGM-003` — Make each page self-orienting with visible fields for:

- `Context`: product → router → owning skill;
- `Question`: the implementation question answered;
- `Starts with`: upstream input, event, state, or evidence;
- `Ends with`: downstream outcome or handoff;
- `Owns`: the highlighted responsibility boundary;
- `Defers to`: adjacent skills that own omitted decisions;
- `Contracts`: prose anchors represented by the page;
- `Authority`: the exact topology or ownership claim made by the page.

`ARCH-DGM-004` — Include a compact canonical-product lifecycle strip and visibly mark “you are here.” Show at least one upstream and one downstream stage outside the owned boundary unless the page is the root system boundary. Cross-cutting operations and audit evidence are shown as cross-cutting, not falsely inserted as sequential stages.

`ARCH-DGM-005` — Distinguish hierarchy from runtime flow. Breadcrumb arrows mean documentation routing; lifecycle arrows mean dependency/semantic progression; responsibility arrows mean transfer of an event, decision, record, state, resource, or authority. Never reuse one unlabeled arrow style for all three.

## Visual grammar

`ARCH-DGM-010` — Use one dominant reading direction per page. Put actors, processes, trust zones, authorities, stores, and lifetimes in named lanes or containers when more than one is present. If a page deliberately has one lane, state that in its question or boundary note.

`ARCH-DGM-011` — Highlight the current owner with strong contrast. Render upstream, downstream, sibling, and delegated context with subordinate styling. Do not rely on color alone: include text labels, borders, tags, or patterns.

`ARCH-DGM-012` — Label every behavioral edge with a verb plus the transferred concept, such as `validates request`, `publishes event`, `persists record`, `retries after`, or `returns decision`. Labels such as `next`, `uses`, or an unlabeled arrow are insufficient when the relation could be mistaken for control flow, data flow, authority, or documentation routing. Mechanical maintenance must never guess a normative verb from a node name or shape. When it can prove only adjacency, it may add the visibly defined topology-only label `handoff · <target>`; the page authority and numbered prose then own the payload, decision, and side-effect meaning.

`ARCH-DGM-013` — Define the visible line grammar on every behavioral page. The shared overview grammar is:

- solid blue: primary forward responsibility transfer;
- dashed amber: alternate, fan-out, merge, or bypass path;
- dashed purple: feedback, retry, continuation, or recovery path;
- gray: broader-context or documentation-routing relation.

Use text/pattern differences in addition to color.

`ARCH-DGM-014` — Use sequence numbers only for a true total order. Use tags such as `ENTRY`, `DECISION`, `FAN-OUT`, `MERGE`, `STATE`, `STORE`, `HANDOFF`, or `OUTCOME` for partial orders and topologies.

## Layout and routing rules

`ARCH-DGM-020` — Do not allow an edge to cross any node, including travelling through its own source or target after touching a boundary port, or obscure a label. Do not overlap edge segments unless an explicit junction says that the flows merge. If a crossing is unavoidable, use a visible line jump and keep both labels readable.

`ARCH-DGM-021` — Give fan-out and fan-in edges distinct ports. Route feedback, retry, continuation, and recovery around the perimeter of the forward flow. Route a long edge that skips a dependency layer on an outside rail rather than through intermediate nodes.

`ARCH-DGM-022` — Place nodes by dependency depth and semantic lane, not source-file order or array index. Center nodes within each layer, reserve whitespace for labels, and keep a stable minimum gap between unrelated shapes.

`ARCH-DGM-023` — An automatically routed edge is acceptable only when the layout proves it cannot overlap another edge, node, or label. Otherwise declare ports and waypoints explicitly. Rendering and inspection are required; well-formed XML alone is not readability evidence.

`ARCH-DGM-024` — Cell identifiers must be unique and safe in the target Draw.io codec. Reject identifiers inherited from the viewer's array/object lookup tables, including `reduce`, `map`, `filter`, `length`, `constructor`, and prototype-property names: well-formed XML using such an ID can crash during decode before a page renders.

## Boundary and lifecycle representation

`ARCH-DGM-030` — Show material decision, failure, cancellation, retry, durability, and recovery paths when they change the page's answer. When detail belongs elsewhere, name the deferred skill or contract instead of omitting the boundary silently.

`ARCH-DGM-031` — A store shape means durable evidence only when the prose contract guarantees it. Process-local queues, callbacks, latches, cursors, and counters must be visibly marked volatile. Attempt, queue admission, append, acknowledgement, and consumption are different edges.

`ARCH-DGM-032` — A trust or authority boundary states who decides and who merely transports or presents. Remote placement, UI display, a hook response, or an authenticated channel cannot be drawn as if it owns permission, transcript, task, or policy truth.

## Generated overview pages

`ARCH-DGM-040` — Every generated `architecture.drawio` contains two pages:

1. `Context & Boundaries` locates the skill in the routing hierarchy and canonical lifecycle, summarizes inputs/outputs, names owned and deferred scope, and states authority.
2. `Responsibility Flow` lays out the skill's primary topology by dependency depth, labels every relation, separates alternate and feedback rails, and repeats the context breadcrumb.

The context page is orientation; the flow page is topology. Neither replaces detailed custom diagrams or numbered prose.

`ARCH-DGM-041` — The generator is deterministic and supports a check-only mode. Regeneration must not erase manual custom diagrams, and a generated overview may not be hand-edited without also changing the generator specification.

## Review and acceptance scenarios

### `ARCH-DGM-A01` — Independent orientation

Give a reviewer only one rendered page. They identify its product route, lifecycle position, question, owner, upstream input, downstream handoff, line meanings, deferred domains, and prose authority without consulting the directory name.

### `ARCH-DGM-A02` — Registry fan-out and merge

Render the concrete tool-catalog overview. Build/gate and primitive assembly feed distinct tool-family nodes through separate ports; every family reaches the filtered registry without a shared ambiguous segment, edge-through-node overlap, or false total-order numbering.

### `ARCH-DGM-A03` — Feedback outside forward flow

Render a recursive query or reconnect overview. The forward path reads in one direction; feedback/retry uses a labeled purple perimeter rail and never crosses an intermediate node or primary label.

### `ARCH-DGM-A04` — Prose conflict

Change a diagram to imply different ownership, durability, ordering, or terminal behavior from its declared contract anchors. The audit fails and the numbered prose remains the project authority until the diagram is corrected.
