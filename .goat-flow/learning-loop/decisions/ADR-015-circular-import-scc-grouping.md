# ADR-015: Circular Import SCC Grouping And Canonical Anchor

**Status:** Implemented
**Date:** 2026-06-10
**Author(s):** Codex, user
**Ticket/Context:** 0.4.0 M09 circular-import report explosion and M02 root-graph context prerequisite.

## Decision

`design.circular-import` reports one finding per strongly connected component in the discovered
non-type relative import graph, not one finding per simple cycle variant.

For each SCC:

- `filePath` anchors to the lexicographically first member path.
- `line` anchors to the first non-type import edge in that anchor file that points to another SCC
  member, falling back to line 1 only if no such edge is found.
- `symbol` is the canonical sorted member list joined with ` -> `. Hook stable identity for project
  findings continues to include `symbol`, so the SCC member set is the stable identity component.
- `metadata.files` is the sorted SCC member list.
- `metadata.representativeCycle` is one deterministic closed import path inside the SCC, starting
  and ending at the canonical anchor when such a path can be found.

Type-only imports remain excluded from the graph. Self-loops are not newly reported in this
milestone because the previous simple-cycle detector ignored them.

No `Finding` shape, schema string, baseline format, or hook envelope changes are approved or
needed. Finding count, message, metadata, symbol, fingerprint, and hook stable-identity churn are
accepted as the intentional output-policy change.

For future M02 root-context narrow runs, keep the same canonical anchor even when the requested
file is another SCC member. The filter may decide whether an SCC intersects the requested paths,
but it must not re-anchor the finding to the requested file because that would create divergent
fingerprints for the same architectural cycle.

## Context

Adoption scans showed `design.circular-import` could emit many findings inside one strongly
connected area. OpenUI emitted 108 circular-import findings, with 46 anchored on one chart file.
The old implementation explored simple paths up to length 12 from every file and deduped by the
sorted file set. That preserved determinism, but it produced multiple variants that told the same
reviewer story: "this import region is mutually connected."

M02 may later widen graph context for narrow-path runs. If M09 did not settle cycle grouping first,
a single edited file inside a large SCC could surface many simple-cycle variants in the agent hook.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep simple-cycle output | One SCC can emit many variants and overwhelm the reviewer. M02 root context would amplify this in hooks. | Rejected. It preserves old fingerprints but fails the adoption-scale noise evidence. |
| One finding per SCC with canonical anchor | Fingerprints and finding counts change, but the architectural signal maps to the real graph unit. | Accepted. Owner approved count/fingerprint churn for M09. |
| One finding per requested member in narrow runs | Narrow and full runs would disagree on filePath, line, fingerprint, and hook identity for the same SCC. | Rejected. It would make baselines and M02 filtering harder to reason about. |
| Cap simple-cycle variants per SCC | Still reports arbitrary variants and requires omitted-count semantics. | Rejected. SCC grouping is simpler and more stable. |

## Consequences

`src/project-rules.ts` must build circular-import findings from deterministic SCC detection over
the existing `importsByFile` graph. Graph construction must continue using
`importEdgesForSource` and `isTypeOnlyImportStatement`; no second import parser should be added.

Tests must include:

- one SCC with multiple simple cycles collapsing to one finding;
- two independent SCCs remaining two findings;
- type-only cycles staying at zero findings;
- two-file cycle output staying deterministic across source iteration order;
- hook stable identity using the canonical SCC symbol intentionally.

M23 package/import graph health must consume this policy rather than reintroducing simple-cycle
canonicalization as the primary output shape.

## Reversibility

Reverting this decision requires restoring simple-cycle enumeration and accepting renewed
finding-count expansion. Because fingerprints and baseline entries churn in both directions, any
revert should be called out as a public behaviour change in the changelog.
