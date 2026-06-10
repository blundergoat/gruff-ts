# ADR-016: Root Context For Narrow Circular Import Runs

**Status:** Implemented
**Date:** 2026-06-10
**Author(s):** Codex, user
**Ticket/Context:** 0.4.0 M02 cross-file false negatives on narrow runs.

## Decision

Narrow scans build project-root graph context for `design.circular-import` only. Per-file rules
still analyse only the requested files, and `report.paths.analysedFiles` continues to count the
requested discovery surface, not hidden context files.

Circular-import findings from the root graph are emitted when the SCC member list intersects a
requested file. The finding keeps ADR-015's canonical anchor: `filePath` and `line` stay on the
lexicographically first SCC member, even when the requested file is another member. The same
canonical member list remains the `symbol` and hook stable-identity component.

`design.deep-relative-import` and `design.large-module-concentration` remain scoped to discovered
requested files. They are not widened by this decision.

Changed-region hook output may now include scoped project findings for `design.circular-import`.
File-scope findings such as `size.file-length` remain omitted under changed-region attribution
unless baseline/diff new-only logic re-emits them.

No schema, `Finding` shape, baseline format, default-ignore list, or `gruff.hook.v1` envelope field
changes are approved or needed.

## Measurement

Synthetic fixture: `/tmp/m02-large-tree-abCFRA`, 1205 analysable files including a two-file cycle
`src/cycle/a.ts` <-> `src/cycle/sub/b.ts`.

| Row | Command shape | Wall | User | Sys | Max RSS |
| --- | --- | ---: | ---: | ---: | ---: |
| Full scan | `analyse . --no-config` | 0.75s | 0.88s | 0.13s | 193440 KB |
| Scoped, circular disabled | `analyse src/cycle/sub/b.ts --config /tmp/m02-no-circular.yaml` | 0.47s | 0.50s | 0.09s | 162764 KB |
| Scoped, root circular context | `analyse src/cycle/sub/b.ts --no-config` | 0.51s | 0.51s | 0.14s | 169212 KB |
| Graph-only context spike | discover root files, retain import graph sources, build index, run circular SCC | 0.37s | 0.34s | 0.07s | 170876 KB |

The scoped run stayed at `analysedFiles: 1` and emitted one circular-import finding. The added
wall time over the no-circular scoped row was about 0.04s on this fixture, well below the owner's
fallback threshold of roughly 1s added wall time on a large tree.

## Context

Before this decision, `analyse src/cycle/sub/b.ts` built `ProjectIndex` from only that one file, so
it could not see the import edge back from `src/cycle/a.ts`. The hook had the same blind spot for
explicit changed-file paths. Full `analyse .` saw the cycle, but narrow agent runs reported zero
findings and no caveat.

The repo already records the doctrine that changed-region filtering is not project context:
analyse with enough context first, then filter emitted findings. M02 applies that doctrine narrowly
to circular imports while preserving the latency and scoped-per-file behavior that the audit found
valuable.

M09/ADR-015 had to land first because root graph context would otherwise amplify simple-cycle
variants. With SCC grouping, one mutually connected import region produces one project finding.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep path-scoped graph only | Narrow analyse/hook runs silently miss cycles through the requested file. | Rejected. This is the audited false negative. |
| Add a partial-context note only | Names the limitation but still leaves the agent hook unable to catch the cycle. It also needs new contract surface if machine-readable. | Rejected for 0.4.0 because measured root context is cheap enough. |
| Widen every project rule to root context | Deep-relative and large-module findings from unrelated files could appear in a one-file run. | Rejected. No evidence justified widening those rules. |
| Root graph context for circular imports, filtered by SCC membership | Adds legitimate cycle findings on narrow runs while keeping per-file findings scoped. | Accepted. Cost is within budget and output identity is settled by ADR-015. |
| Re-anchor to the requested file | Full and narrow runs would fingerprint the same SCC differently. | Rejected. Canonical anchor is stable across scan modes. |

## Consequences

`src/analyser.ts` owns the hidden root graph collection. It must read root files for graph context
only, preserve the M07 deep-scan budget by excluding over-budget files from hidden graph retention,
and avoid turning hidden root-context read failures into scoped-run diagnostics.

`src/project-rules.ts` exposes the circular-import pass independently so the analyser can run
non-circular project rules on scoped context and circular imports on root context.

Hook changed-region projection must keep project-scope circular findings that survive analyser
scoping. File-scope suppression behavior remains unchanged.

M23 package/import graph work must consume this root-context and SCC-anchor policy rather than
adding a second graph identity model.

## Reversibility

Reverting means removing root graph context and returning to silent narrow-run false negatives, or
switching to an explicit caveat surface that needs owner approval for the report/hook shape. Because
the current decision can add findings to narrow scans, any revert or caveat replacement should be
called out as a public behavior change.
