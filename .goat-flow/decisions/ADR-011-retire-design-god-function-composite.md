# ADR-011: Retire the design.god-function composite rule

**Status:** Implemented
**Date:** 2026-05-31

## Decision

Remove `design.god-function` from the rule catalogue. The rule emitted a
`warning` whenever one function was both long (>45 lines) and complex
(cyclomatic >10) - a synthetic finding that fired only when a
`size.function-length` finding and a `complexity.*` finding already coincided on
the same symbol.

The design pillar keeps its other rules (`design.large-module-concentration`,
`design.circular-import`, `design.deep-relative-import`,
`design.package-bin-missing`, `design.package-bin-not-executable`), so the pillar
stays non-empty and the catalogue still spans 11 pillars. The catalogue drops
from 120 to 119 rules; the design pillar drops from 6 to 5.

## Context

Under ADR-005 a rule is judged by the direction it pushes the agent when it
fires, because gruff runs as a hook and the agent rewrites code until the finding
clears. `design.god-function` pushed nothing new: its only honest score is
neutral, because the long-and-complex condition is already carried by the
`size.function-length` and `complexity.cognitive` / `complexity.cyclomatic`
findings on the same symbol. ADR-009 already clusters those correlated findings
into a single penalty, so the composite was clustering logic wearing a finding's
clothes - a named restatement that billed a third pillar for one root cause.

This is the family-wide retirement of the `design.god-*` composite recorded in
the shared DESIGN-PRINCIPLES (P5). gruff-rs removed it first (its ADR-017) and the
TypeScript port follows here. With the composite gone, P5 rests purely on
clustering the real `size.*` + `complexity.*` findings; the one thing lost is the
named "god-function" signal, which was never independently scored.

The removal mirrors the `complexity.npath` clean break (CHANGELOG v0.3.0):
the descriptor is deleted from `src/rules.ts`, the emit site from `src/blocks.ts`,
and the rule id is dropped from the `CORRELATED_COMPLEXITY_RULE_IDS` cluster set
in both `src/scoring.ts` and `src/report-renderers.ts`. The remaining three ids
stay in that set, so a long-and-complex function still clusters to one penalty.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep the composite, score it neutral | A finding that fires but never moves the grade reads as broken to the agent and the reviewer. | Rejected: a finding the agent cannot act on is noise. |
| Keep the composite, score it additively | One root cause is billed a third time, in a third pillar - the P5 footgun confirmed in gruff-php. | Rejected: distorts the grade and contradicts the ADR-009 clustering. |
| Retire the composite, cluster the real findings | The named "god-function" label is lost. | Accepted: the size + complexity findings already describe the function, clustered once per ADR-009. |

## Reversibility

Reversible: re-add the descriptor to `src/rules.ts`, the emit site to
`src/blocks.ts`, and the id to both cluster sets. No schema, fingerprint, or
finding-shape change is involved, so a project that re-enables it sees only the
returned rule id. Until then a config block that still names
`rules.design.god-function.*` is silently ignored, matching the `complexity.npath`
clean-break behaviour.
