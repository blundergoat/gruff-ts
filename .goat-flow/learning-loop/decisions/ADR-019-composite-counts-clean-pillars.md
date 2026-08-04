# ADR-019: Composite averages all rule-backed pillars; a clean pillar counts as 100

**Status:** Accepted
**Date:** 2026-08-05
**Author(s):** Claude, user
**Ticket/Context:** 2026-08 goat-flow false-positive report, Defect 6 (composite score punishes fully fixing a pillar).

## Context

`scoreReport` (`src/scoring.ts`) built its pillar list from findings, so a pillar with zero findings never entered the composite mean. Fixing the last finding of an above-average pillar removed that pillar from the average and LOWERED the headline score: the goat-flow cleanup measured `D (69.00)` falling to `F (59.33)` while total findings dropped monotonically and no pillar score decreased. In the limit, ten perfect pillars plus one imperfect one scored as the imperfect pillar alone.

## Decision

The composite is the mean over every rule-backed pillar (the distinct pillars in `ruleDescriptors()`, currently 11), with a zero-findings pillar counting as 100 (`src/scoring.ts`, search: `SCOREABLE_PILLARS`). The report's `pillars` array still lists only finding-bearing pillars - the `gruff.analysis.v2` shape is unchanged; only the composite value's formula changed. The not-applicable refinement (excluding pillars whose rules never ran, for example config-disabled pillars) is deliberately NOT implemented: the simple all-pillars form guarantees the monotonicity invariant and keeps the formula explainable in one sentence.

## Consequences

- Monotonicity holds and is encoded as a test: removing any single finding never decreases the composite (`src/finding-actionability.test.ts`, search: `never decreases the composite`).
- Composite values rise for every project with at least one clean pillar; grade letters can jump (the goat-flow example moves from F-range to A-range). Score history trends (`--history-file`, dashboard) shift once at the release boundary; per-pillar scores, penalties, fingerprints, and identities are unchanged.
- Profiles or configs that disable entire pillars still credit those pillars at 100; revisit with the not-applicable distinction if that ever misleads in practice.
