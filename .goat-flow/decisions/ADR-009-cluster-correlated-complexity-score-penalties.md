# ADR-009: Cluster Correlated Complexity Score Penalties

**Status:** Implemented
**Date:** 2026-05-31

## Decision

Score math counts correlated `complexity.cognitive`,
`complexity.cyclomatic`, `design.god-function`, and `size.function-length`
findings once per function symbol. Detailed reports still emit every individual
finding; only pillar penalties, composite score, and file-offender score use the
clustered penalty.

## Context

M06 addressed high-volume rubric noise without disabling rules. The complexity
family was a scoring-specific overlap: one hard function can receive several
findings for the same root cause, but the maintainer still reviews one symbol.

The score values may change because correlated penalties are clustered, but the
`gruff.analysis.v2` score field names and detailed finding array stay unchanged.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep raw penalties for every correlated rule | One root cause can dominate the grade several times. | Rejected because it turns score into an overlap counter. |
| Hide duplicate findings | Maintainers lose useful rule-specific remediation. | Rejected because the detailed report must keep every signal. |
| Cluster only score penalties | The grade reflects root causes while reports keep detail. | Accepted because it improves prioritisation without weakening analysis output. |

## Reversibility

This is reversible if downstream consumers show that raw per-rule penalties are
more useful than root-cause clustering. Reverting should change only score math,
report text, and tests, not the finding schema or rule emission.
