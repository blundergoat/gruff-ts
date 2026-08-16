# ADR-020: Defer corpus score recalibration to the coordinated family break

**Status:** Accepted
**Date:** 2026-08-11
**Author(s):** Codex, user
**Ticket/Context:** 2026-08-11 gruff-ts 0.5.x corpus remediation, Task 2.

## Context

A fresh no-config corpus scan after package-manager lockfiles were removed from the sensitive-data pass still ranked the deliberately vulnerable `nodejs-goof` repository first. The scan used `bin/gruff-ts analyse --no-config --fail-on=none --format json <repository>` from an empty directory. The lockfile correction reduced NodeGoat from 1,687 to 395 findings and nodejs-goof from 968 to 136 findings, but the score ordering remained inverted:

| Rank | Repository | Findings | Errors | Score | Grade |
| ---: | --- | ---: | ---: | ---: | :---: |
| 1 | nodejs-goof | 136 | 3 | 80.41 | B |
| 2 | express | 2,165 | 2 | 60.18 | D |
| 3 | NodeGoat | 395 | 6 | 52.18 | F |
| 4 | nest | 11,939 | 6 | 26.18 | F |
| 5 | juice-shop | 4,785 | 164 | 23.32 | F |
| 6 | axios | 2,326 | 36 | 19.55 | F |
| 7 | zod | 6,928 | 66 | 18.83 | F |
| 8 | sequelize | 7,589 | 37 | 17.64 | F |
| 9 | typeorm | 23,240 | 52 | 10.41 | F |
| 10 | angular | 67,908 | 244 | 6.64 | F |

The current implementation in `src/scoring.ts` (search: `function scoreReport`) uses the TypeScript port's existing penalty, clustering, pillar, and per-file formulas. The family contract schedules those coupled dimensions for one coordinated migration with the JSON break.

## Decision

Keep `scoreReport` unchanged in this remediation. Carry the measured ordering above into the family scoring and severity parity work; migrate the penalty table, confidence multiplier, pillar and per-file formulas, correlated-rule set, and cluster key together at the coordinated JSON break.

The lockfile scan-surface correction lands independently because it removes findings for public package digests without redefining score semantics.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Retune TypeScript scoring now | The port gains a temporary model that the family migration must replace, and serialized scores change twice. | Rejected. |
| Lower sensitive-data severity | Genuine embedded credentials stop reaching the family-conforming error tier. | Rejected. |
| Keep the model and record the corpus inversion | Rankings remain misleading until the coordinated migration, but one evidence set drives all coupled scoring changes. | Accepted. |

## Reversibility

This is a two-way scheduling decision, not a permanent endorsement of the current ranking. Revisit it when the coordinated family scoring migration begins or if the family contract changes its release boundary. Until then, corpus calibration may add evidence but must not produce a TypeScript-only scoring retune.
