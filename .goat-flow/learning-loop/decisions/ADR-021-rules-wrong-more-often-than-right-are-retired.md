# ADR-021: Rules wrong more often than right are retired, not tuned

**Status:** Accepted
**Date:** 2026-10-05
**Author(s):** Claude, user direction
**Ticket/Context:** precision-floor M19 under family lock M82. The operator ruled on 2026-10-04 that a rule right less than
half the time is deleted, and accepted the gruff-ts table. The same decision is gruff-go ADR-021, gruff-php ADR-034,
gruff-py ADR-029 and gruff-rs ADR-024.

## Context

gruff runs as a coding-agent hook, so a wrong finding asks an agent to change code that was already right. The 0.6.0
precision measurement (the workspace's precision-floor M01) judged a sample of each rule's findings on the family corpus.
Thirteen gruff-ts rules scored below half. The operator kept three for their class fixes (`security.inner-html`,
`security.process-exec` and `sensitive-data.database-url-password`), and M19 turns off rather than deletes a rule below
half that fired fewer than ten times, because so few findings cannot show it is wrong more often than right.

## Decision

gruff-ts retires eight rules the 0.6.0 precision measurement found right less than half the time:

- `security.floating-promise`, right on 3 of 24 judged findings;
- `security.github-actions-broad-permissions`, right on 3 of 10;
- `security.insecure-random`, right on 2 of 23;
- `security.proto-access`, right on 3 of 23;
- `security.risky-lifecycle-script`, right on 5 of 14;
- `sensitive-data.hardcoded-env-value`, right on 7 of 25;
- `sensitive-data.high-entropy-string`, right on 2 of 22;
- `test-quality.no-assertions`, right on 5 of 25.

Each rule's detector goes, with the code only it used: the floating-promise walk over the shared parse, the workflow
permission-block reader, the two line checks, the lifecycle-script check, the environment-assignment and entropy chains
with the public-shape module and the image-asset search, and the test-block check. So do its catalogue entry, its
`gruff.strict` threshold where it had one, tests, docs and dogfood config blocks. The built-in lockfile skip applied
only to `high-entropy-string`, so it goes too, and no lockfile audit row is published. So does the named `thresholds:` config path:
the entropy rule was the only one that published named thresholds, so a `thresholds:` map is now refused on every
rule, as it already was on the rest.

A `rules:` block or a `sensitiveExclusions` entry that names a retired rule exits 2, and `list-rules` refuses the id.
`--include-rule` and `--exclude-rule` accept one silently, so a run narrowed to a retired rule runs no rule and passes,
and a baseline row for one reports as resolved.

It also turns two rules off by default, too few findings to delete on: `security.open-redirect-candidate`, right on
1 of 5, and `sensitive-data.jwt-token`, right on 0 of 1. They stay in the catalogue with `isEnabledByDefault: false`,
`init` seeds them as `enabled: false`, and they run when a config sets `rules.<id>.enabled: true`. `--include-rule`
only narrows a run, so it does not turn one on.

The family specification records the retirements as a catalogue transition with no successor, and keeps each rule's
review record as `retired` (workspace ADR-010).

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Tune each rule | Each repair needs new evidence, and the rule keeps reaching agents until it lands. | Rejected - the 2026-10-04 ruling is to delete, and the roadmap keeps what a rebuilt rule needs. |
| Keep the rules but score-neutral | Findings still reach agents as hook output. | Rejected - the hook carries every finding whatever its score weight. |
| Turn all ten off | Eight rules measured on 10 to 25 findings would stay as hidden code. | Rejected - those measurements are enough to delete on. |
| Retire eight, turn two off | A project that relied on a retired rule loses it. | Accepted - every retired rule was wrong more often than right. |

## Reversibility

A retired rule can return as a new, measured rule; `.goat-flow/plans/0.7.0-roadmap/rules-to-rebuild.md` in the workspace
keeps its wrong shapes and what a rebuilt rule needs. A rule turned off comes back on by removing
`isEnabledByDefault: false` once a measurement on more findings puts it at half or better.
