# ADR-002: Single Threshold And Severity For Rubrics

**Status:** Implemented
**Date:** 2026-05-18
**Author(s):** Codex, user
**Ticket/Context:** User correction during rubric configuration work; reference implementation in `/home/devgoat/projects/gruff-workspace/gruff-php`

## Decision

Every configurable metric rubric in `gruff-ts` uses exactly one public numeric `threshold` and one public `severity`.

The configured `severity` is the severity emitted when the rule's measured value crosses the configured `threshold`. The config contract must not expose warning/error threshold ranges such as `thresholds.warn` plus `thresholds.error`, and rule descriptors must not advertise warning/error threshold keys.

Rules may still have extra non-severity tuning knobs, but those knobs belong under `options`, not `thresholds`. For example, `design.large-module-concentration` uses `threshold` for the maximum share percentage and `options.minFiles` / `options.minLines` for eligibility guards.

Rules without a configurable measured cutoff keep their descriptor/default severity and do not need `threshold` or `severity` config. If a future rule uses an inverse comparison where lower values are worse, the comparator remains rule-owned; the public config still stays one `threshold` plus one `severity`.

This decision does not change `Finding`, `gruff.analysis.v1`, `gruff.baseline.v1`, dashboard wire format, scoring severity names, or CLI `--fail-on` semantics.

## Context

The prior `gruff-ts` config shape allowed metric rubrics to expose warning/error ranges, for example `complexity.cyclomatic.thresholds.warn` and `complexity.cyclomatic.thresholds.error`. That made a rubric carry two cutoff values and derive severity from the range crossed.

The user rejected that model: "it shouldn't be warning/error range, there should be one value and one severity - for all rubrics!" The user then pointed to `gruff-php` as the model. In `gruff-php`, public docs show `threshold: 80` plus `severity: error` for metric rules, with named tuning values reserved for non-severity options.

The implemented `gruff-ts` code now reflects this contract in:

- `src/config.ts` (`ruleConfigValue`, `threshold`, `ruleSeverity`, `optionNumber`)
- `src/types.ts` (`Config`, `RuleDescriptor`)
- `src/rules.ts` (`RULE_DESCRIPTORS`)
- `.gruff-ts.yaml` (`rules.*.threshold`, `rules.*.severity`, and `rules.*.options`)
- `docs/CONFIGURATION.md` and `README.md`
- `src/cli.test.ts` (`rule threshold config requires one value and one severity`, `rule descriptor thresholds and options match implementation and config defaults`)

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep warning/error threshold ranges | Every metric rubric can silently drift into a two-band policy, and callers must understand both cutoff semantics and severity derivation. | Rejected. The user explicitly corrected this model, and it diverges from the `gruff-php` public contract. |
| Keep `thresholds` but allow only one key | The public shape still implies an extensible threshold map and invites future warning/error keys to return. | Rejected. It preserves the ambiguous concept rather than removing it. |
| Use `threshold` plus descriptor default severity only | Users can tune the cutoff but cannot intentionally promote or demote a rule's impact level. | Rejected. The required contract is one value and one severity. |
| Use one `threshold` plus one `severity`, with separate `options` for non-severity knobs | Metric rubrics have a clear public contract, severity is explicit, and secondary tuning values stay available without becoming severity bands. | Accepted. This matches the requested rubric model and the `gruff-php` reference shape. |

## Consequences

New threshold-backed rubrics must add:

- one descriptor `threshold` value;
- one descriptor/default `severity`;
- parser support through the shared `threshold(config, ruleId, defaultValue)` and `ruleSeverity(config, ruleId, defaultSeverity)` helpers;
- tests proving config override, severity override, and descriptor/config/default alignment.

New non-severity tuning values must use `options`, not `thresholds`. A future PR that adds `thresholds.warn`, `thresholds.error`, `thresholdKeys`, or text describing warning/error threshold ranges is a contract regression.

## Reversibility

This is a two-way door technically but should be treated as a public-contract decision. Reversal would require an explicit user-approved config migration, updates to `README.md`, `docs/CONFIGURATION.md`, `.gruff-ts.yaml`, descriptor metadata, SARIF/list-rules output, and compatibility tests.

Revisit only if a future product requirement needs multi-band severity policies and the user explicitly accepts that as a new public contract. Any revisit must preserve report schema versions and stable finding fingerprints unless the user separately approves schema or fingerprint churn.
