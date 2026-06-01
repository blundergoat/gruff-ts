# ADR-013: Count-based baseline identity (file + rule + count, not line)

**Status:** Accepted
**Date:** 2026-06-01
**Author(s):** Claude, user
**Ticket/Context:** Operator directive while moving the baseline cluster (M01/M03/M24) out of the 0.3.0 plan into 0.4.0: "baseline ... can't have the file line number because that is too fragile. Use file count instead and see how phpstan does their baseline."

## Decision

The persistent baseline (`gruff-baseline.json`) keys suppressed findings on `(filePath, ruleId)` plus an occurrence `count` - not on the line-bearing fingerprint. This is the PHPStan baseline model (https://phpstan.org/user-guide/baseline): each entry is `{ message: <regex>, count: N, path }`, carries no line number, ignores up to `count` matching errors per path, and reports the rest. When the real count drops below `count`, PHPStan says the entry "was expected to occur N times but occurred only M".

gruff's faithful analog, adapted to the fact that gruff already has stable rule IDs (PHPStan keys on the message text because it historically lacked stable identifiers):

- Baseline entry shape becomes `{ ruleId, filePath, count }`. `message` MAY be persisted for human review but is NOT part of the match key - the exact stance `applyBaseline` already takes on `message` today (`src/baseline.ts`, search: `applyBaseline ignores it`). `line`, `symbol`, and `fingerprint` are dropped from the entry.
- Match: group current findings by `(filePath, ruleId)`. In deterministic order, the first `count` of a group are `unchanged`; any surplus beyond `count` are `new`; a baselined group whose current count is lower than `count` is `absent`/stale (PHPStan's "expected N, occurred M").
- This is a `gruff.baseline.v1` -> `gruff.baseline.v2` format change. The bump and the entry-shape change are an Ask-First boundary per CLAUDE.md. This ADR records the operator's explicit go-ahead for the DIRECTION; the schema-string edit in `src/` is still gated to implementation time.

`Finding.fingerprint` is NOT removed. It still hashes `(ruleId, filePath, line, symbol)` (`src/findings.ts`, search: `const fingerprint = createHash`) and remains the SARIF `partialFingerprints.gruffFingerprint` / GitHub code-scanning identity (the M25 invariant) and the report-dedupe key (`src/baseline.ts`, search: `function dedupeFindings`). Only the persistent baseline stops keying on it.

## Why

The fingerprint embeds `line`. A pure code move (insert ten lines above a finding) changes the line, changes the fingerprint, and the previously-baselined finding resurfaces as `new` even though nothing about the defect changed. For a committed baseline that real code drifts under, that is churn-by-design. Keying on `(filePath, ruleId)` + count makes intra-file movement free: only a genuine count increase ("you added one more of this rule in this file") surfaces as new. PHPStan chose count-over-line for exactly this reason.

The prior plan (M24) assumed the opposite - that "a line-moved entry still matches the same fingerprint". That assumption is false against the current `makeFinding` and is the latent bug this ADR closes (recorded as a footgun in `.goat-flow/footguns/schema-and-cli.md`, search: `fingerprint embeds`).

## Scope / non-goals

- Applies to the persistent on-disk baseline: M24 (matching, deterministic ordering, stale audit), M01 (three-state classification against it), and M03 (fail-on-new consuming that classification).
- Does NOT change `Finding.fingerprint`, SARIF partial fingerprints, the dashboard wire format, or report dedupe.
- M05's deferred two-pass `--since` diff (ADR-008) builds an ephemeral, same-session baseline and MAY keep finer per-finding granularity; it is out of scope here. The shipped git-hunk region filter (`--since` / `--changed-ranges`) remains the agent gate per ADR-008 and is unaffected by this change.
- File renames change `filePath`, so a renamed file's findings resurface as new - the same property PHPStan has. Accepted.

## Consequences

- M24 and M01 are re-scoped from `(fingerprint, ruleId, filePath)` matching + line-bearing ordering to `(filePath, ruleId)` + count. M03's flag surface and exit wiring are unchanged; it still gates on M01's `new` set.
- One-time churn: operators regenerate `gruff-baseline.json` once on upgrade. The v2 loader rejects v1 files - `applyBaseline` already throws on an unknown `schemaVersion` (`src/baseline.ts`, search: `unsupported baseline schema`).
- A rule that legitimately fires many times in one file (e.g. `docs.missing-public-doc`) is baselined by count. The per-symbol dedupe special-case (`src/baseline.ts`, search: `docs.missing-public-doc`) is a dedupe concern, not a baseline-key concern, and is unaffected.
- Aligns with the adoption framing M24/M01 already carry (freeze existing debt, block the next one) and does NOT reintroduce the tolerate-N quality gate that ADR-006/ADR-008 rejected: count here freezes EXISTING findings, it does not grant a standing allowance for new ones.

## Reversibility

Reversible at the plan stage. This ADR and the M01/M24/M03 edits are planning artifacts; no `src/` schema string has been touched. If rejected, revert the milestone edits and delete this ADR - the shipped v1 fingerprint baseline in `src/baseline.ts` is untouched.
