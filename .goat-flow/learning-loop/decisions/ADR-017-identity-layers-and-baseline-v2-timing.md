# ADR-017: Identity layers stay distinct; count-based baseline v2 rides the family JSON break

**Status:** Accepted
**Date:** 2026-07-12
**Author(s):** Claude, user
**Ticket/Context:** 0.5.0 identity audit; operator approval recorded 2026-07-12. Reaffirms and amends ADR-013.

## Context

gruff-ts carries five distinct identity layers serving different consumers:

- `Finding.fingerprint` (`src/findings.ts`, search: "const fingerprint = createHash"): sha256(ruleId, filePath, line, symbol)[:16], line-bearing. Consumed by report dedupe, `gruff.baseline.v1` matching, and SARIF `partialFingerprints.gruffFingerprint`.
- `Finding.stableIdentity` (`src/findings.ts`, search: "function stableIdentityFor"): sha256(ruleId, filePath, symbol-or-message)[:16], scope-blind, message-derived when no symbol exists. Consumed by external diff tooling only.
- Hook `stableIdentity` (`src/hook-contract.ts`, search: "function hookStableIdentity"): scope-aware component (`file`, `project[:symbol]`, `symbol:{symbol}`, `message:{message}`). Consumed by hook new-only filtering (`--baseline`, `--diff` base replay).
- `gruff.baseline.v1` matching (`src/baseline.ts`, search: "function applyBaseline"): set-match on (fingerprint, ruleId, filePath); `message` persisted for humans but ignored; no `stableIdentity` field is written.
- Report dedupe (`src/baseline.ts`, search: "function dedupeFindings"): fingerprint-keyed, except `docs.missing-public-doc` which keys on (ruleId, filePath, symbol). Dedupe runs before hook rendering, so the hook only ever sees deduped findings.

A live 2026-07-12 probe suite (real CLI `analyse` and `hook` runs plus the real `makeFinding` producer) established the before-state:

- A pure line move churns the fingerprint and resurfaces a v1-baselined finding while both stable identities hold - the churn ADR-013 was opened for, now live-proven.
- Message rewording and redaction-preview changes leave the fingerprint and v1 matching untouched but churn both message-derived identities; a preview wording change in a baseline entry breaks hook `--baseline` suppression (observed live).
- Two distinct secrets on one line collide on the fingerprint tuple and report dedupe drops the second finding before the hook can see its distinct identity.
- A net-zero same-file replacement (one secret removed, a different one added) is reported as new by both v1 matching and the hook today, but would match silently under a (filePath, ruleId, count) model.
- Symbol renames and file renames churn every shipped layer; the count model absorbs symbol renames and accepts file-rename churn (PHPStan parity).

## Decision

`gruff.baseline.v1` ships unchanged in 0.5.0; the count-based v2 model is reaffirmed but lands only with the coordinated family JSON break, and the shipped identity layers stay intentionally distinct until then.

1. **ADR-013 reaffirmed in direction, amended in vehicle.** The persistent baseline moves to (filePath, ruleId) + count as `gruff.baseline.v2` - but that lands with the coordinated family JSON break (FAMILY-CONTRACT sections 2/3), not port-locally in 0.5.0. `gruff.baseline.v1` stays byte-identical this release so baseline users re-baseline once, at the break.
2. **Analysis and hook stable identities remain intentionally distinct.** The hook's scope-aware algorithm is the canonical candidate for post-break unification. Baseline writers must never persist the analysis `Finding.stableIdentity` into the hook-read `stableIdentity` entry field - the hook would prefer an incompatible value and regress suppression.
3. **Same-line dedupe discriminator is `Finding.column`, not message text.** Report dedupe may extend a colliding fingerprint key with the match's byte-offset column - in-memory only, never serialized as identity, deterministic, independent of redaction presentation. Fingerprint values are unchanged; v1 matching is unchanged (equal-fingerprint same-line findings still match a baseline as one identity - a documented v1 limitation until the break).
4. **Redaction previews are presentation data, not identity inputs.** Preview-policy changes leave fingerprint/v1 matching untouched; hook baseline entries carrying old previews stop suppressing. That one-time churn is accepted as fail-safe (previously suppressed secrets resurface for re-review) and must be named in the changelog entry of the release that changes the preview.
5. **Compatibility path.** v1 files read and write unchanged in 0.5.0 with no additive fields. At the break, the v2 loader rejects v1 files with a clear regenerate message (`applyBaseline` already throws on an unknown `schemaVersion`) and operators regenerate once.

## Why

- FAMILY-CONTRACT section 3 routes JSON-visible identity value changes through the family unification precisely so users migrate once; a port-local v2 now would force a second migration at the break.
- The count model's net-zero-replacement blind spot is inherent PHPStan-parity behavior; recording it now, with live before-state evidence, makes the trade-off explicit instead of discovered.
- Column is the only same-line discriminator that is deterministic, cheap, and decoupled from redaction policy; message-derived discriminators would weld occurrence identity to presentation text, and secret-value-derived identity fails the security bar for shareable reports.

## Scope / non-goals

- No schema string, `Finding` shape, or baseline file format changes in 0.5.0.
- Does not authorize the family JSON break itself, the post-break unification design, or any autofix surface.
- Persisting a canonical hook-compatible identity into generated baselines stays blocked until the post-break canonical producer exists.

## Reversibility

Plan-stage reversible until break work starts: revert this ADR and the references that cite it; shipped v1 identity code is untouched by this decision.
