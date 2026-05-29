# ADR-006: Agents Fix Everything - Severity Is Ordering, Not A Gate

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** user, Claude
**Ticket/Context:** User directive during the 1.0.0 plan audit (2026-05-30). Builds on ADR-002 (one threshold + one severity per rubric) and ADR-005 (govern AI-generated code for human sign-off).

## Decision

In gruff's governing use case (a coding-agent hook, per ADR-005), the agent is expected to fix every finding it can - advisory and warning included, not only error. Severity therefore communicates ORDER and impact to a human reviewer; it is not a "fix vs ignore" switch. Two consequences:

1. **One severity and one value per rubric** (reaffirms ADR-002). A rule has a single `severity` and, where applicable, a single `threshold`. No warning/error threshold bands such as `warning: 200 / error: 500` - pick one. The public config must never expose a `thresholds:` map or per-rule severity ranges. Non-severity tuning stays under `options` (ADR-002).
2. **No "tolerate up to N" gating in the agent default.** A CI gate that passes "up to N warnings" treats findings as debt to tolerate. For an agent that fixes everything, the only coherent gate is "fail on any (new) finding" - the existing `--fail-on <level>` (fix everything at or above one level), or a new-only variant scoped to the diff. Per-severity count thresholds (`severityThresholds: { error: 0, warning: 10, advisory: 100 }`) are an adoption-track concept for human teams with legacy debt, not part of agent governance.

## Context

ADR-002 already removed warning/error threshold ranges, justified by user correction and gruff-php parity. This ADR records the deeper WHY from the agent-governance model and extends the principle from per-rule config to CI gating. User framing (2026-05-30): "coding agents should fix everything - including advisory and warning - so having both warning and error is pointless; one severity type and value per rubric is simpler."

Concrete drift this closes, found in the 1.0.0 plans:
- The M04 profile example showed `complexity.cyclomatic: { thresholds: { high: 15 } }` - a thresholds map ADR-002 forbids. Corrected to `threshold: 15`.
- M02 (count-based quality gates) and M03's `severityThresholds` blocks encode "tolerate N per severity," which has no agent-governance justification under this decision.

## Failure Mode Comparison

| Option | What fails | Why rejected / accepted |
| --- | --- | --- |
| Per-rule warning/error bands | Two cutoffs plus severity-derivation per rule; an agent fixes at the lower band anyway, so the upper band never changes behaviour | Rejected (also ADR-002) |
| Per-severity count gates as the default | "Up to N findings is fine" leaves verifiability/security debt the agent was meant to fix; contradicts ADR-005 | Rejected as a default; allowed only as an explicit adoption-track opt-in |
| One severity + one value per rule; gate = fail-on-any-(new) | Simple to read and configure, matches "fix everything," keeps severity as a communication signal | Accepted |

## Consequences

- Rule descriptors keep one `severity` + one `threshold` (already true in `src/rules.ts`). New rules must not add severity bands or `thresholds:` maps.
- 1.0.0 roadmap impact: M02 (count-based gates) loses its agent justification (recommend dropping); M03 (baseline-aware fail-on-new) collapses to a simple "fail on any new finding," not a per-severity count framework.
- The advisory/warning/error ENUM is unchanged - it still orders findings and drives `--fail-on` and scoring. This ADR scopes the meaning of severity; it does not collapse the tiers.
- No change to `Finding`, schema versions, or `--fail-on` semantics by this ADR alone.

## Reversibility

Two-way door, but treat as product-defining. Reversal (reintroducing severity bands, or making count-gates the default) needs explicit user approval and would reopen ADR-002 and the ADR-005 mission framing.
