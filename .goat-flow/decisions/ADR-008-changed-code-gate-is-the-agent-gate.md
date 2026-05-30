# ADR-008: The changed-code gate is the agent gate; resolve the M01-M05 cluster

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, user
**Ticket/Context:** "What's next in 1.0.0?" surfaced that the M01-M05 "gate on new findings" cluster is tangled, partly anti-mission, and partly already shipped.

## Decision

For 1.0.0 the coding-agent gate is **the shipped region-scoped change filter plus `--fail-on`**. No persistent baseline and no two-pass `git worktree` scan are required to "fail only on what the change introduced."

- **M02 (count-based quality gates): DROPPED.** Count-gates ("tolerate up to N findings") are anti-mission - per ADR-006 an agent fixes everything, so a tolerate-N gate has no agent-governance justification. The only sensible agent gate is "fail on any (changed-scope) finding," which `--fail-on` already provides.
- **The baseline-free "new finding" gate is already shipped.** `analyse <paths> --since <ref>` / `--diff` / `--changed-ranges <ranges>` narrows findings to the changed region; `--fail-on <sev>` then gates over exactly those. Verified: a finding outside the changed region does not fail the run, a finding inside it does. `--changed-scope hunk` further restricts the gate to changed lines. This is M05's headline lightweight goal ("did this branch introduce findings, without writing a baseline file").
- **M03 (persistent-baseline `--fail-on-new`): DEFERRED post-1.0.** It targets the human-team-with-a-committed-baseline workflow, overlaps the shipped changed-code gate, and is not needed for the agent-hook mission ("you likely do not need both" - M03 review).
- **M01 (three-state baseline classification) + the heavy M05 two-pass: DEFERRED post-1.0.** The only remaining M05 value over the shipped gate is *precision* - a two-pass scan at `<ref>` and HEAD that fingerprint-classifies each finding `new` / `unchanged` / `absent`, so a pre-existing finding inside a touched symbol is not counted as new. That precision costs ~2x scan time, temporary-worktree orchestration with worktree-safety risk (M05 kill criteria), and the full M01 baseline machinery - while `--changed-scope hunk` already covers most of it. "Hooks run constantly, so speed is correctness" argues against a 2x two-pass by default. Revisit if real usage shows the region filter's over-reporting (pre-existing findings in edited symbols under `--changed-scope symbol`) is a problem.

## Consequences

- M00 marked complete (npath removal shipped). M02 dropped. M01/M03/M05 deferred post-1.0 with this rationale recorded on each milestone.
- 1.0.0's remaining build work is rule-breadth and reporting, not gate machinery: M26 (sensitive-data expansion, unblocked) next, then M04 / M23 / M24 as prioritised; M25 stays blocked pending its own architecture ADR.
- Docs already state the gate (`docs/agent-hook.md` "Scan the change, not the repo"; the CHANGELOG region-scoped entry). No schema, flag, or finding change.

## Reversibility

Fully reversible - deferral, not deletion. The M01/M03/M05 milestone files remain for a post-1.0 precision pass. Any later two-pass build must follow M05's kill criteria (worktree cleanup in `finally`, argv-element ref passing, ephemeral in-memory baseline, mutual-exclusion with `--baseline`).
