# ADR-005: gruff-ts Optimises For The Reviewer Of AI-Generated Code

**Status:** Accepted
**Date:** 2026-05-30
**Author(s):** Claude, user
**Ticket/Context:** Mission-framing documentation pass; product-purpose statement supplied by the user across the 2026-05-30 session.

## Decision

gruff-ts exists to govern AI-generated code so that a human who did not write it can read, review, and trust it. Wired in as a coding-agent hook it is a forcing function on the agent's output, not advisory linting for an author who already holds the context.

The mission decomposes into three goals, in order of intent:

1. **Verifiable** - a reviewer can confirm the change does what was asked by reading it, not by re-deriving the agent's reasoning.
2. **Secure where the eye slips** - mechanical detection of the unsafe patterns human review reliably scans past.
3. **Honestly tested** - tests that assert real behaviour; low-signal ceremony (mock-only, snapshot-only, assertion-free, tautological) is itself a finding, not a way to satisfy a "write tests" instruction.

This has a binding consequence for rule design: **because the agent will rewrite code until a finding clears, every rule is judged by the direction it pushes the agent when it fires, not by whether its threshold matches a conventional linter's default.** A rule whose gradient points away from verifiability or safety is worse than no rule; threshold numbers are secondary to gradient direction.

Documentation rules are deliberately strict for the same reason - a doc comment is expected even on a private one-liner - because forcing the agent to state intent, usage, contract, and failure behaviour gives the reviewer an independent statement to check the code against, and a prose/code mismatch is a signal in itself.

## Context

gruff-ts's surfaces (README, `AGENTS.md`/`CLAUDE.md`, `architecture.md`, `package.json`) described it generically as "a TypeScript project quality analyser / static analyser" - the means, not the end. That framing invites maintenance that optimises for conventional-linter parity rather than for reviewer verification of agent output.

The gradient-over-threshold constraint is not abstract. A 2026-05-30 review of the complexity pillar found concrete cases where the current metrics push agents the wrong way:

- `complexity.npath` (`src/blocks.ts`:`approximateNpath`) computes 2^(decision tokens), so it explodes on flat switches and sequential guard-clause chains - shapes that are easy to verify - and its remediation ("break apart compound branch combinations") would push an agent to fragment legible dispatch into indirection. Measured: a flat 10-case switch scores npath 1024 and eight sequential guard `if`s score 256, both above the 200 threshold.
- `complexity.cyclomatic` (`src/blocks.ts`:`blockRuleContext`) counts `?.` (+1) and `??` (+2 each) while `approximateNpath` strips them, so the two metrics disagree by construction, and a cyclomatic finding can push an agent to delete null-safety operators to lower the count - directly against goal 2. The self-scan's `analyseProjectInCurrentDirectory` (`src/test-fixtures.ts`) scores cognitive 16 with zero control flow, almost entirely from `??` and object-literal nesting.

Raising thresholds does not fix these - npath is exponential, so each doubling of the threshold buys only one more decision token of headroom; the counting/gradient must change. This is exactly the kind of fix a future maintainer could get backwards by reaching for linter-default parity, which is why the mission is recorded as a binding decision rather than left in prose.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Describe gruff as a generic static analyser / quality linter | Maintenance optimises for ESLint/PMD/SonarSource parity; rules get tuned by threshold number and gradient-direction regressions (npath fragmenting legible code, cyclomatic rewarding null-safety removal) read as "correct, matches the standard." | Rejected. It is the framing that produced the anti-mission gradients above. |
| State the mission only in prose (README / `docs/philosophy.md`) | Prose drifts and is not treated as a constraint; a future agent can "improve" a rule toward linter parity without registering that it violated a decision. | Rejected as the sole record. Prose is necessary but not binding. |
| Record the mission plus the gradient-over-threshold constraint as an ADR | The constraint is durable, citable, and visible to future agents at decision time; rule changes can be checked against it. | Accepted. |

## Consequences

- New and existing rules must be evaluated by gradient direction first. A finding's remediation should move agent output toward more-verifiable, safer code; if "make the finding go away" yields worse code, the rule (its counting, gating, or severity) is wrong regardless of threshold.
- The documentation and test-quality pillars are first-class mission instruments, not stylistic extras.
- Conformance is partial as of this ADR: the documentation surfaces now state the mission, but `complexity.npath` and `complexity.cyclomatic` still carry the anti-mission gradients cited above. Fixing those is follow-up work, not settled behaviour. Any resulting finding-value change follows the existing "schema versions are public contract" rule and needs explicit user approval before churning `gruff.analysis.v2`.
- This ADR does not by itself change `Finding`, schema versions, baseline format, dashboard wire format, or CLI semantics.

## Reversibility

Two-way door as a statement, but treat it as a product-defining decision. Reversal (returning to generic-linter positioning) would require updating README, `docs/philosophy.md`, `architecture.md`, the `AGENTS.md`/`CLAUDE.md` openers, and `package.json`, and would re-open the gradient-vs-threshold question this ADR closes. Revisit only if the product's purpose changes and the user explicitly accepts a new positioning.
