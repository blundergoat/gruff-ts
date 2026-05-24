---
category: pr-review
last_reviewed: 2026-05-24
---

# PR review patterns

## Pattern: empirically reproduce multi-agent PR review claims before agreeing

**Created:** 2026-05-24

**Context:** Bot-driven reviews (Copilot, Codex, CodeRabbit) often each leave a dozen comments on the same diff. Some are real bugs, some are theoretical, some are already addressed in a later commit on the same PR, some directly contradict each other. Reading the comments without verification overestimates the agreement signal: three bots flagging similar-sounding findings can still all be wrong. The cost of a small `grep` or shell repro is far less than acting on a phantom bug or dismissing a real one. Applied during PR #3 review (2026-05-23/24): of ~25 surfaced findings across three bots, six survived empirical verification; the remaining ~19 were stale, theoretical, or in active disagreement.

**Approach:** For each claim that names a specific behavior (not a doc/style nit):

1. Open the cited file at the cited symbol on the current branch and read the actual code. PR comments reference an earlier commit; later commits often fix or relocate the code. CodeRabbit explicitly tags its own resolved findings with `✅ Addressed in commit <sha>` - skip those.
2. If the claim is "X happens when Y", build the smallest repro that exercises Y. A 5-line script, a `bin/<cli> --bad-flag`, a temp-directory experiment. Do not reason about whether the bug "would" trigger; trigger it. Examples that worked: a minimal Commander script with an async action that throws after `setTimeout` to verify the `parse` vs `parseAsync` claim; a `/tmp` directory with one of the non-`.gruff-ts.yaml` config names to verify the init precedence guard; `gruff-ts summary fixtures --format=garbage` to verify the silent-coercion claim.
3. When two agents contradict each other (e.g., one says "fail fast on unknown `--format`", another says "preserve permissive fallback"), the existing code already encodes a decision. Read the surrounding comment to find what the maintainer intended, then update either the code or the comment to match. Do not silently flip behavior just to satisfy one bot.
4. Bucket findings into `OBSERVED` (your own repro confirmed it), `THEORETICAL` (the bot's reasoning is correct but the threat model does not apply - e.g. TOCTOU on a single-user CLI write), `STALE` (already addressed in a later commit), `DISAGREE` (two bots contradict; resolve by reading code). Report the bucket and the reason explicitly. Lazy "agree with all" inflates noise; lazy "disagree with all" misses real bugs.

The repros for PR #3 took ~10 minutes total and produced concrete evidence to attach to each verdict, which is what the operator can actually act on.
