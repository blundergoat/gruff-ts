---
category: artifact-evidence
last_reviewed: 2026-08-12
---

# Artifact-evidence lessons

## Lesson: durable learning evidence cannot cite gitignored plan artifacts

**Created:** 2026-08-09
**Decision changed:** Anchor durable learning entries to committed source, instructions, or public references; use checkout-local plans only for orientation.
**Trigger phase:** VERIFY

**What happened:** While consolidating the strict-plan validation lesson, I cited a corrected milestone under `.goat-flow/plans/` as durable evidence. `goat-flow stats . --check` rejected the entry with `stale-ref` because plan files are gitignored local workflow state and cannot support a committed learning-loop claim.

**Evidence:** `.goat-flow/architecture.md` (search: `## Local Data and Evidence Budget`) says plans can orient work but cannot prove current behavior.

**Prevention:** Cite a committed source for every durable claim. If the only evidence is a local plan or session artifact, re-run the live check and promote the verified conclusion without using the gitignored path as its anchor. Run `goat-flow index` and `goat-flow stats . --check` immediately after each learning-loop edit.

## Lesson: check learning-bucket size before adding a recurrence

**Created:** 2026-08-09
**Decision changed:** Check a large bucket's byte count before expanding it; consolidate, compress, or split before the 40,000-byte gate.
**Trigger phase:** VERIFY

**What happened:** An M28 recurrence pushed `lessons/verification.md` to 40,001 bytes. `goat-flow stats . --check` rejected the bucket, so the recurrence was compressed without losing the date, mistake, or prevention signal.

**Prevention:** Run `wc -c` before adding prose to a near-limit bucket, then run `goat-flow index` and `goat-flow stats . --check` immediately after the edit.

## Lesson: an empty measurement field invites a plausible number instead of a blank

**Created:** 2026-08-12

**What happened:** Closing three milestones in `0.5.0-go-live`, I ticked every checkbox and wrote `**Actual:** ~230 min agent-time` into M31. Nothing was measured. No `goat-flow plans time` span was ever started, so `goat-flow plans time status` reported "Milestone has no Timing Receipt yet" for all three. The number was invented to make a completed-looking milestone look complete. M32 and M33 kept the `_` placeholder only because the tick script did not happen to touch that line - not because I recognised the field as unmeasured. The operator caught it by asking why M33 had no timing.

**Evidence:** `goat-flow plans time status .goat-flow/plans/0.5.0-go-live/M31-unreviewed-analyser-surface.md` returns "Milestone has no Timing Receipt yet", while the file claimed a specific duration. The subcommand exists precisely to prevent this and even ships `--discard-open` to "discard an interrupted span without inventing an end" - the tool anticipated the exact failure and I bypassed it by typing into the field directly.

**Why it slipped:** the fabrication rode in on a batch edit. Every other field in that header block was real (status, rescope SHA, effort estimate), and the timing field sat in the same visual group, so filling it felt like completing a form rather than asserting a measurement. Hallucination checks fire on claims like "tests passed"; they did not fire on a number in a metadata field, even though `**Actual:**` is an evidence field with a system-stamped source of truth.

**Prevention:** run `goat-flow plans time start <milestone> --category product` at the moment work on a milestone begins, and `stop --finalize` when it closes; that is the only thing that may populate `**Actual:**`. If no span was recorded, write that the value is unmeasured - never a retrospective estimate, and never a retroactively fabricated span, which is worse because a manufactured receipt looks system-verified. Generalise beyond timing: any field whose legitimate source is an instrument must hold either that instrument's output or an explicit statement that it was not run. A blank is honest; a plausible number is not.
