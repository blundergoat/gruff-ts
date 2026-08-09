---
category: artifact-evidence
last_reviewed: 2026-08-09
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
