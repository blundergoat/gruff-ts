# ADR-018: process-exec severity is graded from evidence; no acknowledgement pragma

**Status:** Accepted
**Date:** 2026-08-04
**Author(s):** Claude, user
**Ticket/Context:** 2026-08 goat-flow false-positive report, Defect 4 (`security.process-exec` unclearable and mis-severitied).

## Context

`security.process-exec` fired at warning severity on every non-exempt child-process call, with the same message regardless of whether the call already was a fixed command vector with the shell disabled. The rule already computed the discriminating evidence (`callName`, `argumentSource`, `shellEnabled` in `src/process-exec-metadata.ts`) but did not use it. In projects that legitimately spawn subprocesses, the security pillar stayed permanently occupied by warnings the reviewer could not act on, which trains users to ignore the pillar - a worse security outcome than a graded rule.

The defect report suggested two remedies: grade severity from the metadata, and separately consider an inline acknowledgement pragma ("reviewed because ...") the rule could verify.

## Decision

1. Severity is graded in `src/line-rules.ts` (search: `function processExecGrade`):
   - warning only when the shell is enabled AND the command source is dynamic (`template`, `parameter`, `member`, `local-builder`, `unknown`);
   - advisory with a message naming what would make it dangerous when the shell is disabled AND the source is fixed (`literal`, `local-const`, `process-exec-path`);
   - advisory with the existing review prompt for everything in between.
   The descriptor keeps warning as its catalogue severity (the rule's ceiling), and `rules.<id>.severity` config overrides still apply uniformly through the central severity pass.
2. No acknowledgement pragma is added. The project's standing position is that findings stay visible rather than suppressed (same reasoning as the no-baseline preference): an in-source "reviewed" marker is a suppression surface that goes stale silently, invites copy-paste, and would need its own rule to audit. Graded advisory severity achieves the intended outcome - reviewed-shape calls stop failing warning gates while remaining visible in reports.

## Consequences

- Fixed-vector, shell-disabled findings change message, so their `stableIdentity` (message-derived because the rule emits no symbol) churns once; fingerprints and `gruff.baseline.v1` matching are unchanged because messages and severities are not hashed.
- `--fail-on warning` runs no longer fail on fixed-vector or shell-disabled-dynamic calls; `--fail-on advisory` behavior is unchanged.
- If a future consumer needs per-site acknowledgement, revisit with a verifiable mechanism (for example config-scoped path allowlists like the existing `allowlists.*` surfaces) rather than free-text pragmas.
