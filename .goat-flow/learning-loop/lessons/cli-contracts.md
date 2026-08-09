---
category: cli-contracts
last_reviewed: 2026-08-09
---

# CLI contract lessons

## Lesson: validate flags against the exact subcommand

**Created:** 2026-08-09
**Decision changed:** Run the target subcommand's `--help` before committing an integration-test command; do not copy a sibling command's flags.
**Trigger phase:** ACT

**What happened:** The M26 hook regression copied `--changed-scope symbol` from the `analyse` command. The scoped integration run failed with `unknown option '--changed-scope'`: hook mode fixes changed-region attribution to symbol scope internally and does not expose that option.

**Evidence:** `src/cli-program.ts` (search: `function registerHookCommand`) registers the hook flags without `--changed-scope`; the same file (search: `function hookScopedOptions`) sets `changedScope: "symbol"` before normalization.

**Prevention:** Verify flags against `<binary> <subcommand> --help` or the live command registration before writing a subprocess fixture. Treat options on sibling subcommands as unrelated until the target surface proves otherwise.

## Lesson: `plans check` validates a directory, not one milestone file

**Created:** 2026-08-09
**Decision changed:** Pass the active plan directory to `goat-flow plans check`; attribute errors by filename when legacy sibling milestones keep the directory red.
**Trigger phase:** VERIFY

**What happened:** Before moving M27 to its testing gate, I passed its Markdown file to `goat-flow plans check ... --strict`. The command exited 2 with `ENOTDIR` because `plans check` scans a directory. The corrected directory-level run showed no M27 error while surfacing known strict-format errors in legacy milestones.

**Evidence:** `.agents/skills/goat-plan/references/milestone-examples.md` (search: `goat-flow plans check .goat-flow/plans/<active> --strict`) and the CLI help examples both pass a plan directory.

**Prevention:** Run strict validation against the active plan directory. When legacy siblings keep it nonzero, inspect the filename-prefixed errors and report the target milestone's error count separately from the directory result.

## Lesson: `plans time start` requires an active milestone status

**Created:** 2026-08-09
**Decision changed:** Validate the pending transition, set the milestone to `in-progress`, then start its timing receipt immediately before product reads.
**Trigger phase:** ACT

**What happened:** M28 attempted to start timing while its status was still `not-started`. The CLI exited 2 because timing starts require exactly one rendered status set to `in-progress` or `testing-gate`. The milestone transitioned only after its pre-transition strict check, and timing then started successfully, but the receipt cannot cover the earlier Step 0 work.

**Prevention:** Run strict validation before activation, apply the approved `in-progress` transition, and invoke `plans time start` as the next command. If earlier work already occurred, classify the final Actual as incomplete or retrospective instead of presenting the partial receipt as a complete measurement.
