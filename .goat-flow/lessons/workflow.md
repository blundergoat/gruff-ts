---
category: workflow
last_reviewed: 2026-05-22
---

# Workflow lessons

## Lesson: never declare a release ready without auditing the active task folder
**Created:** 2026-05-22

**What happened:** Operator asked "is this project ready to ship 0.1 version now?" The agent checked `package.json` version, ran `npm run check` (127/127 pass), self-scanned with `./bin/gruff-ts analyse .` (score 100.0, 0 findings), inspected the tarball via `npm pack --dry-run`, verified rule count (111 across 11 pillars) and README/CHANGELOG/LICENSE presence, then answered "yes, ready to ship" with only a list of nice-to-haves. The operator then asked separately "are there any tasks left in `.goat-flow/tasks/0.1`?" - that folder contained `M38-css-metrics-and-todo-density-calibration.md` with `Status: proposed` (substantive new scope: CSS scanning + `docs.todo-density` decision) and `ISSUE-related-project-study.md` with `Status: human-verification-pending`. Neither blocker showed up in the green checks. The agent gave a ship-ready verdict without ever opening the project's own task ledger.

**Evidence:** `.goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md` line 3 (`Status: proposed`); `.goat-flow/tasks/0.1/ISSUE-related-project-study.md` line 3 (`Status: human-verification-pending` at the time). CLAUDE.md's Router Table explicitly lists `.goat-flow/tasks/` under workspace notes, and the SCOPE rule "MUST read relevant files before changes" - release-readiness is a project-state question, so the project's own task folder is relevant by definition.

**Prevention:** For any "is X ready / are we done / can we ship" question, before invoking build/test/lint/self-scan signals, list and grep status lines in `.goat-flow/tasks/<active-milestone>/`. Concretely: `grep -m1 -iE "^(status|state):" .goat-flow/tasks/<version>/*.md` and surface anything that is not `complete`, `superseded`, `shipped`, or explicitly deferred. Green CI is a necessary signal, not a sufficient one - the task ledger encodes intent that CI cannot see (proposed scope, human-pending signoffs, deliberately deferred work). Treat unaudited task folders as a red-flag the same way you'd treat untested code paths.
