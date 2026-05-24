---
category: workflow
last_reviewed: 2026-05-24
---

# Workflow lessons

## Lesson: review pre-existing `M <file>` diffs before editing the same file
**Created:** 2026-05-24

**What happened:** Session started with `M .gruff-ts.yaml` in `gitStatus`. The agent read the file at its current state, made unrelated edits (deleted two rule blocks plus an `abbreviationDenylist` comment), ran `npm run check` clean, and reported done. The user then committed the work and discovered that `paths.ignore` had silently lost six curated entries (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`). The root cause was a prior `gruff-ts init --force` run that regenerated the YAML from defaults BEFORE the session started; the agent never ran `git diff -- .gruff-ts.yaml` against `HEAD` to see what had already been lost, and let the destruction ride into the user's commit.

**Evidence:** Git log shows the user's commit `bf37f5c` ("feat: rename 'waste' pillar to 'maintainability'") replacing `paths.ignore` with `ignore: []`. The agent's first read of `.gruff-ts.yaml` showed `ignore: []` already in place, while `git show HEAD:.gruff-ts.yaml` still had the curated list. `M .gruff-ts.yaml` in the session-start `gitStatus` was the only warning sign, and the agent ignored it.

**Prevention:** When a session begins with a user-curated config (`*.yaml`, `*.toml`, `package.json`, `tsconfig.json`, `.gruff-ts.yaml`, …) showing `M` in `gitStatus`, the FIRST action before editing that file is `git diff -- <path>` against `HEAD`. If the diff shows entries being deleted from a sequence or values being reset, surface that to the user BEFORE applying your own edits - do not let it ride. The cost is one tool call; the alternative is silently bundling a customisation loss into a user commit. Tooling that regenerates config from defaults (init/scaffold/migrate flows) is the dominant cause of this pattern.

## Lesson: never declare a release ready without auditing the active task folder
**Created:** 2026-05-22

**What happened:** Operator asked "is this project ready to ship 0.1 version now?" The agent checked `package.json` version, ran `npm run check` (127/127 pass), self-scanned with `./bin/gruff-ts analyse .` (score 100.0, 0 findings), inspected the tarball via `npm pack --dry-run`, verified rule count (111 across 11 pillars) and README/CHANGELOG/LICENSE presence, then answered "yes, ready to ship" with only a list of nice-to-haves. The operator then asked separately "are there any tasks left in `.goat-flow/tasks/0.1`?" - that folder contained `M38-css-metrics-and-todo-density-calibration.md` with `Status: proposed` (substantive new scope: CSS scanning + `docs.todo-density` decision) and `ISSUE-related-project-study.md` with `Status: human-verification-pending`. Neither blocker showed up in the green checks. The agent gave a ship-ready verdict without ever opening the project's own task ledger.

**Evidence:** `.goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md` line 3 (`Status: proposed`); `.goat-flow/tasks/0.1/ISSUE-related-project-study.md` line 3 (`Status: human-verification-pending` at the time). CLAUDE.md's Router Table explicitly lists `.goat-flow/tasks/` under workspace notes, and the SCOPE rule "MUST read relevant files before changes" - release-readiness is a project-state question, so the project's own task folder is relevant by definition.

**Prevention:** For any "is X ready / are we done / can we ship" question, before invoking build/test/lint/self-scan signals, list and grep status lines in `.goat-flow/tasks/<active-milestone>/`. Concretely: `grep -m1 -iE "^(status|state):" .goat-flow/tasks/<version>/*.md` and surface anything that is not `complete`, `superseded`, `shipped`, or explicitly deferred. Green CI is a necessary signal, not a sufficient one - the task ledger encodes intent that CI cannot see (proposed scope, human-pending signoffs, deliberately deferred work). Treat unaudited task folders as a red-flag the same way you'd treat untested code paths.
