---
category: workflow
last_reviewed: 2026-05-26
---

# Workflow lessons

## Lesson: milestone close-out must compare self-scan delta, not just `npm run check` pass count

**Created:** 2026-05-26

**What happened:** M01 and M02 both passed `npm run check` cleanly and shipped lock-in tests. The "Verification" gates I followed in each milestone file (run check, paste pass line) reported green. But a baseline self-scan taken BEFORE M01 had 1 finding total; the same scan AFTER M01+M02 reported 11 findings. Ten of those came from the new code I wrote - high NPath in the new functions, large fixtures without purpose comments, self-referential rule firing on rule-descriptor prose, etc. The check passed because TESTS passed; the project's own rule signal got materially worse and the green check missed it.

**Evidence:** `/tmp/gruff-ts-baseline-pre.json` (1 finding pre-M01) vs `/tmp/gruff-ts-self-scan-m02.json` (11 findings post-M02). The new findings tracked back to my own diff: `complexity.npath` on `analyseUnreachable` (NPath 512) and `forOfBodyLineSpan` (NPath 256), `naming.boolean-prefix` on a new local `consequentPending`, `docs.todo-without-tracking` on rule-descriptor prose that mentioned `TODO`/`FIXME`, `docs.fixture-purpose-missing` on the new lock-in test fixtures.

**Prevention:** Before declaring a milestone complete, run `./bin/gruff-ts analyse src --format=json --fail-on=none > /tmp/<milestone>-after.json` and compare against the corresponding pre-milestone scan. The delta surfaces "your new code introduces N new findings" in a way `npm test` cannot. If the delta has self-introduced findings the project would itself flag, do at least the trivial cleanups (renames, comment rephrasings) before close-out. Complexity and large-fixture findings are signal worth either accepting (with a follow-up note) or addressing in a dedicated refactor pass - never both ignoring them and claiming the milestone is clean.

## Lesson: tick `- [ ]` checkboxes inside milestone files as work lands, do not just stamp `Status: complete`

**Created:** 2026-05-27

**What happened:** Closed out the minimumSeverity track by setting `Status: complete (2026-05-27)` at the top of `.goat-flow/tasks/0.1.3/M01-M03 + ISSUE.md`. Every `- [ ]` checkbox inside those files - the Tasks blocks, Testing Gate sections, How checklists in ISSUE.md - was left unticked. Surfaced the work to the operator as "all done," then they opened the files and saw four documents full of `- [ ]` with a top-line `Status: complete` slapped on. Their reaction: "i call bullshit on any of that being completed."

**Evidence:** `.goat-flow/tasks/0.1.3/M01-config-schema-and-cli-wiring.md` line 3 said `Status: complete (2026-05-27)` while lines 116-249 (Tasks section) and 280-307 (Testing Gate) still had every checkbox empty. Same shape for M02, M03, and the parent ISSUE.md's `How` list. The code/test/doc work had actually landed - `npm run check` was green, preflight was clean - but the tracking artifacts inside the task folder claimed nothing was done.

**Prevention:** Before flipping a milestone file's top-line `Status:` to `complete`, open the file and walk every `- [ ]` line. For each one the implementation actually delivered, flip to `- [x]`. For items deferred during execution, leave unticked and add a deferral note nearby (see `.goat-flow/tasks/0.1.2/M03-test-quality-rule-precision.md` for the existing pattern). Apply the same to ISSUE.md `How` checklists. Top-line status without per-task ticks reads as fraud even when the underlying work landed. Standing rule from the operator: "TICK OFF FUCKING CHECKBOX TASKS AS YOU FUCKING COMPLETE THEM."

## Lesson: moving milestone files across folders requires a cross-reference sweep, not just `git mv`

**Created:** 2026-05-27

**What happened:** Asked to move `.goat-flow/tasks/0.1.3/{ISSUE,M01,M02,M03}.md` into `.goat-flow/tasks/0.1.2/` plus delete `M09-rule-visibility-tier.md`. The moves themselves were trivial (`mv` + `rmdir`), but the files contained internal cross-references (`M01 wired the config-driven defaults`, `M02 owns this`, `M03 is the verification sweep`, `[M01 - ...](M01-...md)` markdown links, `pre-0.1.3 baseline`, `0.1.3 task set`, `Status: shipped as gruff-ts 0.1.4`) and external cross-references (ADR-004's `**Ticket/Context:** .goat-flow/tasks/0.1.3/ISSUE.md`, CHANGELOG bullets mentioning `M09 deferred`, the parent `ISSUE.md`'s release-line allocation table with `→ 0.1.3` annotations on every row). On top of that the files had a `gruff-go's 0.1.2 ISSUE.md, M01 (FailThreshold type), M02 (config schema)` reference that was about a different repo and must NOT be renumbered. Forgetting any one class of these leaves a quietly-broken task folder where milestone files claim to be in 0.1.2 but their prose still says 0.1.3 / M01 / M02.

**Evidence:** After the first `mv` + `rmdir` pass, the moved files still had:

- `M01-config-schema-and-cli-wiring.md` line 1 header: `# M01 -` (should be `# M10`).
- `M02-init-preservation-and-docs.md` lines 9/24/30/42/76/93/292/300: prose "M01 wired", "as M01 left it", "complete (per M01)", "M03 owns", etc.
- `M03-verification-and-dogfood.md` ~30 internal cross-refs to M01/M02 of the same track.
- `ISSUE.md` lines 127-132 with markdown links `[M01 - ...](M01-...md)` to the renamed files.
- ADR-004 line 6: `**Ticket/Context:** .goat-flow/tasks/0.1.3/ISSUE.md`.
- Parent `0.1.2/ISSUE.md` had a "Release-line allocation" table claiming everything except M01 was → 0.1.3 or 0.1.4, plus the `Hard constraints` section pointing at `.goat-flow/tasks/0.1.3/`.
- `CHANGELOG.md` mentioned "M09 deferred" though M09 had just been deleted.
- The `gruff-go's 0.1.2 ISSUE.md, M01 (FailThreshold type)` reference in `ISSUE-minimumSeverity.md` line 45 looks like an M01 self-reference but is actually about gruff-go's port - touching it would have been wrong.

**Prevention:** When moving milestone files across version folders or renaming them within a folder, run this checklist BEFORE declaring the move done:

1. `grep -rn "<old-path>"` across `CHANGELOG.md`, `docs/`, `README.md`, `.goat-flow/decisions/`, `src/`, and other task folders. Every hit needs updating.
2. `grep -n "M0[123]\|M0[456]"` (or whatever the renumbered range is) inside each moved file. Update the prose references that name same-track milestones; leave cross-repo references alone (look for paths like `gruff-go/`, `gruff-rs/`, etc.).
3. `grep -n "old-version\b"` (e.g. `0\.1\.3`) inside the moved files. Replace where it refers to the milestone's own version, leave where it refers to a historical "pre-X" baseline.
4. Update markdown-link targets (`[M01 - ...](M01-...md)` becomes `[M10 - ...](M10-...md)`).
5. Update the file header (`# M01 -` -> `# M10 -`).
6. If a milestone was deleted (not just renumbered), grep for its name in CHANGELOG / docs / parent ISSUE and remove or rephrase those mentions.
7. After all edits, re-run `grep -rn "<old-path>\|<old-milestone-id>"` to confirm zero stray references.

A `git mv` alone is not a move - it's the start of one. The cross-reference sweep is what makes the move correct.



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
