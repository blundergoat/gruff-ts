---
category: smoke-verification
last_reviewed: 2026-08-07
---

# Smoke verification lessons

## Lesson: performance-plan commands must exercise the helper's comparison mode

**Created:** 2026-07-11

**What happened:** During the 0.5.0 plan audit, M07 was first rewritten with a 15% parser-performance gate but its Verification section named only `bash scripts/test-performance.sh`. The helper's default mode records one current run; it cannot enforce any regression percentage unless a matrix baseline is written first and then supplied with `--baseline` plus `--fail-on-regression`.

**Evidence:** `scripts/test-performance.sh` (search: `--write-baseline requires --matrix`) and (search: `--fail-on-regression requires --baseline`) define the supported before/after comparison commands; the original milestone was local coordination state rather than a durable evidence anchor.

**Prevention:** Before putting a helper command in a plan exit criterion, read its `--help` and validation branches, then spell out every state-producing and state-consuming invocation. A percentage in prose is not a gate unless the cited command receives a baseline and exits non-zero on that percentage.

## Lesson: restart browser-visible servers after source edits

**Created:** 2026-05-15

**What happened:** During dashboard parity verification, screenshots were first captured against a dashboard server that had been started before the final `src/cli.ts` CSS tweak. The evidence was structurally valid, but it did not prove the current source until the server was stopped, restarted, and the captures were rerun.

**Evidence:** `src/cli.ts` + `(search: "function startDashboard")`; the dashboard-parity capture script in `.goat-flow/scratchpad/dashboard-parity/` captured the current-source screenshots only after the dashboard was restarted on `127.0.0.1:8877`.

**Prevention:** For browser-visible code, restart any long-running dev server after every source edit before taking final screenshots or claiming visual verification.

## Lesson: wait for post-interaction UI state, not just selectors

**Created:** 2026-05-15

**What happened:** The dashboard-parity screenshot script initially clicked dashboard Refresh and then read `[data-scan-status]` before the iframe `load` handler had settled, producing a false failure with status `Scanning`.

**Evidence:** The capture script under `.goat-flow/scratchpad/dashboard-parity/` (search: `wait_for_function`); the corrected script waits until the status text is `Ready` before asserting refresh completion.

**Prevention:** Browser evidence scripts should wait for the user-visible postcondition after an interaction, not only for a reused selector or iframe to exist.

## Lesson: update positive fixtures when raising rule thresholds

**Created:** 2026-05-15

**What happened:** The `test-quality.setup-bloat` default moved from 8 to 12 setup lines, but two positive fixtures still used only nine setup statements. `npm run check` correctly failed until the fixtures were expanded past the new threshold.

**Evidence:** `src/cli.test.ts` + `(search: "test(\"setup bloat\"")`; failing test names were `risk expansion finds scoped test-quality rules` and `cumulative expanded fixture covers every new rule with unique fingerprints`.

**Prevention:** When changing a default threshold, update every positive fixture owned by that rule in the same patch and count the candidate lines against the new default before rerunning the full gate.

## Lesson: verification commands must account for local artifact directories

**Created:** 2026-05-16

**What happened:** During the related-projects intake work, the clone inventory command originally listed every directory under `.goat-flow/scratchpad/related-projects`, but the task itself created `.goat-flow/scratchpad/related-projects/study`, so the command no longer proved "exactly the ten cloned projects" after the first artifact write.

**Evidence:** The verified command now excludes `study`; commands that grep ignored `.goat-flow` artifacts use `rg -uuu`.

**Prevention:** When a task writes verification artifacts inside the tree being enumerated, either exclude the artifact directory in the proof command or write artifacts outside the enumerated scope. Use `rg -uuu` for checks that intentionally inspect gitignored `.goat-flow/plans` or `.goat-flow/scratchpad` files.

## Lesson: widen typed test maps when one list has documented exceptions

**Created:** 2026-05-16

**What happened:** During rule-quality doctrine work, the first `npm run check` failed in `tsc` because a rule-quality self-check built one `Map` from doctrine entries and another from exception entries. TypeScript inferred each `Map` with only its literal key union, so looking up the full risky-rule union failed for the exception-only rule.

**Evidence:** `src/cli.test.ts` + `(search: "rule quality doctrine covers risky scanner descriptors")`; the failing command reported `sensitive-data.api-key-pattern` was not assignable to the doctrine-only map key union.

**Prevention:** For test metadata split across coverage and exception lists, widen lookup maps to `Map<string, ...>` before iterating the combined rule-id list. This preserves useful literal data in the source arrays while keeping strict TypeScript from rejecting intentional exception-only entries.

## Lesson: keep fixture strings compact when fixing self-scan import noise

**Created:** 2026-05-21

**What happened:** While clearing an unused-import self-scan finding, expanding a template fixture into an array of string lines made the surrounding test exceed `test-quality.setup-bloat` and re-triggered `docs.fixture-purpose-missing`.

**Evidence:** `src/docs-comment-rules.test.ts` + `(search: "comment quality requires rationale for non-TypeScript suppressions")`; the corrected fixture uses one concatenated source expression so `TS_IGNORE_DIRECTIVE` is visible to import analysis without adding setup lines.

**Prevention:** When a fixture token must be visible outside a template literal, prefer a compact concatenated expression over line-array builders unless the test already has setup budget and a nearby fixture-purpose comment.

## Lesson: self-scan CLI onboarding changes before close-out

**Created:** 2026-05-24

**What happened:** During baseline-onboarding work, `npm run check` passed but `./bin/gruff-ts summary . --fail-on=none --no-baseline` exposed new gruff findings from newly added helper functions and a CLI test that used a dynamic binary path for `execFileSync`.

**Evidence:** `src/report-renderers.ts` + `(search: "function summaryBaselineLine")`; `src/cli-surfaces.test.ts` + `(search: "summary CLI reports generated and applied baseline metadata")` - the corrected version documents the baseline summary contract and uses the fixed local `./bin/gruff-ts` command vector.

**Prevention:** For scanner-facing CLI or renderer changes, run a self-scan after the normal test gate, then remove avoidable new findings before closing. In CLI tests, prefer fixed local command vectors when possible so process-exec findings remain focused on dynamic commands.

## Lesson: baseline smoke tests must keep project root stable

**Created:** 2026-05-24

**What happened:** A manual baseline smoke generated `gruff-baseline.json` from the repository cwd against an absolute `/tmp/.../sample.ts`, then tried to auto-apply it from the temp project cwd. Default baseline application appeared to fail because the finding `filePath` identity changed from a repo-relative temp path to `sample.ts`.

**Evidence:** `src/baseline.ts` + `(search: "function applyBaseline")`; `src/analyser.ts` + `(search: "function selectedBaseline")` - baseline matching includes `(fingerprint, ruleId, filePath)`, and default baseline discovery is rooted at the current project root.

**Prevention:** Generate and apply baseline smoke artifacts from the same project root. If testing absolute path operands, assert that changed display paths intentionally do not match the baseline.

## Lesson: ground-truth a throwaway when a test result looks impossible (or the harness drops its output)

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED (M25 AST-flow slice)

During the M25 AST-flow slice, `npm test` reported five failing security-flow tests whose failures were logically impossible from reading the code (a negative case with no sink "firing" a filesystem finding). Two compounding causes: (1) a real bug - an AST cache keyed by `SourceFile` identity returned the first test's parse for every later test that reused the shared `fileStub` (see the footgun "caching a parsed AST by SourceFile identity ..."); (2) the tool channel was intermittently dropping or lagging command output, so TAP summaries arrived stale or not at all.

What worked: a tiny throwaway script under `/tmp` that imported the rule function and printed the actual findings per input. Its byte-identical output across six different inputs pinpointed the stale-cache bug at once - something the laggy TAP stream never made clear.

Takeaways: (1) when a test result contradicts a careful read of the code, get ground truth by printing actual values from a minimal harness before "fixing" the rule - the cause is often shared or aliased state, not the logic. (2) Do not thrash re-issuing the same command when the output channel is dropping results; one clean ground-truth probe beats ten dropped re-runs. (3) The root cause was an unrequested cache abstraction - prefer the simplest thing that works (CLAUDE.md: "No new abstractions ... beyond what was asked").
