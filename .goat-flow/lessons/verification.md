---
category: verification
last_reviewed: 2026-05-17
---

# Verification lessons

## Lesson: benchmark workload labels need filesystem-safe temp names

**Created:** 2026-05-17

**What happened:** During M29 perf-harness verification, `./scripts/test-performance.sh --runs 1 --target fixtures/sample.ts --out /tmp/perf-spike.json` failed because the workload label `fixtures/sample.ts` was reused inside the temporary filename, creating an unintended nested path under `/tmp/gruff-perf-work-*`.

**Evidence:** `scripts/test-performance.sh` + `(search: "local cell_name=")` now sanitizes workload/config/format labels before building per-cell temp file paths.

**Prevention:** Any benchmark or report label that can contain `/`, spaces, or option-like prefixes must be converted to a filesystem slug before it is used as a path segment. Keep human labels in JSON/report fields; use sanitized names only for temp files.

## Lesson: source-scanning contract tests must follow refactors across helper contexts

**Created:** 2026-05-17

**What happened:** During self-scan cleanup, `npm run check` failed after threshold-backed rules were refactored to read thresholds through `context.config` instead of a direct `config` parameter. The analyzer behavior was intact, but the descriptor/config threshold contract test only searched for `threshold(config, ...)`, so it undercounted implemented thresholds until the regex was widened.

**Evidence:** `src/cli.test.ts` + `(search: "function thresholdUsages")`; the failing run reported missing implementation thresholds for `size.function-length`, `size.parameter-count`, `complexity.cyclomatic`, `complexity.cognitive`, and `complexity.npath`.

**Prevention:** When a contract test scans source text instead of calling a structured API, update its extractor in the same refactor that changes call shape. Prefer matching the semantic argument form, such as optional context prefixes, over one local variable spelling.

## Lesson: keep verification wrappers visible to the deny hook

**Created:** 2026-05-16

The local deny-dangerous hook blocks verification wrappers that obscure nested execution. During M14 verification, one `node` heredoc was blocked because JavaScript template-literal backticks looked like hidden command substitution, and a later `node -e` wrapper around `spawnSync("./bin/gruff-ts", ...)` was blocked because the shell-executing primitive hid the real command from hook review.

Run the target command directly, save output to `/tmp` if parsing is needed, then use a non-spawning parser command against that file.

## Lesson: run `npm run check` after every `src/cli.ts` edit, not just before commit

**Created:** 2026-05-10

`src/cli.ts` is the entire runtime. It compiles under `strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes`, which means a small change (e.g., adding a property to `Finding` without making it optional, or indexing an array without a bounds check) routinely breaks `tsc` even when the diff "looks fine". `npm run check` runs `tsc --noEmit && npm test` — both are needed, both are fast (sub-second `tsc`, ~150ms test). Pasting the literal "0 fail" line from the test runner is the verification artifact; "looks correct" is not.

## Lesson: when changing rule output, regenerate the baseline test scenario, do not edit findings inline

**Created:** 2026-05-10

`src/cli.test.ts` writes a fixture and asserts that specific `ruleId`s appear (`security.eval-call`, `size.parameter-count`, `test-quality.no-assertions`, `modernisation.public-property`). If you alter a rule's `ruleId`, threshold, or matcher, the fixture text — not the assertion list — is the part to expand: add a new bad pattern that triggers the renamed rule. Editing the assertion to "make the test pass" with the existing fixture defeats the test's purpose (proving the rule fires at all).

## Lesson: the deny-dangerous hook treats piping into `python3 -c`/`node -e` as blocked

**Created:** 2026-05-10

`.claude/hooks/deny-dangerous.sh` blocks "pipe to interpreter" patterns. When summarising audit JSON or processing tool output with a one-liner, write to `/tmp/<file>.json` first and then run the interpreter against the file path. Trying to retry the same pipeline after a block triggers the same hook — the lesson is to switch to a file-based intermediate, not to keep retrying.

## Lesson: threshold fixtures must exceed the threshold they are proving

**Created:** 2026-05-13

**What happened:** The M01 high-entropy sensitive-data fixture initially used a 31-character secret-like value while the rule default required 32 characters, so the targeted test failed after implementation until the fixture value was corrected.

**Evidence:** `src/cli.test.ts` + `(search: "const secret =")` - the first-slice fixture owns the candidate value for `sensitive-data.high-entropy-string`.

**Prevention:** When adding threshold-backed rule fixtures, count or otherwise prove the fixture value crosses the threshold before treating a missing finding as an implementation bug.

## Lesson: self-analysis smoke catches scanner regressions that fixtures miss

**Created:** 2026-05-13

**What happened:** M02 unit fixtures passed, but `./bin/gruff-ts analyse src --format=json --fail-on=none --no-config` exposed a `parse-error` in `src/cli.ts` and false positives where control statements were treated as function blocks.

**Evidence:** `src/cli.ts` + `(search: "function parseDiagnostics")` and `(search: "function functionBlocks")`; `src/cli.test.ts` now includes clean control-flow coverage and delimiter-looking literal coverage.

**Prevention:** For regex-heavy rule work, run the analyzer against `src` before declaring the milestone gate done, and check the output for diagnostics plus impossible symbols such as `if`, `switch`, or `catch`.

## Lesson: inspect smoke output, not just exit status

**Created:** 2026-05-13

**What happened:** M03 tests and the HTML smoke command exited 0, but the first HTML inspection showed obvious sensitive-data false positives on `package-lock.json` SRI hashes and the detector string `OPENAI_API_KEY` inside `src/cli.ts`.

**Evidence:** `src/cli.ts` + `(search: "function isHighEntropySecretCandidate")` and `(search: "sensitive-data.api-key-pattern")`; `src/cli.test.ts` now includes `risk expansion ignores package integrity hashes`.

**Prevention:** When adding source-text detectors, inspect a small slice of CLI smoke output for noisy rule ids and filenames. Exit code 0 only proves the command ran; it does not prove the detector is useful.

## Lesson: do not mutate the scanned tree during determinism checks

**Created:** 2026-05-13

**What happened:** The M04 determinism smoke was first run in parallel with baseline generation. The baseline command created `.goat-flow/scratchpad/gruff-ts-expanded-baseline.json` between the two `analyse .` runs, so the comparison reported one extra finding even though the analyzer output was deterministic for a stable tree.

**Evidence:** M04 verification commands; rerunning `./bin/gruff-ts analyse . --format=json --fail-on=none --no-config` twice after baseline generation completed produced identical reports after ignoring `run.generatedAt`.

**Prevention:** Run determinism checks by themselves, or generate any scratchpad/baseline artifacts before the first compared run. Parallel verification is fine only when none of the commands write into paths being scanned.

## Lesson: anchor repetitive fixture patches before trusting cumulative coverage

**Created:** 2026-05-14

**What happened:** The M07 cumulative rule-coverage test initially missed `test-quality.no-throw-only-test` because a patch matched the first `test("global mutation"` block in `src/cli.test.ts`, not the later cumulative fixture block that owns `expandedRuleIds`.

**Evidence:** `src/cli.test.ts` + `(search: "cumulative expanded fixture covers every new rule with unique fingerprints")`; the failing run of `node --import tsx --test src/cli.test.ts` reported `expected test-quality.no-throw-only-test`.

**Prevention:** When a fixture label appears more than once, patch or inspect around the owning test name first, then verify the new rule id appears in the cumulative fixture before rerunning the full gate.

## Lesson: rule-catalogue coverage fixtures must match scanner limits

**Created:** 2026-05-14

**What happened:** The M08 descriptor self-test first failed for `design.god-function` because the catalogue fixture was not long and complex enough, then failed for `test-quality.magic-number-assertion` because the fixture used `expect(renderCatalogue().length).toBe(42)`, which exceeded the regex assertion matcher’s supported shape.

**Evidence:** `src/cli.test.ts` + `(search: "rule descriptors cover emitted rules and fixture-backed coverage")`; failing runs of `node --import tsx --test src/cli.test.ts` reported missing positive fixture coverage for those rule ids.

**Prevention:** For catalogue coverage, make each fixture intentionally boring and shaped exactly like the scanner pattern: simple variables for assertion arguments, deliberately long blocks for composite size/complexity rules, and no accidental symbol references that mask unused-import coverage.

## Lesson: restart browser-visible servers after source edits

**Created:** 2026-05-15

**What happened:** During M13 dashboard parity verification, screenshots were first captured against a dashboard server that had been started before the final `src/cli.ts` CSS tweak. The evidence was structurally valid, but it did not prove the current source until the server was stopped, restarted, and the captures were rerun.

**Evidence:** `src/cli.ts` + `(search: "function startDashboard")`; `.goat-flow/scratchpad/dashboard-parity/capture_m13.py` captured the current-source screenshots only after the dashboard was restarted on `127.0.0.1:8877`.

**Prevention:** For browser-visible code, restart any long-running dev server after every source edit before taking final screenshots or claiming visual verification.

## Lesson: wait for post-interaction UI state, not just selectors

**Created:** 2026-05-15

**What happened:** The M13 screenshot script initially clicked dashboard Refresh and then read `[data-scan-status]` before the iframe `load` handler had settled, producing a false failure with status `Scanning`.

**Evidence:** `.goat-flow/scratchpad/dashboard-parity/capture_m13.py` + `(search: "wait_for_function")`; the corrected script waits until the status text is `Ready` before asserting refresh completion.

**Prevention:** Browser evidence scripts should wait for the user-visible postcondition after an interaction, not only for a reused selector or iframe to exist.

## Lesson: update positive fixtures when raising rule thresholds

**Created:** 2026-05-15

**What happened:** The `test-quality.setup-bloat` default moved from 8 to 12 setup lines, but two positive fixtures still used only nine setup statements. `npm run check` correctly failed until the fixtures were expanded past the new threshold.

**Evidence:** `src/cli.test.ts` + `(search: "test(\"setup bloat\"")`; failing test names were `risk expansion finds scoped test-quality rules` and `cumulative expanded fixture covers every new rule with unique fingerprints`.

**Prevention:** When changing a default threshold, update every positive fixture owned by that rule in the same patch and count the candidate lines against the new default before rerunning the full gate.

## Lesson: verification commands must account for local artifact directories

**Created:** 2026-05-16

**What happened:** During M15, the clone inventory command originally listed every directory under `.goat-flow/scratchpad/related-projects`, but the milestone itself creates `.goat-flow/scratchpad/related-projects/study`, so the command no longer proved "exactly the ten cloned projects" after the first artifact write.

**Evidence:** `.goat-flow/tasks/0.1/M15-related-project-study-intake.md` + `(search: "find .goat-flow/scratchpad/related-projects")` - the verified command now excludes `study`; commands that grep ignored `.goat-flow` artifacts use `rg -uuu`.

**Prevention:** When a milestone writes verification artifacts inside the tree being enumerated, either exclude the artifact directory in the proof command or write artifacts outside the enumerated scope. Use `rg -uuu` for checks that intentionally inspect gitignored `.goat-flow/tasks` or `.goat-flow/scratchpad` files.

## Lesson: widen typed test maps when one list has documented exceptions

**Created:** 2026-05-16

**What happened:** During M21, the first `npm run check` failed in `tsc` because a rule-quality self-check built one `Map` from doctrine entries and another from exception entries. TypeScript inferred each `Map` with only its literal key union, so looking up the full risky-rule union failed for the exception-only rule.

**Evidence:** `src/cli.test.ts` + `(search: "rule quality doctrine covers risky scanner descriptors")`; the failing command reported `sensitive-data.api-key-pattern` was not assignable to the doctrine-only map key union.

**Prevention:** For test metadata split across coverage and exception lists, widen lookup maps to `Map<string, ...>` before iterating the combined rule-id list. This preserves useful literal data in the source arrays while keeping strict TypeScript from rejecting intentional exception-only entries.
