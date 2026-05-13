---
category: verification
last_reviewed: 2026-05-14
---

# Verification lessons

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
