---
category: fixtures
last_reviewed: 2026-08-11
---

# Fixture and test-data lessons

Lessons about the fixtures, baselines, and scenario files that scanner tests are built on.
Split out of `verification.md` on 2026-08-11 when that bucket passed the 40000-byte threshold.

## Lesson: self-scan new CLI fixtures before settling their test file

**Created:** 2026-06-03

**What happened:** During the `security.new-function` config regression, the first CLI test landed in
`src/cli.test.ts`, pushing that already-near-threshold file over `size.file-length`. Moving it to
`src/security-and-config.test.ts` cleared file length, but the changed-range self-scan then exposed
`security.process-exec` from a dynamic `execFileSync(join(REPO_ROOT, "bin/gruff-ts"), ...)` command
and `docs.fixture-purpose-missing` because the purpose comment was inside the test body instead of
leading the test declaration.

**Evidence:** `src/security-and-config.test.ts` (search: `CLI severity override keeps new Function below fail-on error`);
`src/fixture-purpose-rules.ts` (search: `function hasFixturePurposeComment`); `src/line-rules.ts`
(search: `function isFixedArgvProcessCallSegment`).

**Prevention:** Before closing a new CLI regression, run a changed-range gruff scan on the touched
test file. Put fixture-purpose comments directly above the `test(...)` declaration, prefer block
comments when multiple marker words matter, and use fixed literal command vectors such as
`execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), ...])` instead of making the executable path
itself dynamic.

## Lesson: positive scanner fixtures and repo self-scan do not prove false-positive safety

**Created:** 2026-06-03

**What happened:** The first close-out for `test-quality.static-analysis-redundant-test` had `npm run check` green and a repo self-scan with zero hits, but an independent QA pass built a minimal runtime-callable repro and found high-confidence false positives on `assert.equal(typeof handler, "function")` where `handler` came from a factory, and `plugin.activate` came from a loaded plugin. The implementation's positive fixtures proved the rule fired on shape-only assertions, but they did not prove the rule stayed quiet on the highest-traffic behavioral form of the same assertion syntax.

**Evidence:** `src/static-analysis-redundant-rules.ts` (search: `function typeofFunctionAssertions`) accepted any identifier/member operand as static evidence; `src/test-block-rules.test.ts` (search: `keeps runtime callable typeof assertions quiet`) is the regression shape that should have existed before close-out; the failing throwaway scan reported two `test-quality.static-analysis-redundant-test` findings for factory/plugin callable assertions before the guard was added.

**Prevention:** For every new scanner rule, add at least one adversarial false-positive fixture that uses the same syntax as the intended hit but with behavior-bearing data flow. A repo self-scan returning zero findings is not enough when the repo no longer contains the risky syntax class; build a throwaway repro for the candidate class the rule is meant to police.

## Lesson: when changing rule output, regenerate the baseline test scenario, do not edit findings inline

**Created:** 2026-05-10

`src/cli.test.ts` writes a fixture and asserts that specific `ruleId`s appear (`security.eval-call`, `size.parameter-count`, `test-quality.no-assertions`, `modernisation.public-property`). If you alter a rule's `ruleId`, threshold, or matcher, the fixture text - not the assertion list - is the part to expand: add a new bad pattern that triggers the renamed rule. Editing the assertion to "make the test pass" with the existing fixture defeats the test's purpose (proving the rule fires at all).

## Lesson: threshold fixtures must exceed the threshold they are proving

**Created:** 2026-05-13
**Updated:** 2026-08-11

**What happened:** The first high-entropy sensitive-data fixture initially used a 31-character secret-like value while the rule default required 32 characters, so the targeted test failed after implementation until the fixture value was corrected. A later SHA-512 non-candidate test split its value into two literals, but the second 38-character fragment independently crossed the entropy threshold. The focused test passed because the assembled integrity value was excluded; the repository self-scan still reported the fragment in the test source.

**Evidence:** `src/cli.test.ts` + `(search: "const secret =")` - the first-slice fixture owns the candidate value for `sensitive-data.high-entropy-string`; `src/sensitive-data-rules.test.ts` (search: `SHA512_INTEGRITY_FIXTURE_VALUE`) - every stored fragment is now shorter than the entropy scanner's 24-character candidate floor while their joined value retains the integrity shape.

**Prevention:** When adding threshold-backed rule fixtures, count or otherwise prove the fixture value crosses the threshold before treating a missing finding as an implementation bug. When an exclusion fixture is assembled to stay quiet under self-scan, prove both boundaries: the joined value must exercise the exclusion and every source literal must stay below the scanner's candidate floor.

## Lesson: anchor repetitive fixture patches before trusting cumulative coverage

**Created:** 2026-05-14

**What happened:** The cumulative rule-coverage test initially missed `test-quality.no-throw-only-test` because a patch matched the first `test("global mutation"` block in `src/cli.test.ts`, not the later cumulative fixture block that owns `expandedRuleIds`.

**Evidence:** `src/cli.test.ts` + `(search: "cumulative expanded fixture covers every new rule with unique fingerprints")`; the failing run of `node --import tsx --test src/cli.test.ts` reported `expected test-quality.no-throw-only-test`.

**Prevention:** When a fixture label appears more than once, patch or inspect around the owning test name first, then verify the new rule id appears in the cumulative fixture before rerunning the full gate.

## Lesson: rule-catalogue coverage fixtures must match scanner limits

**Created:** 2026-05-14

**What happened:** The descriptor self-test first failed for `design.god-function` because the catalogue fixture was not long and complex enough, then failed for `test-quality.magic-number-assertion` because the fixture used `expect(renderCatalogue().length).toBe(42)`, which exceeded the regex assertion matcher’s supported shape.

**Evidence:** `src/cli.test.ts` + `(search: "rule descriptors cover emitted rules and fixture-backed coverage")`; failing runs of `node --import tsx --test src/cli.test.ts` reported missing positive fixture coverage for those rule ids.

**Prevention:** For catalogue coverage, make each fixture intentionally boring and shaped exactly like the scanner pattern: simple variables for assertion arguments, deliberately long blocks for composite size/complexity rules, and no accidental symbol references that mask unused-import coverage.

## Lesson: a test-local fixture writer can hide a break in the real on-disk format

**Created:** 2026-08-10

**What happened:** Adding the match column to the hook stable identity broke `hook --baseline`
suppression for every finding that reports a column, and the whole baseline suite still passed. The
local `writeBaseline` helper in `src/hook-contract.test.ts` persists a `stableIdentity` field, so its
baselines matched by stored identity and never reached the recompute path. The production writer,
`writeBaseline` in `src/baseline.ts`, persists no such field, so a real baseline recomputes its
identity from the stored message and stopped matching the now column-bearing live finding.

**Evidence:** `src/hook-contract.test.ts` (search: `function writeBaseline`) writes `stableIdentity`;
`src/baseline.ts` (search: `function writeBaseline`) writes only fingerprint, ruleId, filePath, line,
symbol, and message. A worktree at the pre-change commit suppressed the finding; the patched tree
reported it.

**What to do instead:** When changing anything a persisted artifact is matched on, generate the
artifact with the real command (`analyse --generate-baseline`) and re-run the consumer against it.
A passing suite proves the helper's shape, not the format users actually have on disk. Compare
against a `git worktree` of the pre-change commit when the question is whether behaviour regressed.
