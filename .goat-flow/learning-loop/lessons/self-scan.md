---
category: self-scan
last_reviewed: 2026-10-03
---

# Self-scan lessons

**Scope:** lessons about running gruff-ts on its own source (the `--fail-on=advisory` self-scan and its dogfood config); general check discipline stays in `verification.md`.
Split out of `verification.md` on 2026-10-03 when that bucket came within 102 bytes of the 40000-byte threshold.

## Lesson: converting the dogfood config to a profile breaks rule-enumeration contract tests

**Created:** 2026-05-31

**What happened:** After replacing the repo `.gruff-ts.yaml`'s flat 120-rule block with `profile: recommended` (the named-profiles dogfood step), `npm run check` went from 274/274 to 3 failures. Three contract tests grepped the yaml TEXT for a per-rule entry: `naming-rules.test.ts` (search: `naming rule pack catalogue coverage`), and `rule-catalogue.test.ts` (search: `documentation catalogue covers comment rule pack` and `thresholds and options match implementation`). They encoded the exact manual enumeration that profiles are designed to eliminate.

**Evidence:** the failing assertions were `missing yaml entry for naming.class-file-mismatch`, `missing config entry for docs.fixture-purpose-missing`, and a `Map(0)` vs `Map(10)` threshold mismatch from `yamlThresholdDefaults`. The fix retargeted all three to load the effective config (`loadConfig(cwd(), ...)` then `ruleEnabled`/`threshold`/`ruleSeverity`) instead of grepping yaml text, which is robust whether the config enumerates rules or names a profile, and deleted the now-dead `yamlThresholdDefaults`/`yamlSeverityDefaults`/`yamlOptionDefaults` helpers.

**Prevention:** Before converting a project's shipped config to a profile, grep the test suite for tests that read `.gruff-ts.yaml` as TEXT (`readFileSync(".gruff-ts.yaml"`, `configSource.includes`, yaml-threshold parsers). Retarget them to assert against the loaded `Config` (style-agnostic) in the same change. The sibling gruff ports (go/rs/py/php) will hit the identical break when they add profiles.

## Lesson: self-scan freshly added regression tests before closing

**Created:** 2026-05-31
**Incident count:** 2
**Latest occurrence:** 2026-10-03

**What happened:** The normal `npm run check` gate passed after the rubric-calibration tests were added, but the follow-up gruff self-scan found a `test-quality.magic-number-assertion` in the new regression test itself. The test was behaviorally correct, but still taught future agents a noisy pattern until the expected score was named as a contract constant.

**Evidence:** `src/m06-rubric-refinements.test.ts` + `(search: "EXPECTED_CLUSTER_COMPOSITE_SCORE")`; the fresh scan command `./bin/gruff-ts analyse . --format=json --fail-on=none` later reported `total=0` from `/tmp/gruff_ts_double_check_1304802.json`.

**Prevention:** After adding or moving regression tests for analyzer rules, run the analyzer over the repo as well as `npm run check`. Treat findings in new test files as part of the change, not as harmless test-only noise; use named constants or fixture comments when the numeric or structural value is the documented contract.

**Recurrence 2026-10-03:** The schema-version gate added to `src/release-truth.test.ts` passed its focused run, but the preflight self-scan then flagged a generic `value` identifier and a bare `5` family count. Naming the field and asserting against `PUBLIC_OUTPUT_FAMILIES` (`src/release-truth.test.ts`, search: `const PUBLIC_OUTPUT_FAMILIES`) cleared both and made the assertion stricter.

## Lesson: self-scan comment fixes need context-marker words

**Created:** 2026-05-31

**What happened:** A first self-scan cleanup added leading comments and removed most findings, but the follow-up scan still reported context-doc gaps because the comments did not include the rule's expected contract, throws, or side-effect vocabulary.

**Recurrence, 2026-07-12:** New quoted-hash scanner tests used useful fixture-purpose comments but omitted `stable` or `contract` from the final line. The focused suite and full check passed, then the self-scan reported both test callbacks under `docs.missing-invariant-doc` until the final comment lines named the stable contract. A later redirect fixture made the inverse mistake: `Fixture purpose` appeared on the first line and `Stable contract` on the final line, so `docs.fixture-purpose-missing` fired. The final line must carry every applicable vocabulary, such as `Stable fixture contract`.

**Redaction-policy recurrence, 2026-07-12:** The focused suites and full 389-test gate passed, but self-scan found four comment-contract gaps: a rewritten baseline helper omitted its temp-file write, the complex preview test's final comment line omitted why the boundary exists, and two named display limits lacked nearby threshold rationale. The first fix reduced the scan to one finding because the baseline helper still omitted invariant vocabulary; the final line now combines `Stable contract` with the fixture-directory write. The other fixes put `because` on the fixture contract's final line and explain both limits beside their declarations.

**History-scope recurrence, 2026-07-12:** The focused suites and full 392-test gate passed, but self-scan reported all three new CLI test callbacks for missing side-effect documentation. Their final fixture comments named the stable user contract but not the subprocess action; adding `spawns` to each final line made the real CLI execution explicit.

**Complexity-metric recurrence, 2026-07-12:** The focused suites and full 404-test gate passed, then self-scan reported 16 comment-context findings. Large test callbacks needed `Stable fixture contract` on their final leading line, while the fixed metadata key `catch` made the new metric helpers look error-bearing until their comments said they report deterministically or never throw. The same scan caught `src/blocks.ts` six lines over budget; concise comments brought it to 749 without moving behavior.

**Evidence:** `src/changed-regions.ts` + `(search: "function parseChangedRanges")` and `(search: "function gitOutput")`; `src/test-fixtures.ts` + `(search: "function analyseProject")`; `src/baseline-and-project.test.ts` + `(search: "function assertBaselineRoundTrip")`; `src/sensitive-data-rules.test.ts` + `(search: "short masks stay opaque because")`; `src/sensitive-data-rules.ts` + `(search: "24-character threshold")`; `src/security-flow-rules.test.ts` + `(search: "Stable fixture contract")`; `src/history-scope.test.ts` + `(search: "spawns filtered commands")`; `src/complexity-metrics.test.ts` + `(search: "Stable fixture contract")`; `src/complexity-metrics.ts` + `(search: "It reports one deterministic breakdown")`.

**Prevention:** When adding comments to clear self-scan documentation findings, include the relevant marker word in the declaration's leading comment (`contract`/`stable`, `throws`, `spawns`, `filesystem`, etc.). For stacked `//` comments, put every applicable vocabulary on the final line, then rerun the full self-scan before close-out.

## Lesson: targeted self-scan fixes still need comment-quality review

**Created:** 2026-05-19

**What happened:** A self-scan cleanup first cleared `docs.missing-function-doc` and `docs.missing-interface-doc` by adding repetitive `Maintainer note:` comments. The requested rule count reached zero, but the comments were low-value boilerplate and needed a second pass to become declaration-specific.

**Evidence:** `src/cli.ts` + `(search: "function pushMissingFunctionDocFinding")`; corrected comments now describe the declaration role directly, and `rg -n 'Maintainer note|helper intent|analysis output relies|stable contract' src` returns no matches.

**Prevention:** When fixing documentation findings in bulk, verify both rule counts and comment quality. Grep for repeated scaffolding phrases before presenting the change, and sample the largest edited file for comments that merely satisfy the predicate.

**Follow-up:** A later cleanup made comments more readable but removed words such as `stable`, `deterministic`, `fingerprint`, `throws`, and `reports` that encode the analyzer's own context-doc contracts. Before closing a comment rewrite, rerun the self-scan and compare context-doc rules as well as the originally targeted missing-doc rules.

**Parse-summary recurrence, 2026-08-11:** Renaming the per-file parser diagnostic helper to
`summarizeParseErrors` made its purpose clearer, but its first comment revision described only the
returned report entry. “Reported” and “do not throw” still missed the rule's canonical vocabulary;
the self-scan cleared when the return contract used `reports`: “reports parser errors without throwing.”

## Lesson: self-scan calibration should inspect the candidate class, not only targeted fixtures

**Created:** 2026-05-18

**What happened:** During fixture-purpose rule work, the focused tests passed after implementation, but the self-scan showed broad `test-setup` findings because `analyseProject(...)` alone was treated as a fixture setup signal. Tightening the signal to explicit fixture identifiers or source-generation helpers reduced the self-scan from generic project-helper setup to scanner-relevant fixtures.

**Evidence:** `src/cli.ts` + `(search: "function hasFixtureSetupSignal")`; `src/cli.test.ts` + `(search: "fixture purpose flags large fixture-heavy test setup without flagging documented setup")`.

**Prevention:** For new source-scanner classes, run a self-scan before close-out and inspect representative findings by candidate kind. If a helper name is too broad, require a domain-specific token or metadata signal before emitting.

## Lesson: self-scan refactors must account for rules that apply to new helpers

**Created:** 2026-05-18

**What happened:** During self-scan cleanup, the first `src/cli.ts` helper split removed unused-parameter and complexity findings but introduced new self-scan noise from undocumented helper functions, generic local names, and a six-parameter helper.

**Evidence:** `src/cli.ts` + `(search: "function analyseCommentQualityRules")`; the corrected implementation adds focused helper comments, domain-specific `thresholdValue` names, and `FunctionContextCommentQualityInput` for the helper argument bundle.

**Prevention:** After refactoring code that is scanned by gruff itself, rerun `./bin/gruff-ts analyse . --format=json --fail-on=none --no-baseline` before declaring improvement. Compare targeted rule counts and inspect new findings around the edited region, not only the total count.
