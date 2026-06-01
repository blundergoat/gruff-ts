---
category: verification
last_reviewed: 2026-05-31
---

# Verification lessons

## Lesson: converting the dogfood config to a profile breaks rule-enumeration contract tests

**Created:** 2026-05-31

**What happened:** After replacing the repo `.gruff-ts.yaml`'s flat 120-rule block with `profile: recommended` (the named-profiles dogfood step), `npm run check` went from 274/274 to 3 failures. Three contract tests grepped the yaml TEXT for a per-rule entry: `naming-rules.test.ts` (search: `naming rule pack catalogue coverage`), and `rule-catalogue.test.ts` (search: `documentation catalogue covers comment rule pack` and `thresholds and options match implementation`). They encoded the exact manual enumeration that profiles are designed to eliminate.

**Evidence:** the failing assertions were `missing yaml entry for naming.class-file-mismatch`, `missing config entry for docs.fixture-purpose-missing`, and a `Map(0)` vs `Map(10)` threshold mismatch from `yamlThresholdDefaults`. The fix retargeted all three to load the effective config (`loadConfig(cwd(), ...)` then `ruleEnabled`/`threshold`/`ruleSeverity`) instead of grepping yaml text, which is robust whether the config enumerates rules or names a profile, and deleted the now-dead `yamlThresholdDefaults`/`yamlSeverityDefaults`/`yamlOptionDefaults` helpers.

**Prevention:** Before converting a project's shipped config to a profile, grep the test suite for tests that read `.gruff-ts.yaml` as TEXT (`readFileSync(".gruff-ts.yaml"`, `configSource.includes`, yaml-threshold parsers). Retarget them to assert against the loaded `Config` (style-agnostic) in the same change. The sibling gruff ports (go/rs/py/php) will hit the identical break when they add profiles.

## Lesson: a near-budget file plus "add subsystem X here" forces an extraction

**Created:** 2026-05-31

**What happened:** The milestone said to add `resolveProfile` and the profile machinery to `src/config.ts`. `config.ts` was 749 lines - one under the `size.file-length` 750 default - so the ~180-line resolver pushed it to ~960 and `analyse src --no-config` flagged `size.file-length` on `config.ts` itself (the self-scan is normally 0). Moving the resolver out would have created a `config.ts` <-> resolver cycle because the resolver needs `parseConfigFile`.

**Evidence:** the clean baseline was `./bin/gruff-ts analyse src --no-config` = 0 findings against pristine HEAD; after the additions it reported `config.ts:1 size.file-length`. The fix extracted the zero-dependency YAML parser + `parseConfigFile` + narrowing helpers to a new `src/config-parse.ts` (search: `Config parsing layer`) that imports nothing from `config.ts`, breaking the cycle and dropping `config.ts` to ~505 lines; `resolveProfile` stayed in `config.ts` per the plan.

**Prevention:** When a task says "put new code in file Y", check Y's line count against the `size.file-length` threshold first (`wc -l`). If adding the feature crosses it, plan the supporting extraction up front and pick a split that does not import back into Y. Establish the pristine self-scan baseline (scan HEAD in a throwaway worktree, or before editing) so you can tell which findings you introduced.

## Lesson: run git status before recommending commit, push, or PR steps

**Created:** 2026-05-31

**What happened:** After finishing M06 verification, I answered "next best step: commit this verified work" from stale context instead of checking the current repository state. The user challenged it, and `git status --short --untracked-files=all` returned no output, proving the working tree was already clean and there was nothing to commit.

**Evidence:** `git status --short --untracked-files=all` run in `/home/devgoat/projects/gruff-workspace/gruff-ts` returned no output immediately after the bad recommendation. The stale recommendation contradicted the actual repository state.

**Prevention:** Before recommending `git add`, `git commit`, `git push`, PR creation, or saying "nothing left but commit", run `git status --short --untracked-files=all` in the target repo in the same turn. Base the next step on that output, not on remembered dirty state from earlier work.

## Lesson: self-scan freshly added regression tests before closing

**Created:** 2026-05-31

**What happened:** The normal `npm run check` gate passed after the rubric-calibration tests were added, but the follow-up gruff self-scan found a `test-quality.magic-number-assertion` in the new regression test itself. The test was behaviorally correct, but still taught future agents a noisy pattern until the expected score was named as a contract constant.

**Evidence:** `src/m06-rubric-refinements.test.ts` + `(search: "EXPECTED_CLUSTER_COMPOSITE_SCORE")`; the fresh scan command `./bin/gruff-ts analyse . --format=json --fail-on=none` later reported `total=0` from `/tmp/gruff_ts_double_check_1304802.json`.

**Prevention:** After adding or moving regression tests for analyzer rules, run the analyzer over the repo as well as `npm run check`. Treat findings in new test files as part of the change, not as harmless test-only noise; use named constants or fixture comments when the numeric or structural value is the documented contract.

## Lesson: re-read changed files and contract wording after checks in an active workspace

**Created:** 2026-05-31

**What happened:** During the M06 rubric calibration pass, other agent work was active in the same checkout. The scoring implementation was briefly reverted by concurrent edits after tests had already exercised the intended clustered-penalty behaviour, and a stale source comment still claimed composite score values stayed byte-stable after the code intentionally clustered correlated penalties. A normal "tests passed" check was not enough to prove the final tree and its contract wording still matched the intended code.

**Evidence:** `src/scoring.ts` + `(search: "function scoringPenaltyMap")` and `(search: "correlated complexity clustering must not add")`; `src/m06-rubric-refinements.test.ts` + `(search: "clusters correlated complexity penalties by symbol")`; `.goat-flow/decisions/ADR-009-cluster-correlated-complexity-score-penalties.md` + `(search: "score field names and detailed finding array stay unchanged")`; `scripts/preflight-checks.sh` + `(search: "Gruff full-project scan")`.

**Prevention:** In a dirty or multi-agent workspace, finish verification by re-reading the specific edited files and grepping for old contract phrases after the final test run. Pair the normal check command with a final `git status --short` / `git diff -- <files>` review so overwritten code, stale comments, changelog drift, or interleaved changes are caught before close-out.

## Lesson: self-scan comment fixes need context-marker words

**Created:** 2026-05-31

**What happened:** A first self-scan cleanup added leading comments and removed most findings, but the follow-up scan still reported context-doc gaps because the comments did not include the rule's expected contract, throws, or side-effect vocabulary.

**Evidence:** `src/changed-regions.ts` + `(search: "function parseChangedRanges")` and `(search: "function gitOutput")`; `src/test-fixtures.ts` + `(search: "function analyseProject")`; `src/baseline-and-project.test.ts` + `(search: "function evalFindingLines")`.

**Prevention:** When adding comments to clear self-scan documentation findings, include the relevant marker word in the declaration's leading comment (`contract`/`stable`, `throws`, `spawns`, `filesystem`, etc.) and rerun the full self-scan before close-out.

## Lesson: broadening scope can invalidate old suppression-count assertions

**Created:** 2026-06-01

**What happened:** A review fix changed diff-scoped analysis from "scan changed files only" to "scan the full project, then filter emitted findings" so project-level rules keep central-test and import-graph context. The first focused regression run passed the new behavior tests but failed an older working-tree diff assertion that expected `suppressedCount` to stay `0`. With full context, unchanged findings are now produced and then suppressed, so a positive suppression count is the correct signal.

**Evidence:** `src/analyser.ts` + `(search: "const changedScope = changedRegionScope")`; `src/baseline-and-project.test.ts` + `(search: "working-tree diff treats untracked files as whole-file changed")`; focused command `node --import tsx --test ...` reported `# fail 2` before the assertion was updated.

**Prevention:** When a correctness fix moves filtering later in the pipeline, audit tests that assert counts or skipped totals, not only visible findings. A later filter can preserve user-visible findings while legitimately changing `suppressedCount`, analysed-file totals, or diagnostic counts.

## Lesson: grep source for symbol locations; docs lag the cli.ts split

**Created:** 2026-05-30

**What happened:** While auditing the 0.3.0 milestone plans, I claimed `exitFor` lives in `src/cli-program.ts`, copying `.goat-flow/architecture.md`. The user's "double check" forced a grep, which showed `exitFor` is actually in `src/scoring.ts` - and that architecture.md itself was stale. The `src/cli.ts` split moved most symbols into focused modules, but architecture.md, the milestone plans, and `footguns/schema-and-cli.md` still cited `src/cli.ts` and `gruff.analysis.v1`.

**Evidence:** `src/scoring.ts` + `(search: "function exitFor")`; the wrong source was `.goat-flow/architecture.md` (search: "severity-to-exit mapping lives"), since corrected to `src/scoring.ts`. See `footguns/schema-and-cli.md`, "docs ... still point at the pre-split src/cli.ts".

**Prevention:** Before asserting any `file:symbol` location, grep current source for the symbol. Never quote a file path from architecture.md, a milestone "Read first" list, or a footgun - they predate the cli.ts split. Quote the grep result, not the doc.

## Lesson: run a no-diff control when a zero-tolerance perf gate fails
**Created:** 2026-05-22

**What happened:** During analyser performance work, two small hot-path patches were reverted after `scripts/test-performance.sh --matrix --baseline ... --fail-on-regression 0` reported regressions. A clean-tree control run with no source diff then failed the same zero-tolerance gate, proving the original comparison was not reproducible in the current machine state.

**Evidence:** `scripts/test-performance.sh` + `(search: "check_regressions")`; no-diff command `scripts/test-performance.sh --matrix --baseline /tmp/perf-baseline.json --fail-on-regression 0 --report /tmp/perf-report-control.md --out /tmp/perf-control.json --runs 7` reported wall/RSS regressions despite `git diff -- src` being empty.

**Prevention:** Before attributing a zero-tolerance perf regression to a patch, run one clean-tree control against the same baseline. If the control fails, re-establish a current baseline or remove environmental noise before evaluating code changes.

## Lesson: Codex permission audits reject absent exact workspace paths

**Created:** 2026-05-21

**What happened:** While fixing the Codex secret-path audit gate, switching `.codex/config.toml` to `:workspace_roots` made file-read deny coverage observable, but the next audit failed because exact workspace-root entries named files absent from this checkout (`.env`, `.envrc`, `.docker/config.json`, `.npmrc`, `.pypirc`, `.kube/config`, and `.env.example`).

**Evidence:** `.codex/config.toml` + `(search: "[permissions.goat-flow.filesystem.\":workspace_roots\"]")`; the failing harness message came from the Codex exact-path settings check and said to remove absent exact entries while keeping trailing `/**` subtree denies.

**Prevention:** For Codex permission profiles, use `:workspace_roots`, keep wildcard/subtree denies for absent secret families, and add exact `none` or `read` entries only when the path exists in the checkout. Rerun `goat-flow audit . --harness --agent codex` after both the secret-deny patch and the exact-path cleanup.

## Lesson: targeted self-scan fixes still need comment-quality review

**Created:** 2026-05-19

**What happened:** A self-scan cleanup first cleared `docs.missing-function-doc` and `docs.missing-interface-doc` by adding repetitive `Maintainer note:` comments. The requested rule count reached zero, but the comments were low-value boilerplate and needed a second pass to become declaration-specific.

**Evidence:** `src/cli.ts` + `(search: "function pushMissingFunctionDocFinding")`; corrected comments now describe the declaration role directly, and `rg -n 'Maintainer note|helper intent|analysis output relies|stable contract' src` returns no matches.

**Prevention:** When fixing documentation findings in bulk, verify both rule counts and comment quality. Grep for repeated scaffolding phrases before presenting the change, and sample the largest edited file for comments that merely satisfy the predicate.

**Follow-up:** A later cleanup made comments more readable but removed words such as `stable`, `deterministic`, `fingerprint`, `throws`, and `reports` that encode the analyzer's own context-doc contracts. Before closing a comment rewrite, rerun the self-scan and compare context-doc rules as well as the originally targeted missing-doc rules.

## Lesson: verify extracted modules for circular self-scan edges

**Created:** 2026-05-19

**What happened:** During the first `src/cli-program.ts` extraction, the new module imported `analyse` directly from `src/cli.ts` while `src/cli.ts` imported `buildProgram` from `src/cli-program.ts`. `tsc` passed, but `./bin/gruff-ts analyse src --format=json --no-config --no-baseline --fail-on=none` surfaced a new `design.circular-import` finding between the two modules.

**Evidence:** `src/cli.ts` + `(search: "const buildProgram =")`; `src/cli-program.ts` + `(search: "type AnalyseRunner")`. The corrected extraction passes the analyser callback from `cli.ts` into `cli-program.ts` instead of importing back into `cli.ts`.

**Prevention:** After extracting code from `src/cli.ts`, run a self-scan and inspect `design.circular-import` before accepting the split. If the extracted module needs a runtime callback from `cli.ts`, pass it as a parameter and keep the public wrapper in `cli.ts`.

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

## Lesson: exact optional properties must be omitted instead of set to undefined

**Created:** 2026-05-18

**What happened:** During stale-comment rule work, `staleCommentFinding` initially passed `symbol: metadata.symbol` into `makeFinding`, which can be `undefined` at runtime. `tsc --noEmit` rejected the object under `exactOptionalPropertyTypes`.

**Evidence:** `src/cli.ts` + `(search: "function staleCommentFinding")`; the corrected implementation uses a conditional spread so `symbol` is omitted unless a real symbol exists.

**Prevention:** For optional fields in `Finding` or `FindingInput`, build object literals with conditional spreads rather than assigning possibly undefined values.

## Lesson: use raw source for human labels and masked source only for code-position proof

**Created:** 2026-05-18

**What happened:** During magic-threshold rule work, findings initially built labels from masked source text, so `threshold(config, "rule", "key", 55)` produced whitespace/dot labels after string masking.

**Evidence:** `src/cli.ts` + `(search: "function magicThresholdCandidate")`; the corrected function takes `rawLine` for labels and `codeLine` only to prove the threshold call starts in executable code.

**Prevention:** For source scanners, derive human-facing metadata and message labels from raw source after proving the candidate starts in code with masked source.

## Lesson: line-anchored multiline regexes must not use `\s*` for indentation

**Created:** 2026-05-18

**What happened:** During documentation-rubric work, `interfaceDeclarations` initially used a `gm` regex with `^\s*`, which let the indentation prefix consume newlines and report an interface at line 1 instead of its declaration line. That made a valid leading `//` comment look detached from the interface.

**Evidence:** `src/cli.ts` + `(search: "function interfaceDeclarations")`; the focused test `documentation rubric requires file overview and comments on functions and interfaces` failed until the regex used `[ \t]*` and `[ \t]+` for same-line whitespace.

**Prevention:** In line-anchored `m` regexes, use `[ \t]` for indentation. Reserve `\s` for patterns where crossing line boundaries is intended.

## Lesson: dynamic import is not a safe cycle breaker when the imported module re-enters the CLI

**Created:** 2026-05-18

**What happened:** During self-scan cleanup, replacing the static dashboard import in `src/cli.ts` (`registerDashboardCommand`) with a dynamic import deadlocked the dashboard CLI because `src/dashboard.ts` imported `analyse` back from `src/cli.ts` while the CLI module was still evaluating.

**Evidence:** `npm run check` failed in dashboard tests with `timed out waiting for http://127.0.0.1:<port>/health`; the corrected implementation passes `analyse` into `startDashboard` (`src/dashboard.ts`, search: `type DashboardAnalyse`) instead of importing `cli.ts`.

**Prevention:** When removing an ESM import cycle, prefer moving the dependency direction with a parameter or shared module before trying dynamic import; rerun command-level tests for the affected subcommand.

## Lesson: benchmark workload labels need filesystem-safe temp names

**Created:** 2026-05-17

**What happened:** During perf-harness verification, `./scripts/test-performance.sh --runs 1 --target fixtures/sample.ts --out /tmp/perf-spike.json` failed because the workload label `fixtures/sample.ts` was reused inside the temporary filename, creating an unintended nested path under `/tmp/gruff-perf-work-*`.

**Evidence:** `scripts/test-performance.sh` + `(search: "local cell_name=")` now sanitizes workload/config/format labels before building per-cell temp file paths.

**Prevention:** Any benchmark or report label that can contain `/`, spaces, or option-like prefixes must be converted to a filesystem slug before it is used as a path segment. Keep human labels in JSON/report fields; use sanitized names only for temp files.

## Lesson: source-scanning contract tests must follow refactors across helper contexts

**Created:** 2026-05-17

**What happened:** During self-scan cleanup, `npm run check` failed after threshold-backed rules were refactored to read thresholds through `context.config` instead of a direct `config` parameter. The analyzer behavior was intact, but the descriptor/config threshold contract test only searched for `threshold(config, ...)`, so it undercounted implemented thresholds until the regex was widened.

**Evidence:** `src/cli.test.ts` + `(search: "function thresholdUsages")`; the failing run reported missing implementation thresholds for `size.function-length`, `size.parameter-count`, `complexity.cyclomatic`, `complexity.cognitive`, and `complexity.npath`.

**Prevention:** When a contract test scans source text instead of calling a structured API, update its extractor in the same refactor that changes call shape. Prefer matching the semantic argument form, such as optional context prefixes, over one local variable spelling.

## Lesson: keep verification wrappers visible to the deny hook

**Created:** 2026-05-16

The local deny-dangerous hook blocks verification wrappers that obscure nested execution. During discovery-scope verification, one `node` heredoc was blocked because JavaScript template-literal backticks looked like hidden command substitution, and a later `node -e` wrapper around `spawnSync("./bin/gruff-ts", ...)` was blocked because the shell-executing primitive hid the real command from hook review.

Run the target command directly, save output to `/tmp` if parsing is needed, then use a non-spawning parser command against that file.

**Updated:** 2026-05-23

Workflow-security fixture smoke tests can trip the same hook if the shell command itself contains a literal remote-shell sample. Build risky fixture strings inside the test or temp-file writer from separated tokens, then run `gruff-ts` from the temp project root so workflow path gating still sees `.github/workflows/...`.

## Lesson: run `npm run check` after every `src/cli.ts` edit, not just before commit

**Created:** 2026-05-10

`src/cli.ts` is the entire runtime. It compiles under `strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes`, which means a small change (e.g., adding a property to `Finding` without making it optional, or indexing an array without a bounds check) routinely breaks `tsc` even when the diff "looks fine". `npm run check` runs `tsc --noEmit && npm test` - both are needed, both are fast (sub-second `tsc`, ~150ms test). Pasting the literal "0 fail" line from the test runner is the verification artifact; "looks correct" is not.

## Lesson: when changing rule output, regenerate the baseline test scenario, do not edit findings inline

**Created:** 2026-05-10

`src/cli.test.ts` writes a fixture and asserts that specific `ruleId`s appear (`security.eval-call`, `size.parameter-count`, `test-quality.no-assertions`, `modernisation.public-property`). If you alter a rule's `ruleId`, threshold, or matcher, the fixture text - not the assertion list - is the part to expand: add a new bad pattern that triggers the renamed rule. Editing the assertion to "make the test pass" with the existing fixture defeats the test's purpose (proving the rule fires at all).

## Lesson: the deny-dangerous hook treats piping into `python3 -c`/`node -e` as blocked

**Created:** 2026-05-10

`.claude/hooks/deny-dangerous.sh` blocks "pipe to interpreter" patterns. When summarising audit JSON or processing tool output with a one-liner, write to `/tmp/<file>.json` first and then run the interpreter against the file path. Trying to retry the same pipeline after a block triggers the same hook - the lesson is to switch to a file-based intermediate, not to keep retrying.

## Lesson: threshold fixtures must exceed the threshold they are proving

**Created:** 2026-05-13

**What happened:** The first high-entropy sensitive-data fixture initially used a 31-character secret-like value while the rule default required 32 characters, so the targeted test failed after implementation until the fixture value was corrected.

**Evidence:** `src/cli.test.ts` + `(search: "const secret =")` - the first-slice fixture owns the candidate value for `sensitive-data.high-entropy-string`.

**Prevention:** When adding threshold-backed rule fixtures, count or otherwise prove the fixture value crosses the threshold before treating a missing finding as an implementation bug.

## Lesson: self-analysis smoke catches scanner regressions that fixtures miss

**Created:** 2026-05-13

**What happened:** Core-expansion unit fixtures passed, but `./bin/gruff-ts analyse src --format=json --fail-on=none --no-config` exposed a `parse-error` in `src/cli.ts` and false positives where control statements were treated as function blocks.

**Evidence:** `src/cli.ts` + `(search: "function parseDiagnostics")` and `(search: "function functionBlocks")`; `src/cli.test.ts` now includes clean control-flow coverage and delimiter-looking literal coverage.

**Prevention:** For regex-heavy rule work, run the analyzer against `src` before declaring the work done, and check the output for diagnostics plus impossible symbols such as `if`, `switch`, or `catch`.

## Lesson: inspect smoke output, not just exit status

**Created:** 2026-05-13

**What happened:** Sensitive-data tests and the HTML smoke command exited 0, but the first HTML inspection showed obvious false positives on `package-lock.json` SRI hashes and the detector string `OPENAI_API_KEY` inside `src/cli.ts`.

**Evidence:** `src/cli.ts` + `(search: "function isHighEntropySecretCandidate")` and `(search: "sensitive-data.api-key-pattern")`; `src/cli.test.ts` now includes `risk expansion ignores package integrity hashes`.

**Prevention:** When adding source-text detectors, inspect a small slice of CLI smoke output for noisy rule ids and filenames. Exit code 0 only proves the command ran; it does not prove the detector is useful.

## Lesson: do not mutate the scanned tree during determinism checks

**Created:** 2026-05-13

**What happened:** The determinism smoke was first run in parallel with baseline generation. The baseline command created `.goat-flow/scratchpad/gruff-ts-expanded-baseline.json` between the two `analyse .` runs, so the comparison reported one extra finding even though the analyzer output was deterministic for a stable tree.

**Evidence:** Determinism verification commands; rerunning `./bin/gruff-ts analyse . --format=json --fail-on=none --no-config` twice after baseline generation completed produced identical reports after ignoring `run.generatedAt`.

**Prevention:** Run determinism checks by themselves, or generate any scratchpad/baseline artifacts before the first compared run. Parallel verification is fine only when none of the commands write into paths being scanned.

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

**Prevention:** When a task writes verification artifacts inside the tree being enumerated, either exclude the artifact directory in the proof command or write artifacts outside the enumerated scope. Use `rg -uuu` for checks that intentionally inspect gitignored `.goat-flow/tasks` or `.goat-flow/scratchpad` files.

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
