---
category: schema-and-cli
last_reviewed: 2026-08-08
---

# Schema + CLI surface footguns

## Footgun: score value semantics and JSON field shape are different contracts

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Evidence context:** M06 score clustering.

`scoreReport` (`src/scoring.ts`, search: `function scoreReport`) owns both the public `gruff.analysis.v2` score object shape and the numeric semantics inside that shape. M06 added correlated-complexity clustering (`src/scoring.ts`, search: `function scoringPenaltyMap`) so `score.composite`, `score.pillars[].penalty`, and `score.topOffenders[].score` can change while the JSON field names stay unchanged. It is valid to keep `schemaVersion: "gruff.analysis.v2"` when only score values change, but comments/docs must not say "score semantics unchanged" or "composite score byte-stable" unless the math is actually untouched. When editing scoring or report wording, grep for `score semantics`, `field shape`, `byte-stable`, `gruff.analysis.v2`, and `schema unchanged`; then verify against `src/m06-rubric-refinements.test.ts` (search: `clusters correlated complexity penalties by symbol`) and `.goat-flow/learning-loop/decisions/ADR-009-cluster-correlated-complexity-score-penalties.md` (search: `score field names and detailed finding array stay unchanged`).

## Footgun: docs, milestone plans, and these footguns still point at the pre-split `src/cli.ts`

**Status:** active | **Created:** 2026-05-30 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After any module split, grep every `search:` anchor against current source in the same change; never trust a green `stats --check` as proof that anchors still resolve.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-08-08

`src/cli.ts` was split into focused modules and is now a 24-line shell, but durable docs kept naming it as the home of symbols that moved. Verified relocations: `exitFor` -> `src/scoring.ts` (search: `function exitFor`); `analyse` -> `src/analyser.ts`; `buildProgram` / `normalizeOptions` -> `src/cli-program.ts`; `changedFiles` -> `src/findings-helpers.ts`; `writeBaseline` / `applyBaseline` -> `src/baseline.ts`; `makeFinding` -> `src/findings.ts`; `RULE_DESCRIPTORS` / `ruleDescriptors` -> `src/rules.ts`; `isDefaultIgnoredDir` -> `src/discovery.ts`; `startDashboard` -> `src/dashboard.ts`; `renderHtml` / `escapeHtml` -> `src/report-html.ts`; `analyseSensitiveData` -> `src/sensitive-data-rules.ts`.

The reason this survived two audits is mechanical: no shipped gate resolves an anchor. `goat-flow stats --check` exited 0 with empty findings and warnings on 2026-08-08 while 13 citations across four footgun buckets still pointed at `src/cli.ts` for symbols living elsewhere, because the check confirms the cited *path* exists and `src/cli.ts` does exist. A `grep ... src/cli.ts` static gate has the same shape of blind spot: it matches nothing and silently passes. Only comparing `search:` anchors against live source finds this.

Repointed on 2026-08-08 across `dashboard.md`, `schema-and-cli.md`, and `sensitive-data.md`. One survivor is correct and must stay: `src/cli.ts` (search: `buildProgram().parseAsync(argv)`) genuinely lives in the entrypoint. Treat any file path or schema version stated in a doc or plan as advisory until re-grepped.

## Footgun: routing migration-path reads through the strict schema validator silently clobbers user state

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED
**Evidence context:** PR #4 review, Codex P1.

`readExistingPreservedConfig` (`src/init-config.ts`, search: `function readExistingPreservedConfig`) originally called `loadConfig` to recover `paths.ignore` and `minimumSeverity` from the existing file before `init --force` regenerates it. `loadConfig` runs `applySchemaVersionConfig` (`src/config.ts`, search: `function applySchemaVersionConfig`), which throws `ConfigLoadError` on any config without `schemaVersion: gruff-ts.config.v0.1` - exactly the shape of every pre-0.1.2 config in the wild. The `try { ... } catch { return EMPTY }` swallowed the throw and the regenerated file lost the user's curated entries. The CHANGELOG simultaneously promised "init --force preserves … paths.ignore"; the implementation delivered the opposite for the migration cohort.

The fix splits the readers: `src/config-preservation.ts` (search: `extractPreservedConfigFields`) reads the two preserved fields permissively (no schemaVersion gate, malformed entries dropped silently) for the migration handoff. The analyser load path still uses the strict validator so misconfigurations surface in context at the next run.

When introducing a strict validator for a new required field, audit every code path that reads existing config for purposes OTHER than running the analyser - preservation, diff, dry-run, doc generation. Each one needs a permissive reader that bypasses the new gate, because "no migration shim" is a contract for the analyser load path, not for tools that translate the user's old config into a new shape. Tests: `init-config.test.ts`, search: `preserves paths.ignore from a pre-schemaVersion config`.

## Footgun: catching only ConfigLoadError lets raw IO/parse errors escape the formatted error path

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED
**Evidence context:** PR #4 review, Codex P2.

`runWithConfigErrorHandling` (`src/cli-program.ts`, search: `async function runWithConfigErrorHandling`) catches `ConfigLoadError` and rethrows everything else. The catch is correct as written; the gap was upstream. `parseConfigFile` (`src/config.ts`, search: `function parseConfigFile`) called `readFileSync` and `JSON.parse` directly: `--config <missing>` produced raw `ENOENT`, malformed `.gruff.json` produced raw `SyntaxError`, both bypassed the "gruff-ts: config error\n  ..." stderr template and the documented exit-2 contract by dumping a Node stack.

The fix wraps both producers (`readConfigSource` search: `function readConfigSource`, and `parseConfigSource` search: `function parseConfigSource`) so the IO and parse errors are rewrapped as `ConfigLoadError` at the boundary. The catch site stays unchanged.

Standing rule for any new CLI surface that wraps user input: rewrap raw producer errors as the public error type at the *boundary*, not at the *handler*. Widening the catch in `runWithConfigErrorHandling` to swallow `SyntaxError | NodeJS.ErrnoException` would have worked, but every future call site would inherit the broader catch and lose visibility into genuine bugs that happen to throw the same shapes. Keep the catch narrow; lift the producers to the public error type.

## Footgun: schema version strings are public contract

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-05-30 | **Evidence:** OBSERVED

Three string literals are part of the public output contract: `gruff.analysis.v2` (set in `src/analyser.ts`:`analyse`, search: `schemaVersion: "gruff.analysis.v2"`), `gruff.baseline.v1` (`src/baseline.ts`:`writeBaseline` / `applyBaseline`), and `gruff.hotspot.v1` (`src/report-renderers.ts`:`renderReport` hotspot branch). The `analysis` schema bumped v1->v2 in 0.2.0; `baseline` and `hotspot` remain v1. Downstream consumers (CI integrations, baseline files already on disk) match on these strings exactly. `applyBaseline` even throws `unsupported baseline schema` on mismatch - bumping the baseline version invalidates every existing `gruff-baseline.json` in users' repos. Bump only when the user explicitly asks AND a migration story is in place.

## Footgun: `exitFor` returns 2 on ANY diagnostic, regardless of `--fail-on`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`exitFor` (`src/scoring.ts`, search: `function exitFor`) returns `2` if `report.diagnostics.length > 0` before it ever consults `failOn`. That means a single `read-error`, `missing-path`, `parse-error`, or `history-error` fails the run even with `--fail-on none`. Tests and CI users sometimes assume `--fail-on none` is "always exit 0" - it is not. If you add a new diagnostic type, that diagnostic alone will start failing every consumer's CI on first appearance.

## Footgun: `--no-baseline` and `--no-config` are CommanderJS auto-negations, not custom flags

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`normalizeOptions` (`src/cli-program.ts`, search: `function normalizeOptions`) reads `rawOptions.config === false` and `rawOptions.noConfig === true` to decide whether to load the default `.gruff-ts.yaml`; same pattern for baseline (`baselineValue === false || rawOptions.noBaseline === true`). These come from Commander's `--no-config`/`--no-baseline` automatic negations, which set the *positive* option to `false`. If you migrate to a different CLI framework or change the option declaration, both branches must be reviewed together - testing only `noConfig` will leave silent gaps.

## Footgun: default-ignored directories are hardcoded and lowercase-only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`isDefaultIgnoredDir` (`src/discovery.ts`, search: `function isDefaultIgnoredDir`) checks the FIRST path segment against a fixed lowercase list (`.git`, `.hg`, `.svn`, `.idea`, `.vscode`, `build`, `cache`, `coverage`, `dist`, `generated`, `node_modules`, `target`, `tmp`, `vendor`). Project conventions like `Build/`, `out/`, `__pycache__/`, `.next/`, `.turbo/`, `.venv/` are NOT ignored by default - they get walked, scanned, and reported. Adding to the list is one line, but every addition is a behavioural change for users who had findings inside those dirs accepted into their baseline.

## Footgun: `gruff-ts init --force` regenerates the whole YAML and can wipe user customisations

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`writeDefaultConfig` (`src/init-config.ts`, search: `function writeDefaultConfig`) overwrites `.gruff-ts.yaml` with the registry-derived default whenever `--force` is set. As of 2026-05-24 the function preserves the existing `paths.ignore` block (via `readExistingIgnoredPaths`, search: `function readExistingIgnoredPaths`) - reading it from whichever supported config exists (precedence-aware via `existingConfigPath`, search: `existingConfigPath !== undefined ? readExistingIgnoredPaths`) so non-canonical `.gruff.yaml`/`.yml`/`.json` incumbents also keep their entries - but **everything else is still clobbered**: `allowlists.acceptedAbbreviations` custom entries, any per-rule `threshold`/`severity`/`options` tuning, disabled rules, and so on revert to the rendered defaults. A real incident in 2026-05 dropped a project's curated `paths.ignore` (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`) when init was rerun without `--force` protections; the regression was only noticed after the commit had been pushed. When editing the init flow: NEVER add a new regenerated section without either (a) reading the existing value and preserving it, or (b) writing a loud stderr warning that lists what is about to be lost. When asked to regenerate the config in a real project: review the diff before committing - `git diff -- .gruff-ts.yaml` is the only thing standing between the user and a silent customisation loss.

## Footgun: rule count and scanned-file-types are mirrored across many docs with no consistency test

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED

Removing `size.stylesheet-length` (the CSS-scan removal) required hand-editing the rule count in `package.json` description, `README.md` (catalogue row + the "contains N rules" line + the `size` pillar table row), `docs/rules.md` (header count + `## Pillar Counts` + the per-rule bullet), `.goat-flow/architecture.md`, plus the scanned-types sentence in `README.md` and `.goat-flow/glossary.md`. No test asserts any of these agree with `RULE_DESCRIPTORS`; `scripts/bump-version.sh --check` only checks the version string, not the rule count. Adding/removing a rule, or changing the discovery extension allowlist, silently drifts these unless you grep every surface - before claiming a rule add/remove is done, `grep -rn "<N> rules\|<N-1> rules" package.json README.md docs/ .goat-flow/` and reconcile. Separately: the discovery extension allowlist (`src/discovery.ts`, search: `function pushSourceFile`) is a DISTINCT surface from the catalogue - a file-type-gated rule goes dead when its type leaves the allowlist (`size.stylesheet-length` only ever fired on `.css` via `isCssPath`, so dropping `css` from discovery made the rule dead and it was deleted with it).

## Footgun: discovery has two entry paths - the walk and the explicit-file short-circuit

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED

`discoverSourceInput` (`src/discovery.ts`) handles an explicit file operand by short-circuiting to `pushSourceFile` and returning BEFORE the directory `walk`. Any ignore/scoping policy enforced inside the walk (`classifyIgnore`, formerly `isIgnoredDiscoveryPath`) does NOT apply to explicitly-supplied files unless the `stats.isFile()` branch calls it too. This is exactly how config `paths.ignore` leaked: authoritative in the walk but bypassed for `analyse <file>` and for the changed-file paths a coding-agent hook passes - so the hook flagged deliberately-excluded files (ADR-007 fixed it by calling `classifyIgnore` with empty gitignore rules in the isFile branch: config-only, preserving ADR-003's "explicit files bypass git/default"). When adding any discovery-scope rule, wire it into BOTH the walk and the explicit-file branch, and add an `analyse <single-file>` regression, not just a directory-scan one.

## Footgun: changed-region diff scope is not the same as project context

**Status:** active | **Created:** 2026-06-01 | **Updated:** 2026-06-11 | **Evidence:** ACTUAL_MEASURED
**Evidence context:** review feedback, focused regression tests, and runtime reproduction.

`analyse` (`src/analyser.ts`, search: `function analyse`) originally filtered `discovery.files` before scanning whenever `--diff` / `--since` produced a file/range scope. That made per-file work cheaper, but it also built `ProjectIndex` from a partial project. Cross-file rules then lied: a changed exported source covered only by an unchanged central test could get `test-quality.missing-nearby-test`, and graph rules could miss unchanged nodes that complete a cycle. The correct split is "scan with whole-project context, then filter emitted findings"; `suppressedCount` becomes the count of full-scan findings dropped by region filtering, so tests must not expect zero simply because only one changed file remains visible.

The same surface has a second trap: hunk headers are ranges in the target file, not proof that every target line in the range changed. Piped diffs usually include context, so trusting `@@ -10,5 +10,5 @@` keeps nearby untouched findings. Parse hunk bodies: `+` lines add target ranges, space-prefixed lines only advance the target cursor, `-` lines do not, and target length `0` means deletion-only with no target range. Base-ref modes should mirror `git diff <ref>`: pass the ref after `--end-of-options` and do not union untracked files except for the explicit `working-tree` mode.

Third trap (resolved 2026-06-11): the emitted-finding filter attributed every finding by its anchor `filePath` alone, so `design.circular-import` (anchored at the lexicographically first SCC member under ADR-015) vanished from `--diff` / `--since` and un-based `hook --changed-ranges` runs whenever the edit touched a non-anchor member, while the docs promised attribution via "a project relationship that includes the requested file". The original hook regression test only passed by coincidence: its `--changed-ranges 1-1` overlapped the anchor file's line-1 import, because explicit ranges are file-agnostic. `isFindingInChangedScope` (`src/changed-regions.ts`, search: `projectRelationshipTouchesChange`) now keeps project-relationship findings when any `metadata.files` member is a changed file. When adding a project-scope rule whose finding spans several files, add its id to `PROJECT_RELATIONSHIP_RULE_IDS` and pin a non-anchor-member regression, not only an anchor-overlap one.

Tests: `src/changed-regions.test.ts` (search: `parses added target lines`, `skips deletion-only hunks`), `src/baseline-and-project.test.ts` (search: `keeps central test context`, `base-ref diff does not include unrelated untracked files`), `src/project-graph-rules.test.ts` (search: `changed-region diff keeps a cycle`), and `src/hook-contract.test.ts` (search: `range misses the canonical anchor line`).

## Footgun: `check-ignore` answers both explicit-file and changed-file prefilter questions

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED
**Evidence context:** review feedback plus ignore-authority tests.

`check-ignore` (`src/check-ignore.ts`, search: `function checkIgnore`) calls `classifyPathIgnore` (`src/discovery.ts`) without knowing whether the caller is asking "would `analyse this-file.ts` scan it?" or "would `analyse . --diff ...` later skip this changed path during the walk?" Those are not identical for default/git ignores: explicit file operands bypass `.gitignore` by design, while a directory walk stops at built-in ignored parent dirs like `dist/` and `node_modules/`.

The compromise is deliberate: file inputs to `check-ignore` do NOT apply `.gitignore`, matching explicit-file analysis, but paths under default-ignored parent dirs DO report a default ignore so agent changed-file prefilters do not feed generated outputs into later hook stages. Config `paths.ignore` remains authoritative in every shape. Whenever `check-ignore` changes, add one explicit-file `.gitignore` regression and one default-parent file regression; testing only config ignores misses the fork.

## Footgun: pre-existing `M <config>` in git status at session start may already represent a customisation loss

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

If a session starts with `M .gruff-ts.yaml` (or any other user-curated config) already in the working tree, do NOT treat that as "fine, the user is mid-edit." Run `git diff -- .gruff-ts.yaml` against `HEAD` before editing the file - a regenerated config from `gruff-ts init` can look like ordinary modifications but actually represent destroyed user customisations (`paths.ignore`, `allowlists.acceptedAbbreviations`, rule tuning). If the diff shows entries vanishing from a sequence, surface that to the user before doing anything else; do not let the loss ride into your own commits or into a user commit that bundles it.

## Footgun: `cli.ts` must keep using `parseAsync` because action handlers are async

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`src/cli.ts` (search: `buildProgram().parseAsync(argv)`) now awaits Commander's async `parseAsync()` inside an async IIFE, because action handlers in `src/cli-program.ts` for `analyse`, `summary`, `report`, and `dashboard` are `async` (each `await`s `maybePromptInitConfig`). Commander's docs require `parseAsync` when handlers return a Promise; the earlier synchronous `parse(argv)` let any rejection after the first `await` (prompt failure, downstream throw past the prompt gate) escape Commander's error path as an unhandled promise rejection. Minimal repro confirmed at the time: an async action that threw after a `setTimeout` triggered `process.on("unhandledRejection")` with the message intact while the main path had already returned, and exit-code semantics from `process.exitCode = exitFor(...)` were not reliable downstream of the first `await`. Do not regress the entrypoint to `parse()`: anyone adding another `await` to an action, or registering a new async command, depends on `parseAsync` staying in place.

## Footgun: `gruff-ts init` only guards against `.gruff-ts.yaml`, not the four-name precedence list

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`writeDefaultConfig` (search: `function writeDefaultConfig`) calls `existsSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME))` to decide whether to refuse a write. But config resolution treats four names as interchangeable defaults via `DEFAULT_CONFIG_FILES` (search: `const DEFAULT_CONFIG_FILES`): `.gruff-ts.yaml`, `.gruff.json`, `.gruff.yaml`, `.gruff.yml`, with `.gruff-ts.yaml` first (highest precedence). Reproduced in `/tmp/init-clobber-test/`: with only `.gruff.yaml` present, `gruff-ts init` printed `Wrote .gruff-ts.yaml` with no warning and the project's effective config silently switched to the registry-derived default. Use `defaultConfigPath(projectRoot)` (already exported from `src/config.ts`) when deciding to refuse, and treat `--force` as the explicit override. Same precedence list governs every other code path that "the default config" means - adding a fifth name without updating both `DEFAULT_CONFIG_FILES` and the init guard repeats this trap.

## Footgun: `--format` argParser wiring is inconsistent across commands

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`src/cli-program.ts` defines `parseSummaryFormat` (search: `function parseSummaryFormat`) as a Commander argParser that throws `InvalidArgumentError` on anything other than `text` or `json`. `registerListRulesCommand` wires it in; `registerSummaryCommand` does not (search: `Output format: text or json.`). Instead, `summary` declares the option with no parser, forces `format: "text"` for the analyser run via `normalizeOptions`, and then coerces the *summary render* format with `rawOptions.format === "json" ? "json" : "text"` (search: `const summaryFormat`). Reproduced: `gruff-ts summary fixtures --format=garbage --no-config --no-baseline` prints normal text output with exit 0; `gruff-ts list-rules --format=garbage` errors with `argument 'garbage' is invalid`. Silent coercion breaks CI jobs that expect JSON - a typo like `--format=jsno` exits zero with text and downstream parsing fails on an unrelated line. When adding a `--format` flag to another command, decide explicitly: argParser everywhere, or silent fallback everywhere. The current half-and-half is the trap.

## Footgun: `shouldPromptForInit` gates on stdin/stderr TTY but not stdout

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`shouldPromptForInit` (search: `function shouldPromptForInit`) checks `context.isStdinTty` and `context.isStderrTty`, but `InitPromptContext` (search: `interface InitPromptContext`) has no `isStdoutTty` field and `buildInitPromptContext` (search: `function buildInitPromptContext`) never reads `process.stdout.isTTY`. The pipeline-from-TTY-parent case stays unguarded: `gruff-ts analyse . --format=json | jq ...` invoked from an interactive shell still has both stdin and stderr as TTYs while stdout is a pipe, so the prompt fires on stderr and the pipeline blocks waiting for input the user is not expecting to provide. Add `isStdoutTty` to the context and require it true before prompting (or invert: require none of the three streams to be a pipe). Any future expansion of "is this run interactive?" must reason about all three streams, not just two.

## Footgun: the finding fingerprint embeds `line`, so a baseline keyed on it churns on pure code movement

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED
**Evidence context:** 0.4.0 baseline plan audit.

`makeFinding` (`src/findings.ts`, search: `const fingerprint = createHash`) hashes `[ruleId, filePath, line, symbol]` into the 16-hex fingerprint, and `applyBaseline` (`src/baseline.ts`, search: `function applyBaseline`) keys suppression on `(fingerprint, ruleId, filePath)`. Because `line` is inside the hash, inserting code above a baselined finding changes its line, changes its fingerprint, and resurfaces the finding as "new" even though the defect is unchanged - churn-by-design for any committed `gruff-baseline.json` that real code drifts under. The 0.4.0 M24 plan assumed the opposite ("a line-moved entry that still matches the same fingerprint"); that assumption is false against the current `makeFinding` and was the trigger for ADR-013, which moves the persistent baseline to PHPStan-style `(filePath, ruleId)` + `count` identity (no line). Keep the fingerprint for SARIF `partialFingerprints.gruffFingerprint` (search: `gruffFingerprint`) and report dedupe (`src/baseline.ts`, search: `function dedupeFindings`) - those WANT per-line identity - but never reintroduce `line` or `fingerprint` as the persistent-baseline match key. When editing baseline matching, grep `gruff.baseline.v`, `applyBaseline`, and `ADR-013`.

## Resolved Entries

## Footgun: diff-base replay reconstructs only materialized files

**Status:** resolved | **Created:** 2026-06-11 | **Evidence:** ACTUAL_MEASURED
**Evidence context:** runtime reproduction plus regression test.

`stableIdentitiesFromDiffBase` (`src/hook-contract.ts`, search: `function stableIdentitiesFromDiffBase`) replays the base ref inside a temp tree built only from materialized paths. It originally materialized just current finding anchor paths, so a multi-file finding (`design.circular-import` anchors one SCC member) could not be reconstructed at the base whenever the other members anchored no findings: the base scan saw a partial import graph, the cycle identity never entered the base set, and a pre-existing cycle was reported as new - false blame in the agent hook. Resolved 2026-06-11 by materializing `metadata.files` members alongside anchors (search: `findingBasePaths`); regression pinned in `src/hook-contract.test.ts` (search: `materializes SCC members`). When adding any finding whose stable identity depends on files beyond its anchor, extend `findingBasePaths` - a partial replay silently breaks the new-only comparison, and a member missing at the base ref is the correct "this cycle is new" signal, not an error.
