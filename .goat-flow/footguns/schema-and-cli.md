---
category: schema-and-cli
last_reviewed: 2026-05-30
---

# Schema + CLI surface footguns

## Footgun: docs, milestone plans, and these footguns still point at the pre-split `src/cli.ts`

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED (1.0.0 plan audit)

`src/cli.ts` was split into focused modules and is now a ~22-line shell, but many durable docs were never refreshed: they still say "in `src/cli.ts`" for symbols that moved, and still cite `gruff.analysis.v1` (the v1->v2 analysis bump shipped in 0.2.0). Verified relocations: `exitFor` -> `src/scoring.ts` (search: `function exitFor`); `analyse` -> `src/analyser.ts`; `buildProgram` / `normalizeOptions` -> `src/cli-program.ts`; `changedFiles` -> `src/findings-helpers.ts`; `writeBaseline` / `applyBaseline` -> `src/baseline.ts`; `makeFinding` -> `src/findings.ts`; `RULE_DESCRIPTORS` / `ruleDescriptors` -> `src/rules.ts`; `isDefaultIgnoredDir` -> `src/discovery.ts`. Stale carriers include `.goat-flow/architecture.md` (it said `exitFor` was in `cli-program.ts`), every `.goat-flow/tasks/1.0.0/M0x`-`M2x` plan's "Read first" list and `rg ... src/cli.ts` gates, and the entries in this very file. Always grep the `search:` anchor against current source; treat any file path or schema version stated in a doc or plan as advisory until confirmed. A `rg ... src/cli.ts` static-check gate now matches nothing and silently "passes."

## Footgun: routing migration-path reads through the strict schema validator silently clobbers user state

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED (PR #4 review, codex P1)

`readExistingPreservedConfig` (`src/init-config.ts`, search: `function readExistingPreservedConfig`) originally called `loadConfig` to recover `paths.ignore` and `minimumSeverity` from the existing file before `init --force` regenerates it. `loadConfig` runs `applySchemaVersionConfig` (`src/config.ts`, search: `function applySchemaVersionConfig`), which throws `ConfigLoadError` on any config without `schemaVersion: gruff-ts.config.v0.1` - exactly the shape of every pre-0.1.2 config in the wild. The `try { ... } catch { return EMPTY }` swallowed the throw and the regenerated file lost the user's curated entries. The CHANGELOG simultaneously promised "init --force preserves … paths.ignore"; the implementation delivered the opposite for the migration cohort.

The fix splits the readers: `src/config-preservation.ts` (search: `extractPreservedConfigFields`) reads the two preserved fields permissively (no schemaVersion gate, malformed entries dropped silently) for the migration handoff. The analyser load path still uses the strict validator so misconfigurations surface in context at the next run.

When introducing a strict validator for a new required field, audit every code path that reads existing config for purposes OTHER than running the analyser - preservation, diff, dry-run, doc generation. Each one needs a permissive reader that bypasses the new gate, because "no migration shim" is a contract for the analyser load path, not for tools that translate the user's old config into a new shape. Tests: `init-config.test.ts`, search: `preserves paths.ignore from a pre-schemaVersion config`.

## Footgun: catching only ConfigLoadError lets raw IO/parse errors escape the formatted error path

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED (PR #4 review, codex P2)

`runWithConfigErrorHandling` (`src/cli-program.ts`, search: `async function runWithConfigErrorHandling`) catches `ConfigLoadError` and rethrows everything else. The catch is correct as written; the gap was upstream. `parseConfigFile` (`src/config.ts`, search: `function parseConfigFile`) called `readFileSync` and `JSON.parse` directly: `--config <missing>` produced raw `ENOENT`, malformed `.gruff.json` produced raw `SyntaxError`, both bypassed the "gruff-ts: config error\n  ..." stderr template and the documented exit-2 contract by dumping a Node stack.

The fix wraps both producers (`readConfigSource` search: `function readConfigSource`, and `parseConfigSource` search: `function parseConfigSource`) so the IO and parse errors are rewrapped as `ConfigLoadError` at the boundary. The catch site stays unchanged.

Standing rule for any new CLI surface that wraps user input: rewrap raw producer errors as the public error type at the *boundary*, not at the *handler*. Widening the catch in `runWithConfigErrorHandling` to swallow `SyntaxError | NodeJS.ErrnoException` would have worked, but every future call site would inherit the broader catch and lose visibility into genuine bugs that happen to throw the same shapes. Keep the catch narrow; lift the producers to the public error type.

## Footgun: schema version strings are public contract

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-05-30 | **Evidence:** OBSERVED

Three string literals are part of the public output contract: `gruff.analysis.v2` (set in `src/analyser.ts`:`analyse`, search: `schemaVersion: "gruff.analysis.v2"`), `gruff.baseline.v1` (`src/baseline.ts`:`writeBaseline` / `applyBaseline`), and `gruff.hotspot.v1` (`src/report-renderers.ts`:`renderReport` hotspot branch). The `analysis` schema bumped v1->v2 in 0.2.0; `baseline` and `hotspot` remain v1. Downstream consumers (CI integrations, baseline files already on disk) match on these strings exactly. `applyBaseline` even throws `unsupported baseline schema` on mismatch - bumping the baseline version invalidates every existing `gruff-baseline.json` in users' repos. Bump only when the user explicitly asks AND a migration story is in place.

## Footgun: `exitFor` returns 2 on ANY diagnostic, regardless of `--fail-on`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`exitFor` (`src/cli.ts`, search: `function exitFor`) returns `2` if `report.diagnostics.length > 0` before it ever consults `failOn`. That means a single `read-error`, `missing-path`, `parse-error`, or `history-error` fails the run even with `--fail-on none`. Tests and CI users sometimes assume `--fail-on none` is "always exit 0" - it is not. If you add a new diagnostic type, that diagnostic alone will start failing every consumer's CI on first appearance.

## Footgun: `--no-baseline` and `--no-config` are CommanderJS auto-negations, not custom flags

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`normalizeOptions` (`src/cli.ts`, search: `function normalizeOptions`) reads `rawOptions.config === false` and `rawOptions.noConfig === true` to decide whether to load the default `.gruff-ts.yaml`; same pattern for baseline (`baselineValue === false || rawOptions.noBaseline === true`). These come from Commander's `--no-config`/`--no-baseline` automatic negations, which set the *positive* option to `false`. If you migrate to a different CLI framework or change the option declaration, both branches must be reviewed together - testing only `noConfig` will leave silent gaps.

## Footgun: default-ignored directories are hardcoded and lowercase-only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`isDefaultIgnoredDir` (`src/cli.ts`, search: `function isDefaultIgnoredDir`) checks the FIRST path segment against a fixed lowercase list (`.git`, `.hg`, `.svn`, `.idea`, `.vscode`, `build`, `cache`, `coverage`, `dist`, `generated`, `node_modules`, `target`, `tmp`, `vendor`). Project conventions like `Build/`, `out/`, `__pycache__/`, `.next/`, `.turbo/`, `.venv/` are NOT ignored by default - they get walked, scanned, and reported. Adding to the list is one line, but every addition is a behavioural change for users who had findings inside those dirs accepted into their baseline.

## Footgun: `gruff-ts init --force` regenerates the whole YAML and can wipe user customisations

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`writeDefaultConfig` (`src/init-config.ts`, search: `function writeDefaultConfig`) overwrites `.gruff-ts.yaml` with the registry-derived default whenever `--force` is set. As of 2026-05-24 the function preserves the existing `paths.ignore` block (via `readExistingIgnoredPaths`, search: `function readExistingIgnoredPaths`) - reading it from whichever supported config exists (precedence-aware via `existingConfigPath`, search: `existingConfigPath !== undefined ? readExistingIgnoredPaths`) so non-canonical `.gruff.yaml`/`.yml`/`.json` incumbents also keep their entries - but **everything else is still clobbered**: `allowlists.acceptedAbbreviations` custom entries, any per-rule `threshold`/`severity`/`options` tuning, disabled rules, and so on revert to the rendered defaults. A real incident in 2026-05 dropped a project's curated `paths.ignore` (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`) when init was rerun without `--force` protections; the regression was only noticed after the commit had been pushed. When editing the init flow: NEVER add a new regenerated section without either (a) reading the existing value and preserving it, or (b) writing a loud stderr warning that lists what is about to be lost. When asked to regenerate the config in a real project: review the diff before committing - `git diff -- .gruff-ts.yaml` is the only thing standing between the user and a silent customisation loss.

## Footgun: rule count and scanned-file-types are mirrored across many docs with no consistency test

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED

Removing `size.stylesheet-length` (the CSS-scan removal) required hand-editing the rule count in `package.json` description, `README.md` (catalogue row + the "contains N rules" line + the `size` pillar table row), `docs/rules.md` (header count + `## Pillar Counts` + the per-rule bullet), `.goat-flow/architecture.md`, plus the scanned-types sentence in `README.md` and `.goat-flow/glossary.md`. No test asserts any of these agree with `RULE_DESCRIPTORS`; `scripts/bump-version.sh --check` only checks the version string, not the rule count. Adding/removing a rule, or changing the discovery extension allowlist, silently drifts these unless you grep every surface - before claiming a rule add/remove is done, `grep -rn "<N> rules\|<N-1> rules" package.json README.md docs/ .goat-flow/` and reconcile. Separately: the discovery extension allowlist (`src/discovery.ts`, search: `function pushSourceFile`) is a DISTINCT surface from the catalogue - a file-type-gated rule goes dead when its type leaves the allowlist (`size.stylesheet-length` only ever fired on `.css` via `isCssPath`, so dropping `css` from discovery made the rule dead and it was deleted with it).

## Footgun: discovery has two entry paths - the walk and the explicit-file short-circuit

**Status:** active | **Created:** 2026-05-30 | **Evidence:** OBSERVED

`discoverSourceInput` (`src/discovery.ts`) handles an explicit file operand by short-circuiting to `pushSourceFile` and returning BEFORE the directory `walk`. Any ignore/scoping policy enforced inside the walk (`classifyIgnore`, formerly `isIgnoredDiscoveryPath`) does NOT apply to explicitly-supplied files unless the `stats.isFile()` branch calls it too. This is exactly how config `paths.ignore` leaked: authoritative in the walk but bypassed for `analyse <file>` and for the changed-file paths a coding-agent hook passes - so the hook flagged deliberately-excluded files (ADR-007 fixed it by calling `classifyIgnore` with empty gitignore rules in the isFile branch: config-only, preserving ADR-003's "explicit files bypass git/default"). When adding any discovery-scope rule, wire it into BOTH the walk and the explicit-file branch, and add an `analyse <single-file>` regression, not just a directory-scan one.

## Footgun: pre-existing `M <config>` in git status at session start may already represent a customisation loss

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

If a session starts with `M .gruff-ts.yaml` (or any other user-curated config) already in the working tree, do NOT treat that as "fine, the user is mid-edit." Run `git diff -- .gruff-ts.yaml` against `HEAD` before editing the file - a regenerated config from `gruff-ts init` can look like ordinary modifications but actually represent destroyed user customisations (`paths.ignore`, `allowlists.acceptedAbbreviations`, rule tuning). If the diff shows entries vanishing from a sequence, surface that to the user before doing anything else; do not let the loss ride into your own commits or into a user commit that bundles it.

## Footgun: `cli.ts` uses `parse(argv)` while action handlers are now async

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`src/cli.ts` (search: `buildProgram().parse(argv)`) calls Commander's synchronous `parse()`, but action handlers in `src/cli-program.ts` for `analyse`, `summary`, `report`, and `dashboard` are now `async` because each `await`s `maybePromptInitConfig`. Commander's docs require `parseAsync` when handlers return a Promise; with `parse`, any rejection after the first `await` (prompt failure, downstream throw past the prompt gate) escapes Commander's error path as an unhandled promise rejection. Minimal repro confirmed: an async action that throws after a `setTimeout` triggered `process.on("unhandledRejection")` with the message intact while the main path had already returned. Exit-code semantics from `process.exitCode = exitFor(...)` are not reliable downstream of the first `await`. Anyone adding another `await` to an action - or registering a new async command - inherits the silent escape. Fix the entrypoint to `await buildProgram().parseAsync(argv)` inside an async IIFE before adding more async surfaces.

## Footgun: `gruff-ts init` only guards against `.gruff-ts.yaml`, not the four-name precedence list

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`writeDefaultConfig` (search: `function writeDefaultConfig`) calls `existsSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME))` to decide whether to refuse a write. But config resolution treats four names as interchangeable defaults via `DEFAULT_CONFIG_FILES` (search: `const DEFAULT_CONFIG_FILES`): `.gruff-ts.yaml`, `.gruff.json`, `.gruff.yaml`, `.gruff.yml`, with `.gruff-ts.yaml` first (highest precedence). Reproduced in `/tmp/init-clobber-test/`: with only `.gruff.yaml` present, `gruff-ts init` printed `Wrote .gruff-ts.yaml` with no warning and the project's effective config silently switched to the registry-derived default. Use `defaultConfigPath(projectRoot)` (already exported from `src/config.ts`) when deciding to refuse, and treat `--force` as the explicit override. Same precedence list governs every other code path that "the default config" means - adding a fifth name without updating both `DEFAULT_CONFIG_FILES` and the init guard repeats this trap.

## Footgun: `--format` argParser wiring is inconsistent across commands

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`src/cli-program.ts` defines `parseSummaryFormat` (search: `function parseSummaryFormat`) as a Commander argParser that throws `InvalidArgumentError` on anything other than `text` or `json`. `registerListRulesCommand` wires it in; `registerSummaryCommand` does not (search: `Output format: text or json.`). Instead, `summary` declares the option with no parser, forces `format: "text"` for the analyser run via `normalizeOptions`, and then coerces the *summary render* format with `rawOptions.format === "json" ? "json" : "text"` (search: `const summaryFormat`). Reproduced: `gruff-ts summary fixtures --format=garbage --no-config --no-baseline` prints normal text output with exit 0; `gruff-ts list-rules --format=garbage` errors with `argument 'garbage' is invalid`. Silent coercion breaks CI jobs that expect JSON - a typo like `--format=jsno` exits zero with text and downstream parsing fails on an unrelated line. When adding a `--format` flag to another command, decide explicitly: argParser everywhere, or silent fallback everywhere. The current half-and-half is the trap.

## Footgun: `shouldPromptForInit` gates on stdin/stderr TTY but not stdout

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`shouldPromptForInit` (search: `function shouldPromptForInit`) checks `context.isStdinTty` and `context.isStderrTty`, but `InitPromptContext` (search: `interface InitPromptContext`) has no `isStdoutTty` field and `buildInitPromptContext` (search: `function buildInitPromptContext`) never reads `process.stdout.isTTY`. The pipeline-from-TTY-parent case stays unguarded: `gruff-ts analyse . --format=json | jq ...` invoked from an interactive shell still has both stdin and stderr as TTYs while stdout is a pipe, so the prompt fires on stderr and the pipeline blocks waiting for input the user is not expecting to provide. Add `isStdoutTty` to the context and require it true before prompting (or invert: require none of the three streams to be a pipe). Any future expansion of "is this run interactive?" must reason about all three streams, not just two.
