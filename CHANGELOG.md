# Changelog

## [0.1.2] - 2026-05-27

Pillars-table cross-format harmonisation, rule-precision tier, per-command gating threshold, and a CLI default flip. Multi-stage release: started 2026-05-25 with the renderer/schema-v2 work, picked up rule-precision improvements on 2026-05-26, and closed with the config-schema versioning and minimumSeverity block on 2026-05-27. See ADR-004 for the minimumSeverity design and `.goat-flow/tasks/0.1.2/` for the rule-precision milestones (M01-M08 + M10-M12; M09 was deleted as a no-signal milestone).

### Breaking

- `.gruff-ts.yaml` now requires a top-level `schemaVersion: gruff-ts.config.v0.1` field. Existing configs without it are rejected at load with a documented error pointing at the canonical version. Pre-1.0 hard break - no transitional shim. The new config-input schema (`gruff-ts.config.*`) lives in a separate namespace from the output schemas (`gruff.analysis.v2`, `gruff.summary.v2`, etc.) and the version numbers do not track together.
- `analyse` and `summary` default `--fail-on` flips from `error` to `advisory`. Every CI gate using the defaults goes from "fail on errors only" to "fail on anything." Operators that want the old behaviour pass `--fail-on=error` explicitly or pin `minimumSeverity.<cmd>: error` in `.gruff-ts.yaml`. `report` keeps `--fail-on=none` as it is intended for raw inspection, not gating.
- `summary --format=json` now emits `gruff.summary.v2`. The flat `{pillar, count}` per-pillar array is replaced with a richer shape carrying `grade`, `score`, `penalty`, `applicable`, and per-severity counts (`findings`, `advisory`, `warning`, `error`). Downstream CI consumers parsing the payload must update.
- `analyse` / `report --format=json` now emit `gruff.analysis.v2`. `score.pillars[]` entries gain a `penalty: number` field (the cumulative severity-weighted penalty subtracted from the pillar score). The SARIF `runs[0].properties.gruffSchemaVersion` and the schema tag in the JSON payload move from `gruff.analysis.v1` to `gruff.analysis.v2` in lockstep.
- `docs.missing-function-doc` (advisory) is replaced by two new rule IDs that split by exported-vs-internal surface (M04 §2.9):
  - `docs.missing-exported-function-doc` - **warning** severity. Fires on `export function foo()`, `export const foo = () => ...`, and `export default function ...`. Migration: any `.gruff-ts.yaml` severity override targeting the old rule ID should be updated. Consumers running `--fail-on warning` will see new failures from undocumented exports - either add leading comments, override the exported rule's severity to `advisory` in `.gruff-ts.yaml`, or disable the rule.
  - `docs.missing-internal-function-doc` - advisory severity. Fires on every non-test internal function without a leading comment, preserving the original advisory-tier signal for helpers.
  - Class methods of an exported class are treated as **internal** (advisory) by this release; tracking enclosing-class scope is deferred. `export default function ...` is detected by the existing block pattern; arrow assignments (`export const foo = () => ...`) work via an extended pattern-3 regex that now accepts the optional `export` prefix.

### Added

- Top-level `minimumSeverity:` block in `.gruff-ts.yaml` with per-command thresholds (`analyse / summary / report`). Precedence chain: CLI flag (`--fail-on`) > config block > binary default. `dashboard` is rejected as a key with a documented error (no `--fail-on` flag exists for it). The validator rejects unknown commands, unknown values, and the legacy `never` alias with clear, actionable errors. New `minimumSeverityFor(config, command)` helper exported from `src/config.ts` for direct CLI consumption.
- `gruff-ts init` and `gruff-ts init --force` now emit the `schemaVersion:` and `minimumSeverity:` blocks at the top of the generated `.gruff-ts.yaml`. `init --force` preserves existing values for both fields plus `paths.ignore`, mirroring the existing preservation pattern.
- ADR-004 records the minimumSeverity design (per-command vs verb wording, `none`-over-`never` flip, namespace coexistence, cross-port harmony).
- Cross-port harmonised 7-column Pillars table (pillar, grade, score, findings, advisory, warning, error) in the text, JSON, HTML, and Markdown summaries. Sort order is `findings DESC` then `pillar ASC`; pillars with zero findings render a clean `A/100` row so every applicable pillar stays visible.
- Per-severity grade breakdown in human summaries and a `quality N.N/100` legend on top-offender lines (M05). Text, summary, markdown, and HTML render three lines below the composite (`Errors: A (0)`, `Warnings: D (276)`, `Advisory: F (1367)`) so an operator can see whether an F is driven by errors or by a long tail of advisories; the headline composite grade and number stay unchanged. HTML adds three grade pills under the verdict headline using the existing `.grade-pill.a/.b/.c/.d/.f` CSS classes. JSON output is byte-stable: no new fields in the score block, schema string still `gruff.analysis.v2`.
- `summary` Top-N rules block renders each row with a per-severity split and the rule's one-line description (M07): `- <ruleId>: <total> (<err> err / <warn> warn / <adv> adv) - <description>`. Descriptions longer than 60 characters are truncated with `...`. Sort order is unchanged (`count DESC, ruleId ASC`). When `analyse` finds at least 50 findings, the text reporter appends a one-line `Tip:` pointing at `gruff-ts summary --top=20`.
- `gruff-ts list-rules <ruleId>` accepts an optional positional argument and prints per-rule detail (text or JSON) (M08). Text mode shows `Rule / Pillar / Severity / Confidence / Threshold / Description / Remediation` plus a `Config keys:` block listing `rules.<ruleId>.{enabled,severity,threshold}` and (when present) `Options:` and `Allowlists:` sections. JSON mode wraps the descriptor in a `{ tool, rule: { ..., configKeys: [...] } }` envelope. Unknown rule IDs exit with code 2 and a clear stderr message. The no-argument behaviour is byte-identical to the prior version.
- Every rule with a tunable knob (threshold / optionKeys / allowlists) now points at the config override knob from its `remediation` text (M06). `RuleDescriptor` gains an optional `allowlistKeys: readonly string[]` field; seven naming rules (`naming.acronym-case`, `naming.boolean-prefix`, `naming.generic-function`, `naming.hungarian-notation`, `naming.identifier-quality`, `naming.negative-boolean`, `naming.short-variable`) are annotated. JSON `list-rules` output gains the field; no existing fields change. A new catalogue assertion locks in the threshold/optionKeys/allowlistKeys coverage so future rules cannot slip past the surfacing contract.
- Nine imperative-flag verbs (`check`, `skip`, `enable`, `allow`, `include`, `exclude`, `with`, `without`, `omit`) added to the default `booleanPrefixes` set (M02 §2.4). Option-bag booleans like `checkDrift`, `skipAuto`, `includeMetadata` no longer trip `naming.boolean-prefix`. The default set is now 22 entries.
- `fn` and `cb` added to the default `acceptedAbbreviations` set (M02 §2.8a). Universal conventions for "function parameter" and "callback parameter" no longer trip `naming.short-variable`. The default set is now 18 entries.
- `naming.short-variable` now exempts single-character bindings inside a `for (const X of Y) { ... }` body whose body span is `<= 10` lines (M02 §2.8b). Longer bodies still fire (the binding outlives the locally-obvious scope). Brace-less single-statement bodies return as short.
- `scripts/bump-version.sh --check` verifies that `CHANGELOG.md`'s most-recent `## [version]` heading matches `package.json` / `package-lock.json` / `src/constants.ts`. The preflight gate's `Release version` step is renamed to `Version consistency` and only runs this consistency check - the prior `npm view` "already published" lookup was removed because it conflated "should we bump?" with "are the surfaces in sync?".
- Graceful config-error handling for the `analyse` / `summary` / `report` commands. A malformed `.gruff-ts.yaml` (missing `schemaVersion`, unknown `minimumSeverity` value, `dashboard:` key, YAML parse failure, etc.) now produces a clean two-paragraph stderr message - the error itself plus a context-appropriate suggested fix (e.g. `Run \`gruff-ts init --force\``) - and exits with code 2. No raw Node stack trace. New `ConfigLoadError` class in `src/config-load-error.ts` carries the message + suggestion; CLI action handlers wrap their bodies in `runWithConfigErrorHandling` and rethrow every other exception so genuine bugs still surface their stack. `--config` pointing at a missing file and malformed `.gruff.json` syntax errors are rewrapped at the producer boundary in `parseConfigFile` / `readConfigSource` so they reach the same formatted exit-2 path instead of dumping raw `ENOENT` / `SyntaxError` stacks.
- `src/config-preservation.ts` exports `extractPreservedConfigFields(configPath)` for the init-force migration path: best-effort extraction of `paths.ignore` and `minimumSeverity` without the schemaVersion gate, so pre-schemaVersion configs still hand their curated entries to the regenerated file. `src/config.ts` now exports `parseConfigFile` for reuse by the preservation module.

### Changed

- `waste.swallowed-catch` accepts six additional bare-token rationale comments (M01 §2.2): `/* ignore */`, `/* ignored */`, `/* cleanup */`, `/* teardown */`, `/* noop */`, `/* no-op */`. `/* silent */` is deliberately excluded - real swallowed-error defects in goat-flow's dashboard-projects.ts use that token and must keep firing.
- `test-quality.loop-in-test` recognises fixture loops (parametric coverage pattern) and suppresses the finding for them (M03 §2.6). A loop qualifies when (a) the iterable is a literal array `[...]` or `Object.entries|keys|values(literal)` AND (b) the body has no `if`/`switch`/`case`/`default` AND (c) the body's last meaningful statement is an `assert.*(...)`, `expect(...)`, or `...shouldBe(...)` call. Dynamic iterables, state-building loops, and conditional bodies inside the loop still fire. (§2.7a pathThresholds is deferred - see milestone file for rationale.)
- README CLI examples now use `npx gruff-ts ...` instead of direct `node_modules/.bin/gruff-ts` invocations, matching the standard npm package usage path.
- HTML renderer and dashboard chrome moved from `report-renderers.ts` into a dedicated `report-html.ts` module, and the shared `buildPillarRows` + `grade` helpers moved into `pillar-summary.ts`. No output change; the split keeps each renderer module under the `size.file-length` threshold and removes the circular import between the renderer files.

### Fixed

- `waste.unreachable-code` no longer fires on the unconditional return that follows a braceless `if`/`while`/`for` with a multi-line predicate (M01 §1). The per-line walker now tracks open-paren balance across the predicate's lines so `if (\n  a &&\n  b\n)\n  return X;\nreturn Y;` correctly treats both returns as reachable. The single-line braceless guard (existing FP-#4) keeps working unchanged; genuine unreachable code (FP-#15) still fires.
- `scripts/bump-version.sh` `read_changelog_latest_version` now requires a digit immediately after `[` in the `## [...]` heading, so a future Keep-a-Changelog `## [Unreleased]` section above the latest release stops causing a false lockstep failure in the preflight version-consistency check.
- `naming.short-variable` for-of body exemption (M02 §2.8b) no longer leaks to classic `for (let i = 0; ...)` and `for (const k in obj)` headers. The exemption gate now verifies an `of` token follows the binding in the header rather than keying off the regex match prefix, so the documented for-of-only scope holds.
- `gruff-ts init --force` preserves `paths.ignore` and `minimumSeverity` blocks from configs that pre-date the `schemaVersion:` requirement. The previous strict-loader path threw on the missing field and silently dropped curated entries; the new `src/config-preservation.ts` module reads the two blocks permissively for the migration handoff while the analyser load path still uses the strict validator.
- `docs.missing-exported-function-doc` (warning) fires on locally-declared functions re-exported via `export { foo }` or `export default foo`. Line-local `^export` detection in `src/blocks.ts:functionBlockFromMatch` previously classified the re-export pattern as internal and emitted only the advisory variant; a new file-level `collectReExportedNames` scan is OR'd into the `isExported` decision so the public-API doc gate covers the pattern.
- `CLAUDE.md` and `README.md` switched from "analyzer" to "analyser" to match `src/analyser.ts` and the rest of the project's British spelling (modernisation, sensitive-data).

### Lock-in tests

FP-#12 through FP-#45 added to `src/false-positive-fixes.test.ts`, covering every rule-precision change above plus negative regression guards. The PR #4 review sweep added FP-#33b / FP-#33c for re-export detection in the same file, the C-style for / for-in regression cases under `naming-rules.test.ts`, the pre-schemaVersion preservation regression in `src/init-config.test.ts`, and the dedicated `src/config-preservation.test.ts` suite. M06 / M08 land their tests in `src/rule-catalogue.test.ts` and `src/cli-surfaces.test.ts` respectively. M10-M12 (minimumSeverity track) add parser-rejection tests in `src/project-config-rules.test.ts` and an init-preservation regression test in `src/init-config.test.ts`. M09 (informational tier) was deleted as a no-signal milestone.

### Cross-port status

Aligns with the family-wide `minimumSeverity:` dimension; `gruff-go` / `gruff-rs` / `gruff-py` / `gruff-php` should track. Off-switch value is `none` (not `never`) per the linguistic re-evaluation - the noun position of `minimumSeverity:` favors `none`.

## [0.1.1] - 2026-05-24

Onboarding flow, machine-readable summaries, and a `waste` → `maintainability` pillar rename. Catalogue is now 119 rules across 11 pillars.

- **Breaking**: pillar `waste` renamed to `maintainability` - rule IDs unchanged, but text/JSON/SARIF parsers, dashboard nav, and the `Pillar` TypeScript union must update. Rules `docs.todo-density` and `naming.abbreviation` removed (both opt-in advisories), along with the now-unused `allowlists.abbreviationDenylist` config key; stale entries are silently ignored.
- **Added**: `gruff-ts init` writes the default `.gruff-ts.yaml`, refusing to overwrite any supported config name without `--force` (which preserves existing `paths.ignore` entries). `analyse`, `summary`, `report`, and `dashboard` auto-prompt for `init` when no config is found, gated by `--no-interaction`, `--silent`/`--quiet`, and TTY checks so it never fires in CI.
- **Added**: `summary --format=json` emits the new `gruff.summary.v1` schema; `summary --top <n>` controls digest size; a baseline status line surfaces source and suppression count. `dashboard --project-root <path>` sets the default scan root.
- **Added**: docs index (`docs/README.md`) plus `ci-integration.md`, `dashboard.md`, `output-formats.md`, `rules.md`; CI now runs `npm audit --audit-level=moderate`.
- **Fixed**: `summary`/`list-rules` `--format` rejects unsupported values via Commander instead of coercing to `text`; CLI switched to `parseAsync` so async handler rejections exit with the correct code.
- **Fixed**: `summary --top <n>` now actually controls file-offender count beyond 10. `gruff.analysis.v1` `score.topOffenders` is now the full sorted file list (was capped at 10); HTML report and `--format=hotspot` still cap their own output at 10 rows. `init --force` help text now reflects that it also overrides the refusal triggered by non-canonical configs (`.gruff.yaml`/`.yml`/`.json`). `--top` added to the known-CLI-flag list so comments documenting it no longer trip `docs.stale-comment`.
- **Changed**: docs filenames lowercased (`CONFIGURATION.md` → `configuration.md`, `RELEASING.md` → `releasing.md`, `REPORTS_AND_CI.md` → `reports-and-ci.md`).

## [0.1.0] - 2026-05-23

Initial public release of the `@blundergoat/gruff-ts` npm package.

- TypeScript/JavaScript code quality scanner: 121 rules across 11 pillars
  (complexity, dead-code, design, documentation, maintainability,
  modernisation, naming, security, sensitive-data, size, test-quality).
- CLI commands: `analyse`, `summary`, `report`, `list-rules`, `dashboard`,
  `completion`.
- Output formats: `text`, `json`, `html`, `markdown`, `github`, `hotspot`,
  `sarif`. Stable schemas: `gruff.analysis.v1`, `gruff.baseline.v1`,
  `gruff.hotspot.v1`.
- Baselines via stable per-finding fingerprints, `--diff` for changed-file
  scans, local dashboard on `127.0.0.1:8767`. Released under MIT.
