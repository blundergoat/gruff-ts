# Changelog

## [0.1.2] - 2026-05-25

Cross-format Pillars table, `gruff.summary.v2` schema bump, and a preflight rework focused on internal version consistency rather than registry state.

- **Breaking**: `summary --format=json` now emits `gruff.summary.v2`. The flat `{pillar, count}` per-pillar array is replaced with a richer shape carrying `grade`, `score`, `penalty`, `applicable`, and per-severity counts (`findings`, `advisory`, `warning`, `error`). Downstream CI consumers parsing the payload must update.
- **Added**: cross-port harmonised 7-column Pillars table (pillar, grade, score, findings, advisory, warning, error) in the text, JSON, HTML, and Markdown summaries. Sort order is `findings DESC` then `pillar ASC`; pillars with zero findings render a clean `A/100` row so every applicable pillar stays visible.
- **Added**: `scripts/bump-version.sh --check` now verifies that `CHANGELOG.md`'s most-recent `## [version]` heading matches `package.json` / `package-lock.json` / `src/constants.ts`. The preflight gate's `Release version` step is renamed to `Version consistency` and only runs this consistency check - the prior `npm view` "already published" lookup was removed because it conflated "should we bump?" with "are the surfaces in sync?".
- **Added**: default `acceptedAbbreviations` list expanded with common identifier roots (`age`, `app`, `key`, `url`, etc.) so typical codebases avoid noisy `naming.identifier-quality` advisories out of the box.
- **Changed**: README CLI examples now use `npx gruff-ts …` instead of direct `node_modules/.bin/gruff-ts` invocations, matching the standard npm package usage path.
- **Changed**: HTML renderer and dashboard chrome moved from `report-renderers.ts` into a dedicated `report-html.ts` module, and the shared `buildPillarRows` + `grade` helpers moved into `pillar-summary.ts`. No output change; the split keeps each renderer module under the `size.file-length` threshold and removes the circular import between the renderer files.

## [0.1.1] - 2026-05-24

Onboarding flow, machine-readable summaries, and a `waste` → `maintainability` pillar rename. Catalogue is now 119 rules across 11 pillars.

- **Breaking**: pillar `waste` renamed to `maintainability` — rule IDs unchanged, but text/JSON/SARIF parsers, dashboard nav, and the `Pillar` TypeScript union must update. Rules `docs.todo-density` and `naming.abbreviation` removed (both opt-in advisories), along with the now-unused `allowlists.abbreviationDenylist` config key; stale entries are silently ignored.
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
