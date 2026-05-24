# Changelog

## [0.1.1] - 2026-05-24

Onboarding flow, machine-readable summaries, and a `waste` → `maintainability` pillar rename. Catalogue is now 119 rules across 11 pillars.

- **Breaking**: pillar `waste` renamed to `maintainability` — rule IDs unchanged, but text/JSON/SARIF parsers, dashboard nav, and the `Pillar` TypeScript union must update. Rules `docs.todo-density` and `naming.abbreviation` removed (both opt-in advisories), along with the now-unused `allowlists.abbreviationDenylist` config key; stale entries are silently ignored.
- **Added**: `gruff-ts init` writes the default `.gruff-ts.yaml`, refusing to overwrite any supported config name without `--force` (which preserves existing `paths.ignore` entries). `analyse`, `summary`, `report`, and `dashboard` auto-prompt for `init` when no config is found, gated by `--no-interaction`, `--silent`/`--quiet`, and TTY checks so it never fires in CI.
- **Added**: `summary --format=json` emits the new `gruff.summary.v1` schema; `summary --top <n>` controls digest size; a baseline status line surfaces source and suppression count. `dashboard --project-root <path>` sets the default scan root.
- **Added**: docs index (`docs/README.md`) plus `ci-integration.md`, `dashboard.md`, `output-formats.md`, `rules.md`; CI now runs `npm audit --audit-level=moderate`.
- **Fixed**: `summary`/`list-rules` `--format` rejects unsupported values via Commander instead of coercing to `text`; CLI switched to `parseAsync` so async handler rejections exit with the correct code.
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
