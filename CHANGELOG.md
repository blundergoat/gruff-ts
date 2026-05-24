# Changelog

## [0.1.1] - 2026-05-24

Onboarding flow, machine-readable summaries, and a `waste` →
`maintainability` pillar rename. Catalogue is now 119 rules across 11
pillars.

### Breaking changes

- **Pillar `waste` → `maintainability`.** Rule IDs are unchanged (still
  `waste.any-type`, `waste.console-log`, etc.) so existing
  `.gruff-ts.yaml` configs keep working without edits. But every
  consumer of the pillar *name* must update: text / JSON / SARIF output
  parsers, dashboard navigation, and the exported `Pillar` TypeScript
  union (which no longer includes `"waste"`).
- **Rules removed: `docs.todo-density`, `naming.abbreviation`.** Both
  were opt-in advisories, disabled by default. If either was enabled in
  your `.gruff-ts.yaml`, the rule entry is now silently ignored.
- **Config key removed: `allowlists.abbreviationDenylist`** (consumed
  only by the removed `naming.abbreviation` rule). Silently ignored;
  delete it from `.gruff-ts.yaml` when convenient.

### Added

- **`gruff-ts init`** writes the default `.gruff-ts.yaml` to the current
  directory. Refuses to overwrite when any of the supported config names
  (`.gruff-ts.yaml`, `.gruff.json`, `.gruff.yaml`, `.gruff.yml`) is
  already present; `--force` overrides. When `--force` regenerates an
  existing `.gruff-ts.yaml`, the file's `paths.ignore` entries are
  preserved. A successful write prints the recommended adoption-flow
  next steps (generate a baseline, then gate new findings).
- **Auto-prompt for `init`** in `analyse`, `summary`, `report`, and
  `dashboard` when no config is found in the project. Gated by
  `--no-interaction`, output suppression (`--silent`/`--quiet`), and
  TTY checks on stdin, stdout, and stderr — the prompt never fires in
  pipelines, CI, or scripted runs.
- **`summary --format=json`** emits a machine-readable digest under the
  new stable schema `gruff.summary.v1` (joins the existing
  `gruff.analysis.v1`, `gruff.baseline.v1`, and `gruff.hotspot.v1`).
- **`summary --top <n>`** controls how many top rules and file
  offenders the digest lists (default 10).
- **Baseline status line** in `summary` output, surfacing the
  baseline source and how many findings it suppressed.
- **`dashboard --project-root <path>`** sets the default project root
  the dashboard scans.
- **Docs**: `docs/README.md` (index), `docs/ci-integration.md`,
  `docs/dashboard.md`, `docs/output-formats.md`, and
  `docs/rules.md` (catalogue reference).
- **CI**: `npm audit --audit-level=moderate` gate in `.github/workflows/ci.yml`.

### Fixed

- `summary --format` and `list-rules --format` reject unsupported values
  with a Commander usage error instead of silently coercing to `text` —
  typos like `--format=jsno` no longer exit zero with the wrong output.
- CLI entrypoint switched to `parseAsync`, so rejections inside async
  action handlers surface through Commander's error path with the right
  exit code instead of escaping as unhandled promise rejections.

### Changed

- Docs filenames lowercased: `docs/CONFIGURATION.md` →
  `docs/configuration.md`, `docs/RELEASING.md` → `docs/releasing.md`,
  `docs/REPORTS_AND_CI.md` → `docs/reports-and-ci.md`. Update bookmarks
  and external links.

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
