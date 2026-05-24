# Glossary - gruff-ts

Last reviewed 2026-05-24.

This glossary defines terms used by `gruff-ts`, its public reports, and local project memory. Keep shared gruff-family terms aligned with the sibling implementations; keep TypeScript/JavaScript-specific differences explicit rather than making them look identical.

## Scope

`gruff-ts` is the TypeScript/JavaScript implementation of the gruff quality-scanner family. The npm package is `@blundergoat/gruff-ts`; the CLI binary is `gruff-ts`; product code lives under `src/`.

## Shared Gruff Terms

### Analysis Report

The complete result of one scan: schema version, tool metadata, run metadata, paths, summary counts, score data, diagnostics, findings, baseline state, and optional history state. Native JSON uses `gruff.analysis.v1`.

### Baseline

A reviewed-finding suppression file. `gruff-ts` writes and reads `gruff.baseline.v1`; entries match findings by fingerprint, rule ID, and file path.

### Changed-Code Scan

A scan filtered to changed files. `--diff` accepts `working-tree`, `staged`, `unstaged`, or a base ref and uses local Git data only when requested.

### Confidence

The certainty tier attached to a finding: `low`, `medium`, or `high`. It helps consumers and reviewers distinguish high-signal findings from heuristic prompts.

### Dashboard

The local browser UI served by `gruff-ts dashboard`. It binds to `127.0.0.1:8767` by default and has no authentication; use `--port` when another gruff dashboard is already using the port.

### Diagnostic

A run-level problem such as `parse-error`, `read-error`, `missing-path`, or `history-error`. Fatal diagnostics force exit code `2`.

### Display Filter

A report-only filter or command option that changes rendered output after analysis. In `gruff-ts`, baseline suppression is available on `analyse`; `report` intentionally renders raw inspection output.

### Exit Codes

`0` means the run completed and no finding met the failure threshold. `1` means at least one finding met the threshold. `2` means a fatal diagnostic or invalid input stopped the requested scan from being fully trustworthy.

### Finding

One rule-produced result with rule ID, message, severity, confidence, pillar, location, remediation, metadata, and fingerprint.

### Fingerprint

A stable 16-character SHA-256 prefix of the finding identity. Baselines and downstream tooling key on it together with rule ID and file path.

### Gruff Config

Project configuration that tunes discovery, allowlists, naming lists, and per-rule thresholds/severity/options. Shared keys include `paths.ignore`, `allowlists.acceptedAbbreviations`, `allowlists.secretPreviews`, and `rules.<id>`.

### Hotspot Output

A compact JSON view of the worst file offenders for dashboards or trend tooling. `gruff-ts` emits it as `gruff.hotspot.v1`.

### Output Format

A renderer over the same analysis report. `analyse` supports `text`, `json`, `html`, `markdown`, `github`, `hotspot`, and `sarif`; `report` supports `html` and `json`.

### Pillar

The quality dimension a finding belongs to, such as `complexity`, `security`, `sensitive-data`, or `test-quality`. Pillars feed per-pillar scoring and display filters.

### Rule Catalogue

The set of built-in rules plus their public metadata. `list-rules --format=json` is the source of truth for rule IDs, pillars, severity, confidence, thresholds, options, and default enablement.

### Rule ID

Stable public identifier for one rule, using dotted gruff-family names such as `size.file-length`, `security.eval-call`, `docs.todo-without-tracking`, and `sensitive-data.high-entropy-string`. Documentation rules use `docs.*` while the emitted pillar is `documentation`.

### SARIF

Static Analysis Results Interchange Format. `gruff-ts` emits SARIF 2.1.0 from the same report data used by the other renderers.

### Score And Grade

The numeric and letter quality summary derived from findings after baseline and filter layers have been applied according to the current command.

### Secret Preview

A redacted representation of sensitive-data matches. Raw secret values must not appear in terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

### Severity And Failure Threshold

`gruff-ts` uses `advisory`, `warning`, and `error`. `--fail-on` controls exit code `1`; `none` reports findings without failing for severity.

### Source Discovery

The process that turns input paths into classifiable source, package metadata, and text/config files. `paths.ignore` always applies; `--include-ignored` opts into default-ignored and Git-ignored paths for deliberate inspection.

### Trust Boundary

Default scans are local source inspections. `gruff-ts` parses supported files and may call Git for explicit diff scans; it does not execute target application code, run tests, invoke the TypeScript compiler, query package registries, or read vulnerability feeds.

## Implementation-Specific Terms

### Supported File Type

`gruff-ts` scans TypeScript, JavaScript, CSS, JSON, YAML, TOML, INI, XML, and `.env*` files when they are discoverable and not ignored.

### Function Block

A regex-matched function-like unit used by per-function rules for size, complexity, naming, documentation, and test-quality checks. It is not a full TypeScript AST.

### Naming Surface

Metadata describing where a naming finding fired, such as declaration, parameter, destructuring, or interface field. Consumers can use it to split reports by origin.

### Config Fallback

Config discovery checks `.gruff-ts.yaml`, then `.gruff.json`, `.gruff.yaml`, and `.gruff.yml`. This differs from implementations that only support YAML or native package-file config.

### Naming Allowlist

Tunable config sets such as `acceptedAbbreviations`, `booleanPrefixes`, `knownAcronyms`, `placeholderNames`, and related naming policy lists. They intentionally reflect TypeScript/JavaScript naming conventions.

### Project Config Rule

A rule that inspects package/config files such as `package.json`, `tsconfig.json`, workflows, or tool metadata rather than TypeScript source alone.

### Dashboard Scan Endpoint

The dashboard `/scan` endpoint analyses filesystem paths from request parameters. The loopback bind is the primary safety boundary.

## Agent Workflow Terms

### GOAT Flow

Local agent workflow framework installed from `@blundergoat/goat-flow`. It provides skills, audit commands, safety references, and `.goat-flow/` project-memory directories.

### Agent-Owned Surface

Files one agent setup owns without widening scope. Claude owns `CLAUDE.md` and `.claude/**`; Codex owns `AGENTS.md` and `.codex/**`; shared agent skills live under `.agents/skills/**`.

### Learning Loop

Durable shared project-memory directories under `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, and `.goat-flow/decisions/`.
