# gruff-ts

`gruff-ts` is an opinionated static analyzer for TypeScript and JavaScript projects. The dependency-light Node.js CLI scans source, tests, package metadata, and common config files, then emits reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard. It is heuristic static analysis; run it beside `tsc`, ESLint, tests, dependency scanners, and code review, not instead of them.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `0.1.0` package line |
| Runtime | Node.js `22+` |
| Package | `@blundergoat/gruff-ts` |
| Binary | `gruff-ts` |
| Rule catalogue | 119 rules across 11 pillars |
| Primary config | `.gruff-ts.yaml`; `.gruff.json`, `.gruff.yaml`, and `.gruff.yml` are fallback files |
| Analysis schema | `gruff.analysis.v1` |
| Baseline schema | `gruff.baseline.v1` |
| Severity gate | `--fail-on` with `none`, `advisory`, `warning`, `error` |
| Dashboard | `127.0.0.1:8767` by default |

Scanned file types include TypeScript, JavaScript, CSS, JSON, YAML, TOML, INI, XML, and `.env*`.

## Requirements

- Node.js `22+`, matching [`package.json`](package.json).
- npm for source-checkout development.
- Git only for diff modes.

## Install

Install as a project dev dependency:

```bash
npm install --save-dev @blundergoat/gruff-ts
./node_modules/.bin/gruff-ts init
./node_modules/.bin/gruff-ts summary
```

From this checkout:

```bash
npm install
./bin/gruff-ts analyse . --fail-on=none
```

## Quick Start

```bash
# Create the project config.
./node_modules/.bin/gruff-ts init

# Review the current finding mix.
./node_modules/.bin/gruff-ts summary

# Explore without failing because of findings.
./node_modules/.bin/gruff-ts analyse . --fail-on=none

# Gate on warning and error findings.
./node_modules/.bin/gruff-ts analyse . --fail-on=warning

# Emit SARIF for code scanning.
./node_modules/.bin/gruff-ts analyse . --format=sarif --fail-on=none > gruff-ts.sarif

# Generate a fresh-start baseline.
./node_modules/.bin/gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none

# Start the local dashboard.
./node_modules/.bin/gruff-ts dashboard
```

Open `http://127.0.0.1:8767/` for the dashboard.

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the analyzer and print findings. |
| `summary [paths...]` | Print compact score, pillar, rule, and file summaries. |
| `report [paths...]` | Render an HTML or JSON report to stdout or `--output`. |
| `init` | Write the default `.gruff-ts.yaml` to the current directory (`--force` to overwrite). |
| `list-rules` | Print rule metadata as text or JSON. |
| `dashboard` | Serve the local browser dashboard. |
| `completion [shell]` | Print a shell completion script for `bash`, `zsh`, or `fish`. |
| `list`, `help` | Show command lists and command-specific help. |

Global console options match the broader gruff CLI surface: `--silent`, `--quiet`, `--ansi` / `--no-ansi`, `--no-interaction`, and `-v` / `-vv` / `-vvv`.

## Output Formats

`analyse --format <fmt>` accepts:

| Format | Use it for |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full `gruff.analysis.v1` report. |
| `html` | Self-contained inspection report. |
| `markdown` | Pull-request or issue comment summary. |
| `github` | GitHub Actions workflow annotations. |
| `hotspot` | `gruff.hotspot.v1` file-offender JSON. |
| `sarif` | SARIF 2.1.0 for code scanning. |

`report --format <fmt>` accepts `html` and `json`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Run completed and no finding met `--fail-on`. |
| `1` | At least one finding met `--fail-on`. |
| `2` | Fatal diagnostic such as missing input, parse error, config error, diff failure, baseline failure, or invalid input. |

`analyse` defaults to `--fail-on error`.

## CI Usage

Generic CI command:

```bash
./node_modules/.bin/gruff-ts analyse . --format=github --fail-on=warning
```

SARIF jobs can write an artifact for code scanning:

```bash
./node_modules/.bin/gruff-ts analyse . --format=sarif --fail-on=none > gruff-ts.sarif
```

Security-focused gates can bypass adoption baselines:

```bash
./node_modules/.bin/gruff-ts analyse . --no-baseline --fail-on=error
```

## Configuration

`analyse` auto-loads the first supported config file it finds in the project root:

1. `.gruff-ts.yaml`
2. `.gruff.json`
3. `.gruff.yaml`
4. `.gruff.yml`

Use `--config <path>` for an explicit file or `--no-config` to skip config loading. Recursive scans respect root and nested `.gitignore` files; `--include-ignored` includes default and Git-ignored paths for one run, but `paths.ignore` entries still apply as project policy.

```yaml
paths:
  ignore:
    - "generated/**"

allowlists:
  acceptedAbbreviations:
    - api
    - cli
  secretPreviews: []

rules:
  complexity.cyclomatic:
    threshold: 10
    severity: warning
  size.file-length:
    threshold: 400
    severity: warning
```

See [Configuration](docs/configuration.md) for the full config shape.

## Rules And Pillars

The v0.1 catalogue contains 119 rules:

| Pillar | Rules |
| --- | ---: |
| `complexity` | 3 |
| `dead-code` | 1 |
| `design` | 6 |
| `documentation` | 17 |
| `maintainability` | 14 |
| `modernisation` | 14 |
| `naming` | 10 |
| `security` | 27 |
| `sensitive-data` | 8 |
| `size` | 4 |
| `test-quality` | 15 |

Use `./node_modules/.bin/gruff-ts list-rules --format=json` for exact rule IDs, severities, confidence levels, remediation text, thresholds, and options.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by stable fingerprint:

```bash
./node_modules/.bin/gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
./node_modules/.bin/gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
./node_modules/.bin/gruff-ts analyse . --no-baseline --fail-on=none
```

Changed-file scans use Git only when requested:

```bash
./node_modules/.bin/gruff-ts analyse . --diff=working-tree --format=github --fail-on=warning
./node_modules/.bin/gruff-ts analyse . --diff=staged --format=json --fail-on=none
```

`--diff` accepts `working-tree`, `staged`, `unstaged`, or a base ref. `report` renders raw inspection output and does not accept `--baseline`; use `analyse` when baseline suppression matters.

## Dashboard

```bash
./node_modules/.bin/gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

The dashboard serves a local iframe report and compact controls panel. It has no authentication; keep the default loopback bind unless the network is trusted. The `/scan` endpoint analyses filesystem paths from request parameters, so the bind address is the main safety boundary.

In polyglot repositories, `gruff-ts` defaults to port `8767`, `gruff-rs` defaults to `8766`, and `gruff-go`, `gruff-php`, and `gruff-py` default to `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are local source inspections. `gruff-ts` parses supported source, config, and package metadata files; it does not execute target application code, run tests, invoke the TypeScript compiler, query package registries, or read vulnerability feeds. Git is used only for explicit diff modes. Secret-like findings use redacted previews; raw secret values should not appear in terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

## Stability Contract

The `0.1.x` line treats rule IDs, finding fingerprints, baseline identity, `gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`, SARIF rendering, and CLI exit semantics as compatibility-sensitive. Breaking changes should be tagged as a future minor release and recorded in [`CHANGELOG.md`](CHANGELOG.md).

## How It Compares

| Tool | Relationship |
| --- | --- |
| `tsc` | Type checking. `gruff-ts` does not prove type correctness or replace compiler diagnostics. |
| ESLint | Rule-driven linting. `gruff-ts` adds scoring, baselines, reports, dashboard, and cross-file/project-quality signals. |
| Prettier / formatters | Formatting only. `gruff-ts` does not format code. |
| Knip / ts-prune | Focused unused export/dead-code tools. `gruff-ts` includes broader quality and security-oriented heuristics. |
| `npm audit` / dependency scanners | Advisory-backed dependency checks. `gruff-ts` reports local static signals and does not replace advisory feeds. |

## Development

```bash
npm install
npm run check
npm test
npm run start-dev
./bin/gruff-ts analyse . --fail-on=none
```

Source lives under `src/`: `src/cli.ts` is the bootstrap, `src/cli-program.ts` owns Commander wiring, `src/analyser.ts` orchestrates scans, and focused sibling modules own rules and renderers.

## Documentation

- [Changelog](CHANGELOG.md)
- [Configuration](docs/configuration.md)
- [Reports and CI](docs/reports-and-ci.md)
- [Release checklist](docs/releasing.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
