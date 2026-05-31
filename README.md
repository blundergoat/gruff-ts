# gruff-ts

`gruff-ts` governs AI-generated code. Wired in as a coding-agent hook, it forces the agent to produce changes a human who did not write them can actually sign off on: legible enough to verify by reading, secure where the human eye slips, and tested for real behaviour instead of padded with low-signal ceremony. Mechanically it is a dependency-light, opinionated static analyser for TypeScript and JavaScript - it scans source, tests, package metadata, and common config files, then emits reports for terminals, CI annotations, SARIF consumers, static HTML, and a local dashboard. It is heuristic static analysis; run it beside `tsc`, ESLint, tests, dependency scanners, and code review, not instead of them.

## Why gruff-ts Exists

The reviewer of AI-generated code is not its author. A coding agent holds the full context while it writes; the human who has to read, review, and trust the result does not. Conventional linters optimise for the author who already understands the code and just wants it tidy. gruff-ts optimises for that reviewer instead, which is the position every human signing off on an agent's output is in.

That goal breaks into three:

- **Verifiable.** A reviewer can read the change and confirm it does what was asked, rather than re-deriving what the agent was thinking. The complexity, size, naming, and documentation pillars push toward code whose intent is visible on its face.
- **Secure where the eye slips.** Human review reliably scans past a known set of unsafe patterns - disabled TLS verification, `eval` and dynamic `Function` construction, injection-shaped string building, committed secrets. The security and sensitive-data pillars catch those mechanically so the reviewer does not have to.
- **Honestly tested.** A suite should raise confidence, not just coverage. The test-quality pillar flags low-signal ceremony - mock-only, snapshot-only, assertion-free, and tautological tests - so an agent cannot satisfy a "write tests" instruction with padding.

Documentation rules carry extra weight here, which is why a doc comment is expected even on a private one-liner. Coding agents routinely produce code that superficially works while misunderstanding the requirement. Forcing the agent to state intent, usage, contract, and failure behaviour in prose gives a reviewer something to check the implementation against - a mismatch between the doc comment and the code is itself a signal that the change needs a deeper look.

Used as a hook on an agent's output, gruff-ts is a forcing function rather than advice: a finding is friction the agent must resolve before the change reaches a human, so what finally lands is already shaped for sign-off. See [Philosophy](docs/philosophy.md) for the longer form.

## Status At A Glance

| Field | Value |
| --- | --- |
| Release line | Published `0.3.0` package line |
| Runtime | Node.js `22+` |
| Package | `@blundergoat/gruff-ts` |
| Binary | `gruff-ts` |
| Rule catalogue | 120 rules across 11 pillars |
| Primary config | `.gruff-ts.yaml`; `.gruff.json`, `.gruff.yaml`, and `.gruff.yml` are fallback files |
| Analysis schema | `gruff.analysis.v2` |
| Baseline schema | `gruff.baseline.v1` |
| Severity gate | `--fail-on` with `none`, `advisory`, `warning`, `error` |
| Dashboard | `127.0.0.1:8767` by default |

Scanned file types include TypeScript, JavaScript, JSON, YAML, TOML, INI, XML, and `.env*`.

## Requirements

- Node.js `22+`, matching [`package.json`](package.json).
- npm for source-checkout development.
- Git only for diff modes.

## Install

Install as a project dev dependency:

```bash
npm install --save-dev @blundergoat/gruff-ts
npx gruff-ts init
npx gruff-ts summary
```

From this checkout:

```bash
npm install
./bin/gruff-ts analyse . --fail-on=none
```

## Quick Start

```bash
# Create the project config.
npx gruff-ts init

# Review the current finding mix.
npx gruff-ts summary

# Explore without failing because of findings.
npx gruff-ts analyse . --fail-on=none

# Gate on warning and error findings.
npx gruff-ts analyse . --fail-on=warning

# Emit SARIF for code scanning.
npx gruff-ts analyse . --format=sarif --fail-on=none > gruff-ts.sarif

# Generate a fresh-start baseline.
npx gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none

# Start the local dashboard.
npx gruff-ts dashboard
```

Open `http://127.0.0.1:8767/` for the dashboard.

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the analyser and print findings. |
| `summary [paths...]` | Print compact score, pillar, rule, and file summaries. |
| `report [paths...]` | Render an HTML or JSON report to stdout or `--output`. |
| `init` | Write the default `.gruff-ts.yaml` to the current directory (`--force` to overwrite). |
| `list-rules` | Print rule metadata as text or JSON. |
| `list-profiles` | Print the built-in profiles (`gruff.minimal`, `gruff.recommended`, `gruff.strict`) with their rule-count summary, as text or JSON. |
| `check-ignore <paths...>` | Report whether each path is ignored (config, gitignore, or default) with the matching source and pattern; runs no analysis. |
| `dashboard` | Serve the local browser dashboard. |
| `completion [shell]` | Print a shell completion script for `bash`, `zsh`, or `fish`. |
| `list`, `help` | Show command lists and command-specific help. |

Global console options match the broader gruff CLI surface: `--silent`, `--quiet`, `--ansi` / `--no-ansi`, `--no-interaction`, and `-v` / `-vv` / `-vvv`.

## Output Formats

`analyse --format <fmt>` accepts:

| Format | Use it for |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full `gruff.analysis.v2` report. |
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

`analyse` and `summary` default to `--fail-on advisory`; `report` defaults to `--fail-on none`. The defaults can be overridden per-project by a `minimumSeverity:` block in `.gruff-ts.yaml`. CLI flag wins over config; config wins over the binary default. See ADR-004 and the Configuration section.

## CI Usage

Generic CI command:

```bash
npx gruff-ts analyse . --format=github --fail-on=warning
```

SARIF jobs can write an artifact for code scanning:

```bash
npx gruff-ts analyse . --format=sarif --fail-on=none > gruff-ts.sarif
```

Security-focused gates can bypass adoption baselines:

```bash
npx gruff-ts analyse . --no-baseline --fail-on=error
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
  acceptedBooleanNames:
    - verbose
    - enabled
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

## Profiles

A `profile:` selects a named bundle of rules instead of enumerating every rule by hand. Three profiles ship with the binary:

| Profile | Intent |
| --- | --- |
| `gruff.minimal` | Security and sensitive-data rules only - the smallest sanity gate for incremental adoption. |
| `gruff.recommended` | Every pillar at its default threshold and severity - identical to gruff's zero-config behaviour. |
| `gruff.strict` | Every pillar enabled with tightened size, complexity, and secret thresholds for high-bar repositories. |

`gruff-ts list-profiles` prints them with their enabled-rule counts. Select one in config or on the CLI:

```yaml
# Shorthand: the whole profile in one line.
profile: recommended
```

```yaml
# Compose: extend a built-in, then override a few rules or add ignored paths.
profile:
  extends: gruff.recommended      # a built-in name OR a relative path like ./team-profile.yaml
  rules:
    complexity.cyclomatic:
      threshold: 12
    docs.missing-public-doc:
      enabled: false
  ignoredPaths:
    - "examples/**"
```

`--profile <name-or-path>` applies a profile for one run (on `analyse`, `report`, `summary`, and `dashboard`) and overrides a config-file `profile:`. The value is a built-in name (the bare `minimal` / `recommended` / `strict` short forms are accepted too) or a path to a `.yaml`/`.yml`/`.json` profile file.

Semantics:

- **Precedence (highest first):** `--profile` flag, config `profile:` block, the `extends:` base chain, the built-in default `gruff.recommended`. A top-level `rules:` entry still overrides the profile for that rule.
- **`extends:`** accepts a built-in name or a relative file path - never a remote URL, never shell. A shared profile file's top level is itself a profile spec (`extends` / `rules` / `ignoredPaths`).
- **Last-wins, deterministic:** a child profile's per-rule fields override the parent's same-rule fields, and a child `ignoredPaths` array replaces (does not concatenate) the parent's.
- **Validated at load time:** an unknown built-in name resolved as a missing file, a missing `extends:` file, an `extends:` cycle, and a rule id outside the catalogue all fail with a clear error before any scan runs.

## Rules And Pillars

The v0.1 catalogue contains 120 rules:

| Pillar | Rules |
| --- | ---: |
| `complexity` | 2 |
| `dead-code` | 1 |
| `design` | 6 |
| `documentation` | 17 |
| `maintainability` | 14 |
| `modernisation` | 14 |
| `naming` | 10 |
| `security` | 27 |
| `sensitive-data` | 10 |
| `size` | 3 |
| `test-quality` | 15 |

Use `npx gruff-ts list-rules --format=json` for exact rule IDs, severities, confidence levels, remediation text, thresholds, and options.

## Baselines And Changed-Code Scans

Baselines suppress reviewed findings by stable fingerprint:

```bash
npx gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
npx gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
npx gruff-ts analyse . --no-baseline --fail-on=none
```

Changed-file scans use Git only when requested:

```bash
npx gruff-ts analyse . --diff=working-tree --format=github --fail-on=warning
npx gruff-ts analyse . --diff=staged --format=json --fail-on=none
```

`--diff` accepts `working-tree`, `staged`, `unstaged`, or a base ref. `report` renders raw inspection output and does not accept `--baseline`; use `analyse` when baseline suppression matters.

Changed-region scans keep only findings attributable to the changed hunk or its enclosing symbol:

```bash
npx gruff-ts analyse --format=json --changed-ranges "3-3,8-10" src/foo.ts
npx gruff-ts analyse --format=json --since HEAD src/foo.ts
git diff | npx gruff-ts analyse --format=json --diff -
```

JSON output keeps the normal `findings` array and adds `suppressedCount` when changed-region filtering is active.

## Dashboard

```bash
npx gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

The dashboard serves a local iframe report and compact controls panel. It has no authentication; keep the default loopback bind unless the network is trusted. The `/scan` endpoint analyses filesystem paths from request parameters, so the bind address is the main safety boundary.

In polyglot repositories, `gruff-ts` defaults to port `8767`, `gruff-rs` defaults to `8766`, and `gruff-go`, `gruff-php`, and `gruff-py` default to `8765`; use `--port` when running multiple dashboards at the same time.

## Trust Boundary

Default scans are local source inspections. `gruff-ts` parses supported source, config, and package metadata files; it does not execute target application code, run tests, invoke the TypeScript compiler, query package registries, or read vulnerability feeds. Git is used only for explicit diff modes. Secret-like findings use redacted previews; raw secret values should not appear in terminal, JSON, SARIF, GitHub, Markdown, hotspot, or HTML output.

## Stability Contract

The `0.3.x` line treats rule IDs, finding fingerprints, baseline identity, `gruff.analysis.v2`, `gruff.baseline.v1`, `gruff.hotspot.v1`, SARIF rendering, and CLI exit semantics as compatibility-sensitive. Breaking changes should be tagged as a future minor release and recorded in [`CHANGELOG.md`](CHANGELOG.md).

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
- [Rules catalogue](docs/rules.md)
- [Reports and CI](docs/reports-and-ci.md)
- [Release checklist](docs/releasing.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
