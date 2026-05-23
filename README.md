# gruff-ts

`gruff-ts` is a static analyzer for TypeScript and JavaScript projects. The
dependency-light Node.js CLI scans source, tests, package metadata, and
common config files, then reports quality findings across 11 pillars with
stable fingerprints for baselines and repeatable machine output.

The 0.1.0 release ships 121 rules across 11 pillars,
JSON/HTML/Markdown/GitHub/SARIF/hotspot output, baseline support, changed-file
filtering, local score history, a rule catalogue, and a dark local dashboard.
Scanned file types include TypeScript, JavaScript, CSS, JSON, YAML, TOML, INI,
XML, and `.env*`.

## Install

From npm after publishing:

```bash
npm install --save-dev gruff-ts
npx gruff-ts analyse . --fail-on=none
```

From this checkout:

```bash
npm install
./bin/gruff-ts analyse . --fail-on=none
```

## Quick Start

Run an exploratory scan without failing the shell on findings:

```bash
gruff-ts analyse . --fail-on=none
```

Scan specific paths:

```bash
gruff-ts analyse src fixtures/sample.ts --fail-on=none
```

Generate a static HTML report:

```bash
gruff-ts report . --output gruff-report.html
```

Start the local dashboard:

```bash
gruff-ts dashboard
```

The dashboard binds to `127.0.0.1:8767` by default.

## What It Checks

Findings are grouped into 11 public pillars:

- `size`
- `complexity`
- `dead-code`
- `waste`
- `naming`
- `documentation`
- `modernisation`
- `security`
- `sensitive-data`
- `test-quality`
- `design`

Inspect the exact rule ids, severities, confidence levels, remediation text,
threshold values, and options:

```bash
gruff-ts list-rules
gruff-ts list-rules --format=json
```

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the scanner and print findings. |
| `summary [paths...]` | Print per-pillar counts, top rules, and top file offenders without per-finding output. |
| `report [paths...]` | Render an HTML or JSON report, optionally to a file. |
| `list-rules` | Print rule catalogue metadata. |
| `dashboard` | Serve the local HTTP dashboard. |
| `completion [shell]` | Print a shell completion script for `bash`, `zsh`, or `fish`. |
| `list` | Print the Symfony-style command catalogue. |

Useful help commands:

```bash
gruff-ts --help
gruff-ts list
gruff-ts analyse --help
gruff-ts summary --help
gruff-ts report --help
gruff-ts dashboard --help
```

Global console options match the `gruff` PHP CLI surface: `--silent`,
`--quiet`, `--ansi` / `--no-ansi`, `--no-interaction`, and `-v` / `-vv` /
`-vvv`. The command menu uses the same ANSI colour treatment as `gruff` when
stdout is a TTY; `--ansi` forces colour and `--no-ansi` disables it.

## Output Formats

`analyse` supports:

| Format | Use case |
| --- | --- |
| `text` | Human terminal output. |
| `json` | Full machine-readable `gruff.analysis.v1` report. |
| `html` | Self-contained dark inspection report. |
| `markdown` | Short Markdown summary. |
| `github` | GitHub Actions annotation commands. |
| `hotspot` | Compact `gruff.hotspot.v1` top-offender payload. |
| `sarif` | SARIF 2.1.0 code-scanning output. |

Examples:

```bash
gruff-ts analyse . --format=json --fail-on=none
gruff-ts analyse . --format=github --fail-on=warning
gruff-ts analyse . --format=hotspot --fail-on=none
gruff-ts analyse . --format=sarif --fail-on=none > gruff.sarif
```

`report` supports `html` and `json`:

```bash
gruff-ts report . --format=json --output gruff-report.json
```

## CI

`analyse` defaults to `--fail-on error`.

```bash
# Exploratory scan: never fail because of findings.
gruff-ts analyse . --fail-on=none

# CI gate only on error findings.
gruff-ts analyse . --fail-on=error

# Stricter CI gate on warnings and errors.
gruff-ts analyse . --fail-on=warning
```

Exit codes:

- `0`: scan completed and no finding met `--fail-on`.
- `1`: scan completed and at least one finding met `--fail-on`.
- `2`: scan produced diagnostics such as missing inputs or parse/config errors.

Changed-file scans:

```bash
gruff-ts analyse . --diff=working-tree --format=github --fail-on=warning
gruff-ts analyse . --diff=staged --format=json --fail-on=none
```

`--diff` accepts `working-tree`, `staged`, `unstaged`, or a base ref.

Security-focused CI can run without baseline suppression so new error-severity
security or sensitive-data findings cannot be hidden by an adoption baseline:

```bash
gruff-ts analyse . --no-baseline --fail-on=error
```

## Baselines And History

Baselines suppress existing findings by stable fingerprint so teams can adopt
the tool without fixing every current issue first.

```bash
gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
gruff-ts analyse . --no-baseline --fail-on=none
```

Baseline files use `schemaVersion: "gruff.baseline.v1"`.

`report` is intended for raw inspection output and does not accept
`--baseline`; use `analyse` when you need baseline suppression in CI.

Append local score history:

```bash
gruff-ts analyse . --history-file .gruff-history.json --fail-on=none
```

## Configuration

`analyse` auto-loads the first supported config file it finds in the project root:

1. `.gruff-ts.yaml`
2. `.gruff.json`
3. `.gruff.yaml`
4. `.gruff.yml`

Use an explicit config or skip config loading:

```bash
gruff-ts analyse . --config .gruff-ts.yaml
gruff-ts analyse . --no-config
```

Recursive scans respect root and nested `.gitignore` files. Use
`--include-ignored` to include default and Git-ignored paths for a run;
`paths.ignore` entries still apply as project policy.

Minimal YAML example:

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

See [Configuration](docs/CONFIGURATION.md) for the full config shape and
examples.

## Dashboard

Start the local dashboard:

```bash
gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

The dashboard serves a local iframe report and a compact controls panel. Keep
the default loopback bind unless the network is trusted. The `/scan` endpoint
analyses filesystem paths from request parameters, so the bind address is the
main safety boundary.

## Safety And Limitations

- Secret-like findings include redacted previews; raw secret values should not
  appear in findings or rendered output.
- The scanner is heuristic. It is not a TypeScript compiler, type checker, or
  full JavaScript parser.
- Rule confidence is included in the rule catalogue and each finding. Treat low
  and medium confidence findings as review prompts.
- Baselines suppress matching fingerprints. Review baseline diffs carefully so
  new findings are not hidden by accident.

## Documentation

- [Changelog](CHANGELOG.md)
- [Configuration](docs/CONFIGURATION.md)
- [Reports and CI](docs/REPORTS_AND_CI.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Release checklist](docs/RELEASING.md)

## Development

```bash
npm install
npm run check
npm test
npm run start-dev
./bin/gruff-ts analyse . --fail-on=none
```

Source lives under `src/`: `src/cli.ts` is the thin bootstrap,
`src/cli-program.ts` owns Commander wiring, `src/analyser.ts` orchestrates the
scan, `src/rules.ts` holds the descriptor catalogue, and focused sibling
modules own rule packs and renderers. Tests live in focused `src/*.test.ts`
files.

To bump the released version, run `scripts/bump-version.sh <new-version>` - it
updates `package.json` and `src/constants.ts` in lockstep so the CLI
`--version` output stays consistent with the published package.

## Author

Built by [Matthew Hansen](https://www.blundergoat.com/about).

## License

[MIT](LICENSE)
