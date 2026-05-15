# gruff-ts

`gruff-ts` is a dependency-light Node.js CLI for statically analysing
TypeScript and JavaScript projects. It scans source, tests, package metadata,
and common config files, then reports quality findings across 11 pillars with
stable fingerprints for baselines and repeatable machine output.

The 0.1 release includes 86 rules, JSON/HTML/Markdown/GitHub output, baseline
support, changed-file filtering, local score history, a rule catalogue, and a
dark local dashboard.

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
and threshold keys:

```bash
gruff-ts list-rules
gruff-ts list-rules --format=json
```

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the scanner and print findings. |
| `report [paths...]` | Render an HTML or JSON report, optionally to a file. |
| `list-rules` | Print rule catalogue metadata. |
| `dashboard` | Start a local HTTP dashboard. |

Useful help commands:

```bash
gruff-ts --help
gruff-ts analyse --help
gruff-ts report --help
gruff-ts dashboard --help
```

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

Examples:

```bash
gruff-ts analyse . --format=json --fail-on=none
gruff-ts analyse . --format=github --fail-on=warning
gruff-ts analyse . --format=hotspot --fail-on=none
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

## Baselines And History

Baselines suppress existing findings by stable fingerprint so teams can adopt
the tool without fixing every current issue first.

```bash
gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
gruff-ts analyse . --no-baseline --fail-on=none
```

Baseline files use `schemaVersion: "gruff.baseline.v1"`.

Append local score history:

```bash
gruff-ts analyse . --history-file .gruff-history.json --fail-on=none
```

## Configuration

`analyse` auto-loads the first default config file it finds:

1. `.gruff.json`
2. `.gruff.yaml`
3. `.gruff.yml`

Use an explicit config or skip config loading:

```bash
gruff-ts analyse . --config .gruff.yaml
gruff-ts analyse . --no-config
```

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
    thresholds:
      warn: 10
      error: 20
  size.file-length:
    thresholds:
      warn: 400
      error: 800
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

The runtime is intentionally concentrated in `src/cli.ts`, with tests in
`src/cli.test.ts`.

## License

`package.json` currently declares `proprietary`. If this project is intended to
be open source, add a `LICENSE` file and update package metadata before the
public release.
