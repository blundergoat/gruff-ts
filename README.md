# gruff-ts

`gruff-ts` is a Node.js/ESM CLI for statically analysing TypeScript and
JavaScript projects. It scans source and common project/config files, reports
quality findings across multiple pillars, and keeps stable finding fingerprints
so baselines and machine-readable reports can round-trip without churn.

The package exposes a `gruff-ts` binary. In this repository, use the local shim:

```bash
npm install
./bin/gruff-ts analyse .
```

## What It Checks

The analyser emits findings across 11 pillars:

- size
- complexity
- dead-code
- waste
- naming
- documentation
- modernisation
- security
- sensitive-data
- test-quality
- design

Use the rule catalogue to inspect the exact rule ids, severities, confidence
levels, remediation text, and threshold keys:

```bash
./bin/gruff-ts list-rules
./bin/gruff-ts list-rules --format=json
```

## Quick Start

Run a first scan without failing the shell on findings:

```bash
./bin/gruff-ts analyse . --fail-on=none
```

Scan a specific file or directory:

```bash
./bin/gruff-ts analyse src fixtures/sample.ts --fail-on=none
```

Representative text output:

```text
gruff-ts 0.1.0-dev
Score: 94.5 (A) | Findings: 8 advisory, 2 warning, 3 error
Analysed files: 1

Findings:
- [error] fixtures/sample.ts:9 security.eval-call - eval() executes dynamic code.
```

For machine output, choose a format:

```bash
./bin/gruff-ts analyse . --format=json --fail-on=none
./bin/gruff-ts analyse . --format=markdown --fail-on=none
./bin/gruff-ts analyse . --format=github --fail-on=warning
./bin/gruff-ts analyse . --format=hotspot --fail-on=none
```

JSON analysis reports use `schemaVersion: "gruff.analysis.v1"`.

## Commands

| Command | Purpose |
| --- | --- |
| `analyse [paths...]` | Run the scanner and print findings. |
| `report [paths...]` | Render an HTML or JSON report, optionally to a file. |
| `list-rules` | Print rule catalogue metadata. |
| `dashboard` | Start a local HTTP dashboard. |

Useful command help:

```bash
./bin/gruff-ts --help
./bin/gruff-ts analyse --help
./bin/gruff-ts report --help
./bin/gruff-ts dashboard --help
```

## CI And Exit Codes

`analyse` defaults to `--fail-on error`. Use a threshold that matches the
workflow:

```bash
# Exploratory scan: never fail because of findings.
./bin/gruff-ts analyse . --fail-on=none

# CI gate only on error findings.
./bin/gruff-ts analyse . --fail-on=error

# Stricter CI gate on warnings and errors.
./bin/gruff-ts analyse . --fail-on=warning
```

Exit codes:

- `0`: scan completed and no finding met `--fail-on`.
- `1`: scan completed and at least one finding met `--fail-on`.
- `2`: the run produced diagnostics, such as missing inputs or parse/config
  diagnostics.

For pull-request workflows, combine changed-file filtering with CI output:

```bash
./bin/gruff-ts analyse . --diff=working-tree --format=github --fail-on=warning
./bin/gruff-ts analyse . --diff=staged --format=json --fail-on=none
```

`--diff` accepts `working-tree`, `staged`, `unstaged`, or a base ref.

## Baselines And History

Baselines suppress findings by stable fingerprint. They are useful when adopting
the tool in an existing project without fixing every current finding first.

Generate a baseline:

```bash
./bin/gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
```

Apply a baseline:

```bash
./bin/gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
```

Skip automatic baseline discovery for one run:

```bash
./bin/gruff-ts analyse . --no-baseline --fail-on=none
```

Baseline files use `schemaVersion: "gruff.baseline.v1"`. The hotspot output
format uses `schemaVersion: "gruff.hotspot.v1"`.

Append score history to a JSON file:

```bash
./bin/gruff-ts analyse . --history-file .gruff-history.json --fail-on=none
```

## Reports

Generate an HTML report:

```bash
./bin/gruff-ts report . --output gruff-report.html
```

Generate a JSON report:

```bash
./bin/gruff-ts report . --format=json --output gruff-report.json
```

`report` defaults to `--fail-on none` so report generation is render-first.

## Configuration

`analyse` auto-loads the first default config file it finds, in this order:

1. `.gruff.json`
2. `.gruff.yaml`
3. `.gruff.yml`

Use an explicit config:

```bash
./bin/gruff-ts analyse . --config .gruff.yaml
```

Skip config loading for one run:

```bash
./bin/gruff-ts analyse . --no-config
```

Minimal YAML example:

```yaml
paths:
  ignore:
    - ".goat-flow/scratchpad/**"

allowlists:
  acceptedAbbreviations:
    - id
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

Default ignored directories are matched by first path segment:

```text
.git, .hg, .svn, .idea, .vscode, build, cache, coverage, dist,
generated, node_modules, target, tmp, vendor
```

Use `--include-ignored` when you intentionally want to scan those directories.

## Dashboard

Start the local dashboard:

```bash
./bin/gruff-ts dashboard
```

By default it binds to `127.0.0.1:8767` and uses the current directory as the
project root. Keep the loopback default unless the network is trusted:

```bash
./bin/gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

Avoid binding the dashboard to `0.0.0.0` on shared or public networks. The
dashboard scan endpoint analyses filesystem paths from request parameters, so
the bind address is the main safety boundary.

## Safety And Limitations

- Secret-like findings include redacted previews; raw secret values should not
  be copied into findings or rendered output.
- Several rules are heuristic. The scanner is not a TypeScript compiler, type
  checker, or full JavaScript parser.
- Rule confidence is part of the rule catalogue and each finding. Treat low and
  medium confidence findings as review prompts, not facts.
- Baselines suppress existing fingerprints. Review baseline changes carefully so
  newly introduced findings are not hidden by accident.

## Development

Install dependencies:

```bash
npm install
```

Run the full local check:

```bash
npm run check
```

Run tests only:

```bash
npm test
```

Start the development dashboard:

```bash
npm run start-dev
```

Run the local CLI during development:

```bash
./bin/gruff-ts analyse . --fail-on=none
```

The runtime is concentrated in `src/cli.ts`, with tests in `src/cli.test.ts`.
