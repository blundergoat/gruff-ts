# Reports And CI

This guide covers output formats, exit codes, baselines, GitHub annotations, and
the local dashboard.

## Exit Codes

`analyse` exits with:

- `0` when the scan completed and no finding met `--fail-on`.
- `1` when at least one finding met `--fail-on`.
- `2` when diagnostics were produced, such as missing inputs or parse/config
  diagnostics.

Examples:

```bash
gruff-ts analyse . --fail-on=none
gruff-ts analyse . --fail-on=error
gruff-ts analyse . --fail-on=warning
```

## Machine Output

Full JSON report:

```bash
gruff-ts analyse . --format=json --fail-on=none > gruff-report.json
```

Hotspot summary:

```bash
gruff-ts analyse . --format=hotspot --fail-on=none > gruff-hotspots.json
```

Schema strings:

- `gruff.analysis.v1` for full analysis reports.
- `gruff.baseline.v1` for baselines.
- `gruff.hotspot.v1` for hotspot output.

## GitHub Actions

Use GitHub annotation output in a workflow step:

```bash
gruff-ts analyse . --format=github --fail-on=warning
```

Changed-file modes:

```bash
gruff-ts analyse . --diff=working-tree --format=github --fail-on=warning
gruff-ts analyse . --diff=staged --format=github --fail-on=warning
gruff-ts analyse . --diff=origin/main --format=github --fail-on=warning
```

`--diff` filters findings to changed files after analysis.

## Baselines

Generate an adoption baseline:

```bash
gruff-ts analyse . --generate-baseline gruff-baseline.json --fail-on=none
```

Apply it in CI:

```bash
gruff-ts analyse . --baseline gruff-baseline.json --fail-on=warning
```

Skip automatic baseline discovery:

```bash
gruff-ts analyse . --no-baseline --fail-on=none
```

Review baseline diffs carefully. A baseline suppresses matching fingerprints, so
unexpected additions can hide findings.

## HTML Reports

Write a dark self-contained report:

```bash
gruff-ts report . --output gruff-report.html
```

Write report JSON:

```bash
gruff-ts report . --format=json --output gruff-report.json
```

`report` defaults to `--fail-on none`, making it suitable for local inspection
and scheduled reporting.

## Dashboard

Start the dashboard:

```bash
gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

The dashboard serves:

- `/` - iframe shell and controls panel.
- `/health` - plain `ok`.
- `/scan?projectRoot=<path>&path=<path>` - report HTML for the selected scan.

Keep the dashboard on loopback unless the network is trusted. The scan endpoint
accepts filesystem paths through request parameters.

## Score History

Append score history to a JSON file:

```bash
gruff-ts analyse . --history-file .gruff-history.json --fail-on=none
```

History files are local artifacts. Commit them only if your project explicitly
wants trend data in version control.
