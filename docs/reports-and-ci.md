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

Human scan digest:

```bash
gruff-ts summary . --fail-on=none
```

The summary output includes the scanned path, elapsed duration, total findings,
per-pillar counts, top rules, and top file offenders.

Schema strings:

- `gruff.analysis.v2` for full analysis reports.
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

For SARIF consumers, write SARIF output from `analyse` and upload the generated
file with your platform's code-scanning upload step:

```bash
gruff-ts analyse . --format=sarif --fail-on=none > gruff.sarif
```

For a strict security-oriented gate, bypass baselines and fail on error-severity
findings:

```bash
gruff-ts analyse . --no-baseline --fail-on=error
```

This is useful when an adoption baseline exists for general quality debt but
security and sensitive-data errors should still break CI.

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

`report` intentionally renders raw scan results and does not accept a
`--baseline` option. Use `analyse` for baseline-aware machine output.

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
and scheduled reporting. `analyse` and `summary` default to `--fail-on advisory`
out of the box; override per-project by setting `minimumSeverity:` in
`.gruff-ts.yaml`. See `docs/configuration.md` and ADR-004 for the precedence
chain (CLI flag > config > binary default).

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
