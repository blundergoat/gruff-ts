# Reports And CI

This guide covers output formats, exit codes, baselines, GitHub annotations, and
the local dashboard.

## Exit Codes

`analyse` exits with:

- `0` when the scan completed and no finding met `--fail-on`.
- `1` when at least one finding met `--fail-on`.
- `2` when a run-invalidating diagnostic was produced, such as missing inputs or
  parse/config diagnostics.

Parse diagnostics for TypeScript and JavaScript source use TypeScript's
syntax-only parser, including TSX and JSX modes by extension. They do not run
semantic typechecking.

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

- `gruff.analysis.v3` for full analysis reports.
- `gruff.summary.v3` for `summary --format=json`.
- `gruff.baseline.v3` for baselines.
- `gruff.hotspot.v1` for hotspot output.

[Output Formats](./output-formats.md) owns the envelope shape and the v2-to-v3
field table; this page does not restate them.

`gruff.analysis.v3` may include an optional notes array at
`extensions.ts.topLevel.notes`. Notes are non-fatal: they explain scan-surface
limits without changing exit codes. A fatal `diagnostics` entry owns exit `2`; a
non-fatal one leaves the exit code alone.

`gruff.analysis.v3` always carries a `suppressions` array: one row per
configured `sensitiveExclusions:` entry, empty when none are configured. A
suppressed finding leaves `findings`, the score, and the `--fail-on` exit code,
but its count is always reported. A malformed entry exits `2` before the scan
starts. See [Configuration](./configuration.md).

Current note types:

- `no-analysable-files` - a requested path existed but contributed no supported
  files, usually because ignore rules excluded everything under it.
- `non-text-file` - a file contained invalid UTF-8 or NUL bytes, so it was
  skipped before parsing.

`bounded-deep-scan` is reported as a diagnostic rather than a note: a script
file exceeded the deep-scan budget. It still counts as analysed and text-level
rules still run, but deep TypeScript passes, parse diagnostics, and
project-graph retention are skipped for that file. It does not invalidate the
run, so it leaves the exit code alone.

The deep-scan budget is `20,000` lines or `2,000,000` UTF-8 bytes, whichever
limit is hit first. Text output prints notes in a `Notes:` block. JSON reports
omit `notes` when there are no notes, so ordinary scans keep the same report
shape.

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

`--diff` filters findings to changed regions after analysis. `--changed-scope`
sets how wide a region is: `hunk`, `symbol` (the default), or `file`.

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

Review baseline diffs carefully. A baseline suppresses findings whose identity and
accepted count it already records, so
unexpected additions can hide findings.

The `gruff.baseline.v1` limitations - entries matched on
`(fingerprint, ruleId, filePath)`, a fingerprint that hashed the line rather
than the column, and code movement that resurfaced reviewed findings as new -
are resolved by `gruff.baseline.v3`, the coordinated cross-analyser schema
release those limitations were recorded against (ADR-013, ADR-017). Each row now
carries a line-free identity and the count it accepts, so code movement no longer
resurfaces a reviewed finding. Two distinct same-line findings from one rule have
been reported separately since 0.5.0 and now hold separate reviews.

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
out of the box; override per-project by setting `failOn:` in `.gruff-ts.yaml`.
See `docs/configuration.md` and ADR-004 for the precedence chain (CLI flag >
config > binary default).

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

`--history-file` requires a full scan. Combining it with `--diff`, `--since`, or
`--changed-ranges` exits `2` before anything is written, so a filtered scan can
never append a partial trend point.

History files are local artifacts. Commit them only if your project explicitly
wants trend data in version control.
