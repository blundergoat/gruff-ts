# Output Formats

`gruff-ts analyse --format <format>` renders the same analysis data for
different consumers. The combined legacy page remains at
[Reports And CI](reports-and-ci.md).

## Text

Use `text` for local terminal scans:

```sh
./bin/gruff-ts analyse src --format text --fail-on=warning
```

## JSON

Use `json` for automation. Analysis reports use `gruff.analysis.v3`:

```sh
./bin/gruff-ts analyse src --format=json --fail-on=none > gruff-ts.json
```

Version 3 is a coordinated family contract and a hard break from the TypeScript
v2 envelope. Machine paths are project-relative POSIX paths, `run.projectRoot`
is `.`, and volatile generation timestamps are omitted. Migrate these fields
before accepting v3:

| v2 | v3 |
|---|---|
| `findings[].filePath` and `findings[].file` | `findings[].file` |
| `score.composite` plus `score.grade` | `score.composite.score` plus `score.composite.grade` |
| `score.topOffenders[].filePath` | `score.topOffenders[].file` |
| `paths.skipped` | `paths.details` |
| top-level `notes` | `extensions.ts.topLevel.notes` |
| `baseline.suppressed` | `baseline.suppressedFindings` |
| top-level `suppressedCount` | `diff.filteredFindings` and `summary.suppressedFindings` |
| `generatedAt` | omitted |

Optional `column`, `endLine`, and `symbol` fields are omitted when unavailable;
they are never `null`. Finding metadata includes `locationPrecision` as
`scanner-pinpointed` or `line-only`. Fingerprints and `stableIdentity` values do
not change.

`suppressions` carries one row per configured `sensitiveExclusions:` entry, in
declaration order, shaped
`{index, rule, paths, symbol?, reason, suppressed}`. The array is always present
and is empty when nothing is configured. Text output prints the total as
`Suppressed findings: N via ...` when it is non-zero. See
[Configuration](./configuration.md).

`paths.details` lists every excluded path with a canonical `reason` and its
`source` (`config`, `gitignore`, or `default`). Only `config` entries include the
matching `pattern`. `paths.ignoredPaths` is the exact ordered path projection of
those detail rows.

Score math clusters correlated `complexity.cognitive`,
`complexity.cyclomatic`, and `size.function-length` findings once per function
symbol. The detailed `findings` array still lists each rule finding; only pillar
penalties and offender scores are de-duplicated.

## HTML

Use `html` for archived human review or dashboard scan output:

```sh
./bin/gruff-ts report src --format=html --output gruff-ts.html
```

## Markdown

Use `markdown` for pull request comments and release notes.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for compact score and offender analysis.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
./bin/gruff-ts analyse src --format=sarif --fail-on=none > gruff-ts.sarif
```

The SARIF document remains version 2.1.0. Its
`runs[0].properties.gruffSchemaVersion` value mirrors `gruff.analysis.v3`.

## Summary

JSON summary is the analysis v3 envelope with only the top-level `findings`
array removed and the schema changed to `gruff.summary.v3`:

```sh
./bin/gruff-ts summary src --format=json --fail-on=none
```

The same inputs and flags therefore produce the same `run`, counts, scores,
diagnostics, paths, suppressions, baseline, diff, and extensions fields.
`--top` affects text summary only. Existing analysis flags such as `--diff`,
`--baseline`, and `--generate-baseline` remain available.

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs.
