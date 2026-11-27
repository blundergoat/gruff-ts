# Output Formats

`gruff-ts analyse --format <format>` renders the same scan results for different
consumers. The combined legacy page remains at
[Reports And CI](reports-and-ci.md).

## Text

Use `text` for local terminal scans:

```sh
npx gruff-ts analyse src --format text --fail-on=warning
```

## JSON

Use `json` for automation. Analysis reports emit `gruff.analysis.v3`:

```sh
npx gruff-ts analyse src --format=json --fail-on=none > gruff-ts.json
```

Version 3 is a coordinated family contract and a hard break from the `0.5.x` v2
envelope. Paths are project-relative POSIX strings, `run.projectRoot` is `.`,
and volatile generation timestamps are omitted. Update consumers for these field
changes:

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

Optional `column`, `endLine`, and `symbol` fields are omitted when unavailable
rather than set to `null`. Finding metadata sets `locationPrecision` to
`scanner-pinpointed` or `line-only`. Baseline identities follow the line-free v3
contract introduced in `0.6.0` (see [Upgrading](../UPGRADING.md)) and stay
stable across output formats and ordinary edits.

### Suppressions audit

The `suppressions` array is always present (empty when nothing was configured or
suppressed) and groups audit rows in three ordered sections:

1. **Configured exclusions** - one row per `sensitiveExclusions:` entry in
   declaration order (`{index, rule, paths, symbol?, reason, suppressed}`). See
   [Configuration](./configuration.md).
2. **Built-in test-path skips** - rows marked `source: "built-in"` (numbered
   from `0` among themselves), one per file and rule skipped because security
   and sensitive-data rules skip test, fixture, and example paths. Text output
   labels them `builtInTestPath[<path>]`.
3. **Inline tool directives and duplicate merges** - rows continuing that
   numbering with `source: "inline"` or `source: "duplicate"`:
   - Supported inline comments on the reported line or alone on the line above
     suppress the matching gruff finding: ESLint `no-eval` and `no-new-func`
     (or a bare per-line ESLint disable covering both); Biome
     `lint/security/noGlobalEval`, `lint/correctness/noUnusedImports`, or a
     parent group such as `lint/security`; and zizmor `ignore[unpinned-uses]`
     and `ignore[dangerous-triggers]`. Type-checker comments (`@ts-expect-error`)
     and file-wide directives are not honoured.
   - An `eval` call flagged by both `security.eval-call` and
     `security.unsafe-deserialization` reports once under `security.eval-call`
     and records the merged duplicate as `source: "duplicate"`.
   - Text output prints `Suppressed findings: N via ...` with `inline[<path>]`
     and `duplicate[<path>]` labels, and SARIF keeps each removed finding as a
     suppressed result (`"suppressions": [{"kind": "inSource", "justification": <reason>}]`).

`paths.details` lists every excluded path with a canonical `reason` and its
`source` (`config`, `gitignore`, or `default`). Only `config` entries include the
matching `pattern`. `paths.ignoredPaths` is the ordered path projection of those
detail rows.

Score math clusters correlated `complexity.cyclomatic` and `size.function-length`
findings once per function symbol. The `findings` array still lists each finding;
only pillar penalties and offender scores are deduplicated.

## HTML

Use `html` for archived human review or dashboard output:

```sh
npx gruff-ts report src --format=html --output gruff-ts.html
```

## Markdown

Use `markdown` for pull request comments and summaries.

## GitHub

Use `github` inside GitHub Actions to emit workflow annotations.

## Hotspot

Use `hotspot` for the compact score and file-offender list. Its `diagnostics`
array carries the same scan diagnostics as `json`, such as a
`bounded-deep-scan` notice.

## SARIF

Use `sarif` for GitHub code scanning or other SARIF consumers:

```sh
npx gruff-ts analyse src --format=sarif --fail-on=none > gruff-ts.sarif
```

SARIF stays on version 2.1.0, and `runs[0].properties.gruffSchemaVersion`
matches `gruff.analysis.v3`.

## Summary

JSON summary is the analysis v3 envelope with only the top-level `findings`
array removed and `schemaVersion` set to `gruff.summary.v3`:

```sh
npx gruff-ts summary src --format=json --fail-on=none
```

The same inputs and flags produce identical `run`, counts, scores, diagnostics,
paths, suppressions, baseline, diff, and extensions fields. `--top` affects text
output only. Analysis flags such as `--diff`, `--baseline`, and
`--generate-baseline` work on `summary` as well.

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Pass
`--fail-on none` for report-only jobs.
