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

Use `json` for automation. JSON reports use `gruff.analysis.v2`.

```sh
./bin/gruff-ts analyse src --format=json --fail-on=none > gruff-ts.json
```

`paths.skipped` (added in 0.3.0) lists every excluded path with its ignore
`source` (`config` / `gitignore` / `default`) and the matching `pattern`;
`paths.ignoredPaths` remains as the back-compatible `string[]` of the same paths.
The field is additive, so existing `gruff.analysis.v2` consumers are unaffected.

Score math clusters correlated `complexity.cognitive`,
`complexity.cyclomatic`, `design.god-function`, and `size.function-length`
findings once per function symbol. The detailed `findings` array still lists
each rule finding; only pillar penalties and offender scores are de-duplicated.

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

## Summary

`summary` has its own compact text/JSON contract:

```sh
./bin/gruff-ts summary src --format=json --top=5 --fail-on=none
```

TypeScript keeps the existing `summary` analysis flags such as `--diff`,
`--baseline`, and `--generate-baseline` as extensions.

## Exit Codes

`analyse` exits `1` when at least one finding meets `--fail-on`. Use
`--fail-on none` for report-only jobs.
