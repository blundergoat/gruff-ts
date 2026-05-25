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
