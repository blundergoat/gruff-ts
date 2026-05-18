# Configuration

`gruff-ts` can run without config. A config file is useful when adopting the
tool in a real project with generated files, local naming conventions, or rule
thresholds that need tuning.

## Discovery Order

`analyse` auto-loads the default config file from the project root:

- `.gruff-ts.yaml`

Use an explicit path:

```bash
gruff-ts analyse . --config .gruff-ts.yaml
```

Skip config for a run:

```bash
gruff-ts analyse . --no-config
```

## Shape

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
  rule.id:
    enabled: true
    threshold: 10
    severity: warning
```

## Ignored Paths

Recursive directory scans respect root and nested `.gitignore` files before
adding supported source and config files to a run. `paths.ignore` is an extra
project policy layer for paths that should remain out of normal scans even when
they are not ignored by Git.

`paths.ignore` accepts exact paths, prefix-style paths, and simple glob
patterns. Examples:

```yaml
paths:
  ignore:
    - "generated/**"
    - "fixtures/vendor/**"
    - "src/generated-client.ts"
```

Default ignored directories are matched by first path segment:

```text
.git, .hg, .svn, .idea, .vscode, build, cache, coverage, dist,
generated, node_modules, target, tmp, vendor
```

Use `--include-ignored` when you intentionally want to scan default ignored
directories and Git-ignored paths. Configured `paths.ignore` entries still
apply.

## Allowlists

`allowlists.acceptedAbbreviations` lowers naming-rule noise for project-specific
short terms:

```yaml
allowlists:
  acceptedAbbreviations:
    - api
    - cli
    - env
```

`allowlists.secretPreviews` accepts redacted secret previews that are known false
positives:

```yaml
allowlists:
  secretPreviews:
    - "abcd...wxyz (redacted, 32 chars)"
```

Prefer fixing false positives with a narrow config entry instead of disabling an
entire sensitive-data rule.

## Rule Controls

Disable a rule:

```yaml
rules:
  docs.missing-public-doc:
    enabled: false
```

Set one threshold and one emitted severity for a metric rule:

```yaml
rules:
  complexity.cyclomatic:
    threshold: 10
    severity: warning
  size.file-length:
    threshold: 400
    severity: error
```

Rules with extra tuning knobs use `options` for those knobs while the primary
metric still uses `threshold` and `severity`:

```yaml
rules:
  design.large-module-concentration:
    threshold: 55
    severity: advisory
    options:
      minFiles: 4
      minLines: 80
```

List supported thresholds and options:

```bash
gruff-ts list-rules
gruff-ts list-rules --format=json
```

## Example Project Config

```yaml
paths:
  ignore:
    - "generated/**"
    - "fixtures/**"

allowlists:
  acceptedAbbreviations:
    - api
    - cli
    - env
    - id
  secretPreviews: []

rules:
  complexity.cognitive:
    threshold: 15
    severity: warning
  complexity.cyclomatic:
    threshold: 10
    severity: warning
  design.deep-relative-import:
    threshold: 2
    severity: advisory
  sensitive-data.high-entropy-string:
    threshold: 32
    severity: error
  size.function-length:
    threshold: 30
    severity: warning
  test-quality.setup-bloat:
    threshold: 12
    severity: advisory
```
