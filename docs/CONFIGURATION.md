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
    thresholds:
      key: 10
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

Adjust thresholds:

```yaml
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

List threshold keys supported by each rule:

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
    thresholds:
      warn: 15
  complexity.cyclomatic:
    thresholds:
      warn: 10
      error: 20
  design.deep-relative-import:
    thresholds:
      maxParentSegments: 2
  sensitive-data.high-entropy-string:
    thresholds:
      minLength: 32
  size.function-length:
    thresholds:
      warn: 30
      error: 60
  test-quality.setup-bloat:
    thresholds:
      maxSetupLines: 12
```
