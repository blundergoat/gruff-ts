# Configuration

`gruff-ts` can run without config. A config file is useful when adopting the
tool in a real project with generated files, local naming conventions, or rule
thresholds that need tuning.

## Discovery Order

`analyse` auto-loads the first default config file it finds in the project root:

1. `.gruff.json`
2. `.gruff.yaml`
3. `.gruff.yml`

Use an explicit path:

```bash
gruff-ts analyse . --config .gruff.yaml
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

The same shape works as JSON.

## Ignored Paths

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

Use `--include-ignored` when you intentionally want to scan those directories.

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
    - ".goat-flow/scratchpad/**"

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
      maxSetupLines: 8
```
