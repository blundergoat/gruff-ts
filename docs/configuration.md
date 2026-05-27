# Configuration

`gruff-ts` can run without config. A config file is useful when adopting the
tool in a real project with generated files, local naming conventions, or rule
thresholds that need tuning.

## Discovery Order

`analyse` auto-loads the first supported config file it finds in the project root:

1. `.gruff-ts.yaml`
2. `.gruff.json`
3. `.gruff.yaml`
4. `.gruff.yml`

Use an explicit path:

```bash
gruff-ts analyse . --config .gruff-ts.yaml
```

Skip config for a run:

```bash
gruff-ts analyse . --no-config
```

## Required schema version

Every `.gruff-ts.yaml` must declare `schemaVersion: gruff-ts.config.v0.1` at the
top. Loading throws if the field is missing or carries a different value. The
field is in a different namespace from the output schemas (`gruff.analysis.v2`,
`gruff.summary.v2`, etc.) - the config-input version travels independently of
the output-payload versions. See ADR-004.

## minimumSeverity (per-command gating defaults)

A top-level `minimumSeverity:` block sets the default `--fail-on` value per
command. The precedence chain is **CLI flag > config > binary default**.

```yaml
schemaVersion: gruff-ts.config.v0.1
minimumSeverity:
  analyse: advisory
  summary: advisory
  report: none
```

Valid values: `advisory | warning | error | none`. The validator rejects any
other value (including `never`, which was an early cross-port draft for the
off-switch before the family converged on `none`).

`dashboard` is intentionally **not** a valid key in this block. The dashboard
subcommand has no `--fail-on` flag today; setting `minimumSeverity.dashboard:`
would be a silent no-op CI footgun, so the validator rejects it with a clear
error.

Binary defaults are `analyse: advisory`, `summary: advisory`, `report: none`.

## Shape

```yaml
schemaVersion: gruff-ts.config.v0.1
minimumSeverity:
  analyse: advisory
  summary: advisory
  report: none

paths:
  ignore:
    - "generated/**"

allowlists:
  acceptedAbbreviations:
    - api
    - cli
  secretPreviews: []
  bannedGenericNames: [process, handle, doit, run, execute, manage]
  booleanPrefixes: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires]
  hungarianPrefixes: [str, obj, arr, bool, int, num]
  placeholderNames: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]
  negativeBooleanAllowed: [nostore, nofollow, noreferrer, noscript, noindex]
  knownAcronyms: [url, http, https, id, xml, json, html, css, api, sql, db, io, ui, uuid, ip, tcp, udp, ast, cli, npm]

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

Naming allowlists tune the 0.1.2 naming pack without changing rule ids or
fingerprints:

| Key | Used by | Default behavior |
| --- | --- | --- |
| `acceptedAbbreviations` | `naming.short-variable` | Adds short names that should not be flagged. |
| `bannedGenericNames` | `naming.generic-function` | Replaces the built-in generic function-name denylist. |
| `booleanPrefixes` | `naming.boolean-prefix` | Replaces the accepted boolean-name prefixes such as `is`, `has`, `should`, `may`, `supports`, and `requires`. |
| `hungarianPrefixes` | `naming.hungarian-notation` | Replaces type-style prefixes to flag. |
| `placeholderNames` | `naming.identifier-quality`, `naming.generic-parameter` | Replaces placeholder words; numbered suffix checks stay active. |
| `negativeBooleanAllowed` | `naming.negative-boolean` | Replaces domain terms allowed to start with `no`. |
| `knownAcronyms` | `naming.acronym-case` | Replaces acronyms checked for mixed casing. |

For replace-style allowlists, use an empty list (`[]`) when you intentionally
want no entries.

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

See [Rules](./rules.md) for the full rule catalogue grouped by pillar.

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
