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
field is in a different namespace from the output schemas (`gruff.analysis.v3`,
`gruff.summary.v3`, etc.) - the config-input version travels independently of
the output-payload versions. See ADR-004.

## failOn (per-command gating defaults)

A top-level `failOn:` block sets the default `--fail-on` value per command.
The precedence chain is **CLI flag > config > binary default**.

```yaml
schemaVersion: gruff-ts.config.v0.1
failOn:
  analyse: advisory
  summary: advisory
  report: none
```

Valid values: `advisory | warning | error | none`. The validator rejects any
other value (including `never`, which was an early cross-port draft for the
off-switch before the family converged on `none`).

`dashboard` is intentionally **not** a valid key in this block. The dashboard
subcommand has no `--fail-on` flag today; setting `failOn.dashboard:` would be
a silent no-op CI footgun, so the validator rejects it with a clear error.

Binary defaults are `analyse: advisory`, `summary: advisory`, `report: none`.

Across the Gruff family only `analyse` and `report` are accepted by every port, so a
polyglot repository that shares one `failOn` block should write only those two keys.
`summary` is accepted by gruff-go and gruff-ts, and `dashboard` by gruff-go, gruff-php
and gruff-py; each other port refuses the key with exit 2 rather than ignoring it,
because it ships no gate for that command.

`minimumSeverity:` is a different setting: one severity - `advisory`,
`warning`, or `error` - that hides quieter findings from the report without
changing the score or the exit code. A `minimumSeverity:` carrying the
per-command map above is refused at config load rather than read as a floor, so
an existing 0.5 config cannot quietly change what it gates.

## Shape

```yaml
schemaVersion: gruff-ts.config.v0.1
failOn:
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
  bannedGenericNames: [process, handle, doit, run, execute, manage]
  acceptedBooleanNames: [all, apply, check, dev, enabled, force, fresh, harness, json, ok, verbose, yes]
  booleanPrefixes: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires, allow, check, enable, exclude, include, omit, skip, with, without]
  hungarianPrefixes: [str, obj, arr, bool, int, num]
  placeholderNames: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]
  negativeBooleanAllowed: [nostore, nofollow, noreferrer, noscript, noindex]
  knownAcronyms: [url, http, https, id, xml, json, html, css, api, sql, db, io, ui, uuid, ip, tcp, udp, ast, cli, npm]

sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: tests/fixtures/aws-sample.env
    reason: Synthetic key used by the loader fixture; not a live credential.

rules:
  complexity.cyclomatic:
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

VCS internals are always blocked at any depth:

```text
.git, .hg, .svn
```

When no `.gitignore` exists from the project root through a candidate's parent,
the family fallback skips `.fleet`, `.idea`, `.vscode`, `build`, `coverage`,
`dist`, `node_modules`, and `vendor` at any depth. Once a `.gitignore` exists in
that chain, it owns those names for the subtree. Committed control metadata such
as `.agents`, `.claude`, `.codex`, `.github`, and `.goat-flow` stays scannable
unless Git or config excludes it.

Use `--include-ignored` when you intentionally want to scan fallback and
Git-ignored paths. An explicit supported file also bypasses those two layers.
Neither form overrides configured `paths.ignore` or the VCS boundary. Lockfile
names add no exclusion; eligible forms such as `package-lock.json` are scanned.

`paths.ignore` is authoritative in every invocation mode (ADR-007): a matching
path is excluded and produces no findings whether it is reached by a directory
walk, passed as an explicit file operand (`gruff-ts analyse src/generated-client.ts`),
or touched by a diff/changed-region run. Excluded paths appear in the report's
`paths.details` array with their `source` (`config` / `gitignore` / `default`) and, for
`config` entries only,
the matching `pattern`. Query a path without scanning via `check-ignore`, which
shares the same engine and mirrors `git check-ignore` exit codes (0 = at least
one ignored, 1 = none, 2 = error):

```sh
gruff-ts check-ignore src/generated-client.ts --format json
# [ { "path": "src/generated-client.ts", "ignored": true, "source": "config", "pattern": "src/generated-client.ts" } ]
```

## Generated Markers

Use `paths.ignore` when a generated or vendored surface should not be scanned at
all. If the file should stay in the scan, gruff treats a source file as generated
only when one of these explicit markers appears in the first 10 lines:
`AUTO-GENERATED`, `@generated`, `GENERATED FILE`, `Code generated`,
`Generated by`, `DO NOT EDIT`, or `Copied from`.

Generated files skip documentation and naming findings only. Security,
sensitive-data, size, complexity, maintainability, modernisation, and
test-quality checks still run, so a generated file can still report a leaked
credential, unsafe execution, or a file-size finding. Path names such as
`fixtures/`, `testdata/`, or `perf-tests/` do not by themselves suppress any
rule family.

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

The 0.5 key `allowlists.secretPreviews` is removed: FAMILY-CONTRACT.md section 5 makes every sensitive-data marker unconditional and zero-payload, so the key authorised nothing. `gruff-ts init` no longer writes it, a configuration carrying it (even as an empty list) is refused with that explanation, and `gruff-ts migrate-config` deletes it.

The key never suppresses a sensitive finding. Reports use fixed category markers without matched characters or secret-derived lengths.

Tune a documented rule threshold or enabled setting when a sensitive-data detector does not fit the project; preview values cannot be used as exclusions.

Naming allowlists tune the 0.2.0 naming pack without changing rule ids or
fingerprints:

| Key | Used by | Default behavior |
| --- | --- | --- |
| `acceptedAbbreviations` | `naming.short-variable` | Adds short names that should not be flagged. |
| `acceptedBooleanNames` | `naming.boolean-prefix` | Replaces the complete set of exact interface/type contract-field names, such as `verbose`, `enabled`, `ok`, and `force`. |
| `acceptedClassFilePairs` | `naming.class-file-mismatch` | Replaces the exact case-insensitive `fileBase:ClassName` pairs that may use feature-file and class-role naming. Defaults to empty. |
| `acceptedCasingPairs` | `naming.inconsistent-casing` | Replaces the exact case-insensitive `wire_name:internalName` pairs allowed within one declaration or lexical owner. Either pair order matches. Defaults to empty. |
| `bannedGenericNames` | `naming.generic-function` | Replaces the built-in generic function-name denylist. |
| `booleanPrefixes` | `naming.boolean-prefix` | Replaces the accepted boolean-name prefixes such as `is`, `has`, `should`, `may`, `supports`, and `requires`. |
| `hungarianPrefixes` | `naming.hungarian-notation` | Replaces type-style prefixes to flag. |
| `placeholderNames` | `naming.identifier-quality`, `naming.generic-parameter` | Replaces placeholder words; numbered suffix checks stay active. |
| `negativeBooleanAllowed` | `naming.negative-boolean` | Replaces domain terms allowed to start with `no`. |
| `knownAcronyms` | `naming.acronym-case` | Replaces acronyms checked for mixed casing. |

For replace-style allowlists, use an empty list (`[]`) when you intentionally
want no entries.

When a boolean-prefix finding names `allowlists.acceptedBooleanNames`, copy any
defaults the project still needs into the configured list before adding the
external key - the configured list replaces defaults rather than extending
them. If renaming a JSON, CLI, or DTO key would break consumers, keep a clearer
internal field and map the external key explicitly at the serialization boundary.

Use exact pair allowlists when both names must coexist:

```yaml
allowlists:
  acceptedClassFilePairs: ["focusModeTranscript:TranscriptFocusController"]
  acceptedCasingPairs: ["note_id:noteId"]
```

The class/file entry uses the extensionless file base before the colon. Casing
pairs may be written in either order. Both lists are case-insensitive, replace
the complete configured list, and suppress only the exact pair rather than every
name sharing the same canonical form.

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

## Sensitive Exclusions

`sensitiveExclusions:` is the only way to suppress a sensitive-data finding. It
is a separate top-level section, not part of `rules:` or `paths.ignore`, because
it is the one surface that can hide a detected secret.

You write every entry by hand. Gruff never converts a detected value, a preview,
or a finding message into an exclusion, and no key on an entry matches against
finding text.

```yaml
sensitiveExclusions:
  - rule: sensitive-data.aws-access-key
    path: tests/fixtures/aws-sample.env
    symbol: Fixtures::awsSample
    reason: Synthetic key used by the loader fixture; not a live credential.
```

An entry suppresses a finding only when all of the following match:

- `rule` equals the finding's rule id exactly. One rule id per entry, from the
  `sensitive-data` pillar only.
- `path` equals the finding's project-relative path exactly. One file per entry.
- `symbol`, when present, equals the finding's symbol exactly. It narrows the
  scope. No sensitive-data rule stamps a symbol today, so an entry carrying one
  currently matches nothing - that is the declared scope working, not a bug.

Nothing else is suppressed: the same rule in another file, and a different rule
in the same file, both keep reporting.

`reason` is required and must be non-empty. Loading fails with exit code 2 and
names the entry index plus the offending key when an entry:

- omits `rule`, or gives a wildcard, glob, regular-expression character, pillar
  name, unknown rule id, or a rule outside the `sensitive-data` pillar;
- omits `path`, or gives an absolute path, a `..` traversal, or a glob;
- carries any key outside `rule`, `path`, `symbol`, and `reason` - including
  `message_contains`, `messageContains`, `value`, and `preview`;
- omits `reason` or supplies only whitespace;
- repeats a `rule` + `path` + `symbol` scope an earlier entry already claims.

An entry that matches no finding is not an error. It reports `suppressed: 0`, so
fixing the underlying problem never breaks a build.

Every entry is counted. The `suppressions` array in the `gruff.analysis.v3`
report carries one row per entry in declaration order:

```json
{ "index": 0, "rule": "sensitive-data.aws-access-key", "paths": ["tests/fixtures/aws-sample.env"], "reason": "Synthetic key used by the loader fixture; not a live credential.", "suppressed": 2 }
```

Text output prints the total when it is non-zero:

```text
Suppressed findings: 2 via sensitiveExclusions[0] sensitive-data.aws-access-key: 2 (Synthetic key used by the loader fixture; not a live credential.)
```

A suppressed finding leaves the finding list, the score, and the `--fail-on`
exit code, but it is never invisible: its count is always reported. Only the
configured rule id, path, and reason appear in output - never any part of the
detected value.

## Example Project Config

A complete file. The shorter snippets above omit `schemaVersion` because they
show a single key in isolation; every real `.gruff-ts.yaml` needs it.

```yaml
schemaVersion: gruff-ts.config.v0.1

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
  acceptedBooleanNames:
    - verbose
    - enabled

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
```
