# Rules

`gruff-ts` exposes 119 rules across 11 pillars. This list is generated from the
public rule catalogue used by `gruff-ts list-rules`; severity, confidence,
thresholds, and option names are the defaults before project config overrides.

The pillars are organised around one goal: making AI-generated code something a
human who did not write it can verify by reading, trust as secure, and rely on as
honestly tested rather than padded with low-signal ceremony. Complexity, size,
naming, and documentation serve verifiability; security and sensitive-data serve
safety where review is weakest; test-quality guards against coverage theatre. See
[Philosophy](philosophy.md) for the intent behind the catalogue, including why a
doc comment is expected even on a private one-liner.

Use the CLI when you need machine-readable metadata:

```bash
gruff-ts list-rules --format=json
```

## Pillar Counts

- complexity: 3
- dead-code: 1
- design: 6
- documentation: 17
- maintainability: 14
- modernisation: 14
- naming: 10
- security: 27
- sensitive-data: 8
- size: 4
- test-quality: 15

## Complexity

- `complexity.cognitive` (warning; high confidence; threshold 15): Flags functions with high combined branch and nesting complexity.
- `complexity.cyclomatic` (warning; high confidence; threshold 15): Flags functions with many independent branch paths.
- `complexity.npath` (warning; medium confidence; threshold 200): Flags functions with high approximate NPath complexity.

## Dead Code

- `dead-code.unused-private-method` (advisory; low confidence): Flags private methods without an apparent same-file call site.

## Design

- `design.circular-import` (warning; medium confidence): Flags simple relative import cycles inside the discovered source set.
- `design.deep-relative-import` (advisory; medium confidence; threshold 2): Flags relative imports that climb too many parent directories.
- `design.god-function` (warning; high confidence): Flags functions that are both long and complex.
- `design.large-module-concentration` (advisory; medium confidence; threshold 55; options: minFiles, minLines): Flags a production module that dominates project source lines.
- `design.package-bin-missing` (warning; high confidence): Flags package bin entries that point at missing files.
- `design.package-bin-not-executable` (warning; high confidence): Flags package bin targets that are not executable.

## Documentation

- `docs.fixture-purpose-missing` (advisory; medium confidence): Flags large or scanner-relevant fixtures without a nearby purpose comment.
- `docs.magic-threshold-without-rationale` (advisory; medium confidence): Flags threshold-like numeric values without a nearby rationale comment.
- `docs.missing-error-behavior-doc` (advisory; medium confidence): Flags commented functions whose error behavior is not described.
- `docs.missing-file-overview` (advisory; medium confidence): Flags source files without a top-of-file purpose comment.
- `docs.missing-function-doc` (advisory; medium confidence): Flags functions without a leading maintainer comment.
- `docs.missing-interface-doc` (advisory; medium confidence): Flags interfaces without a leading maintainer comment.
- `docs.missing-invariant-doc` (advisory; medium confidence): Flags commented declarations that own schema, fingerprint, baseline, or determinism contracts without saying so.
- `docs.missing-param-tag` (advisory; medium confidence): Flags documented exports with parameters missing @param tags.
- `docs.missing-public-doc` (advisory; medium confidence): Flags exported class, type, and enum APIs without a nearby doc comment.
- `docs.missing-return-tag` (advisory; medium confidence): Flags documented non-void exports without @returns.
- `docs.missing-side-effect-doc` (advisory; medium confidence): Flags commented functions that perform observable side effects without naming them.
- `docs.missing-why-for-complex-code` (advisory; medium confidence): Flags comments on complex functions that do not explain why the shape exists.
- `docs.stale-comment` (advisory; medium confidence): Flags comments that reference missing files, unknown rules, stale CLI flags, or the wrong declaration.
- `docs.stale-param-tag` (advisory; medium confidence): Flags @param tags for parameters no longer in the signature.
- `docs.suppression-without-rationale` (advisory; medium confidence): Flags lint, formatter, coverage, or tool suppressions without a maintainer rationale.
- `docs.todo-without-tracking` (advisory; high confidence): Flags TODO, FIXME, HACK, and XXX comments without tracking context.
- `docs.useless-docblock` (advisory; medium confidence): Flags comments or docblocks that only restate the symbol name.

## Modernisation

- `modernisation.date-now-candidate` (advisory; high confidence): Flags verbose current-time expressions that can use Date.now().
- `modernisation.double-cast` (warning; medium confidence): Flags casts through unknown or any into another type.
- `modernisation.loose-equality` (advisory; medium confidence): Flags loose equality comparisons that may coerce values.
- `modernisation.non-null-assertion` (warning; medium confidence): Flags non-null assertions that bypass null checks.
- `modernisation.nullish-coalescing-candidate` (advisory; medium confidence): Flags || fallbacks that may erase valid falsy values.
- `modernisation.object-spread-candidate` (advisory; medium confidence): Flags Object.assign({}, ...) cloning that can use object spread.
- `modernisation.optional-chaining-candidate` (advisory; medium confidence): Flags repeated guard-and-property access patterns.
- `modernisation.public-property` (advisory; high confidence): Flags public class properties that expose representation.
- `modernisation.readonly-property-candidate` (advisory; medium confidence): Flags class properties that appear readonly-worthy.
- `modernisation.ts-comment-without-rationale` (warning; medium confidence): Flags TypeScript suppression comments without a rationale.
- `modernisation.tsconfig-exact-optional-disabled` (warning; high confidence): Flags tsconfig files without exactOptionalPropertyTypes enabled.
- `modernisation.tsconfig-index-safety-disabled` (warning; high confidence): Flags tsconfig files without noUncheckedIndexedAccess enabled.
- `modernisation.tsconfig-strict-disabled` (warning; high confidence): Flags tsconfig files without strict mode enabled.
- `modernisation.var-declaration` (advisory; high confidence): Flags var declarations.

## Naming

- `naming.acronym-case` (advisory; medium confidence): Flags mixed casings of a known acronym in one file.
- `naming.boolean-prefix` (advisory; medium confidence): Flags boolean names without intent-revealing prefixes on declarations, function parameters (typed `: boolean` or with `= true|false` default), and interface/type-literal fields.
- `naming.class-file-mismatch` (advisory; medium confidence): Flags exported classes whose name differs from the file name.
- `naming.generic-function` (advisory; high confidence): Flags generic function names that hide intent.
- `naming.generic-parameter` (advisory; medium confidence; options: minCyclomatic, minLineCount, minParameters): Flags placeholder parameter names in multi-parameter, long, exported, or complex functions.
- `naming.hungarian-notation` (advisory; medium confidence): Flags identifiers named after storage type prefixes.
- `naming.identifier-quality` (advisory; medium confidence): Flags placeholder or numbered identifiers on declarations, function parameters, and destructured locals.
- `naming.inconsistent-casing` (advisory; medium confidence): Flags the same canonical identifier appearing in two different surface forms (for example CONSTANT_CASE and camelCase) in one file.
- `naming.negative-boolean` (advisory; medium confidence): Flags boolean identifiers framed as a negation on declarations, parameters, and interface fields.
- `naming.short-variable` (advisory; medium confidence): Flags very short variable names outside common loop counters; covers declarations, function parameters, and destructured locals.

## Security

- `security.async-foreach` (warning; medium confidence): Flags async callbacks passed to forEach.
- `security.disabled-tls-verification` (error; high confidence): Flags code that disables TLS certificate verification.
- `security.document-write` (warning; high confidence): Flags document.write usage.
- `security.dynamic-regexp` (warning; medium confidence): Flags external input used to construct regular expressions.
- `security.eval-call` (error; high confidence): Flags eval() dynamic code execution.
- `security.floating-promise` (warning; medium confidence): Flags promise-like calls without await, return, or void.
- `security.github-actions-broad-permissions` (warning; medium confidence): Flags GitHub Actions workflows that grant broad write permissions.
- `security.github-actions-pull-request-target` (warning; medium confidence): Flags pull_request_target workflows paired with risky execution or trust context.
- `security.github-actions-remote-shell` (warning; medium confidence): Flags workflow run steps that pipe remote downloads to a shell.
- `security.github-actions-secrets-in-pr` (warning; medium confidence): Flags pull request workflows that reference GitHub secrets.
- `security.github-actions-unpinned-action` (warning; medium confidence): Flags third-party GitHub Actions that are not pinned to a full commit SHA.
- `security.inner-html` (warning; high confidence): Flags innerHTML assignment.
- `security.insecure-random` (warning; high confidence): Flags Math.random usage in source.
- `security.javascript-url` (error; high confidence): Flags javascript: URL literals that execute script.
- `security.new-function` (error; high confidence): Flags Function constructor dynamic code execution.
- `security.open-redirect-candidate` (warning; medium confidence): Flags external input sent to redirect or navigation sinks.
- `security.path-traversal-candidate` (warning; medium confidence): Flags external input sent to filesystem path sinks.
- `security.process-exec` (warning; high confidence): Flags child-process execution calls.
- `security.proto-access` (warning; medium confidence): Flags direct __proto__ access that can enable prototype pollution.
- `security.remote-install-script` (error; medium confidence): Flags package scripts that pipe remote content to a shell.
- `security.risky-lifecycle-script` (warning; medium confidence): Flags package lifecycle scripts that run automatically.
- `security.sql-concatenation` (warning; high confidence): Flags SQL text composed with runtime string interpolation.
- `security.ssrf-candidate` (warning; medium confidence): Flags external input sent to network request sinks.
- `security.string-timer` (warning; high confidence): Flags string callbacks passed to timers.
- `security.throw-non-error` (warning; medium confidence): Flags thrown non-Error values.
- `security.url-dependency` (warning; medium confidence): Flags dependencies installed from URL or git specs.
- `security.weak-crypto` (warning; high confidence): Flags weak crypto primitives such as md5, sha1, or createCipher.

## Sensitive Data

- `sensitive-data.api-key-pattern` (error; high confidence): Flags vendor API key patterns.
- `sensitive-data.aws-access-key` (error; high confidence): Flags AWS access key looking values.
- `sensitive-data.database-url-password` (error; high confidence): Flags database URLs that include passwords.
- `sensitive-data.hardcoded-env-value` (error; medium confidence; threshold 16): Flags environment-style secret values committed in text.
- `sensitive-data.high-entropy-string` (error; medium confidence; threshold 32): Flags high-entropy string literals that may be secrets.
- `sensitive-data.jwt-token` (error; high confidence): Flags JWT-looking token literals.
- `sensitive-data.pii-pattern` (error; high confidence): Flags PII-like identifier patterns.
- `sensitive-data.private-key` (error; high confidence): Flags private key block markers.

## Size

- `size.file-length` (warning; high confidence; threshold 750): Flags files longer than the configured threshold.
- `size.function-length` (warning; high confidence; threshold 200): Flags functions longer than the configured threshold.
- `size.parameter-count` (warning; high confidence; threshold 7): Flags functions with too many parameters.
- `size.stylesheet-length` (warning; high confidence; threshold 1500): Flags stylesheets longer than the configured threshold.

## Test Quality

- `test-quality.conditional-logic` (advisory; high confidence): Flags tests with conditional logic.
- `test-quality.exception-type-only` (advisory; high confidence): Flags tests that only assert exception type.
- `test-quality.global-state-mutation` (warning; high confidence): Flags tests mutating process or global runtime state.
- `test-quality.loop-in-test` (advisory; high confidence): Flags loops inside test bodies.
- `test-quality.magic-number-assertion` (advisory; medium confidence): Flags assertions against unexplained numeric literals.
- `test-quality.missing-nearby-test` (advisory; medium confidence): Flags exported production files without nearby tests.
- `test-quality.mock-only-test` (advisory; high confidence): Flags tests that only verify mock interaction.
- `test-quality.no-assertions` (warning; high confidence): Flags tests without apparent assertions.
- `test-quality.no-throw-only-test` (advisory; high confidence): Flags tests that only assert code does not throw.
- `test-quality.only-skip` (advisory; high confidence): Flags focused or skipped test markers.
- `test-quality.setup-bloat` (advisory; medium confidence; threshold 12): Flags tests with too much setup before the first assertion.
- `test-quality.sleep-in-test` (advisory; high confidence): Flags sleeps in tests.
- `test-quality.snapshot-only-test` (advisory; high confidence): Flags tests that rely only on snapshots.
- `test-quality.trivial-assertion` (warning; high confidence): Flags tautological assertions.
- `test-quality.unused-mock` (advisory; medium confidence): Flags mocks created but not used.

## Maintainability

- `waste.any-type` (warning; high confidence): Flags any type usage.
- `waste.broad-runtime-version` (advisory; medium confidence): Flags broad runtime dependency version ranges.
- `waste.commented-out-code` (advisory; high confidence): Flags comments that appear to contain disabled code.
- `waste.console-log` (advisory; high confidence): Flags console log/debug calls in source.
- `waste.empty-function` (advisory; high confidence): Flags functions with no executable body.
- `waste.exported-any` (warning; medium confidence): Flags exported APIs exposing any.
- `waste.redundant-boolean-cast` (advisory; medium confidence): Flags redundant boolean casts in condition expressions.
- `waste.redundant-variable` (advisory; medium confidence): Flags variables returned immediately after assignment.
- `waste.swallowed-catch` (warning; medium confidence): Flags empty catch blocks.
- `waste.unreachable-code` (warning; high confidence): Flags statements after terminating statements.
- `waste.unused-import` (advisory; medium confidence): Flags named imports with no apparent usage.
- `waste.unused-parameter` (advisory; medium confidence): Flags parameters with no apparent usage.
- `waste.useless-catch` (advisory; high confidence): Flags catch blocks that only rethrow the caught value.
- `waste.useless-return` (advisory; medium confidence): Flags terminal bare return statements in void functions.
