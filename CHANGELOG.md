# Changelog

All notable changes to `gruff-ts` are documented here.

This project follows semantic versioning once public releases begin.

## [0.1.0] - 2026-05-19

Initial public release.

### CLI

- `analyse [paths...]` runs the scanner and prints findings; defaults to
  `--fail-on=error`.
- `summary [paths...]` prints per-pillar counts, top rules, and top file
  offenders without per-finding output.
- `report [paths...]` renders an HTML or JSON report, optionally to a file;
  defaults to `--fail-on=none`.
- `list-rules` prints the rule catalogue in `text` or `json` form.
- `dashboard` serves a local HTTP dashboard with iframe report and controls
  panel; binds to `127.0.0.1:8767` by default.
- `completion [shell]` prints a shell completion script for `bash`, `zsh`, or
  `fish`.
- `list` prints a Symfony-style command catalogue with ANSI section headers
  when stdout is a TTY.
- Global console options match the `gruff` PHP CLI surface: `--silent`,
  `--quiet`, `--ansi` / `--no-ansi`, `--no-interaction`, and
  `-v` / `-vv` / `-vvv`.
- `-V, --version` prints the CLI version sourced from `src/constants.ts`.

### Rules

- 112 rule descriptors across 11 public pillars:
  - `complexity` (3): cognitive, cyclomatic, npath.
  - `dead-code` (1): unused-private-method.
  - `design` (6): circular-import, deep-relative-import, god-function,
    large-module-concentration, package-bin-missing,
    package-bin-not-executable.
  - `documentation` (18): missing-file-overview, missing-function-doc,
    missing-interface-doc, missing-public-doc, missing-param-tag,
    missing-return-tag, missing-side-effect-doc, missing-error-behavior-doc,
    missing-invariant-doc, missing-why-for-complex-code,
    magic-threshold-without-rationale, fixture-purpose-missing,
    suppression-without-rationale, stale-comment, stale-param-tag,
    useless-docblock, todo-density (opt-in), todo-without-tracking.
  - `modernisation` (14): date-now-candidate, double-cast, loose-equality,
    non-null-assertion, nullish-coalescing-candidate, object-spread-candidate,
    optional-chaining-candidate, public-property, readonly-property-candidate,
    ts-comment-without-rationale, tsconfig-strict-disabled,
    tsconfig-index-safety-disabled, tsconfig-exact-optional-disabled,
    var-declaration.
  - `naming` (11): abbreviation (opt-in), acronym-case, boolean-prefix,
    class-file-mismatch, generic-function, generic-parameter,
    hungarian-notation, identifier-quality, inconsistent-casing,
    negative-boolean, short-variable.
  - `security` (18): async-foreach, disabled-tls-verification, document-write,
    eval-call, floating-promise, inner-html, insecure-random, javascript-url,
    new-function, process-exec, proto-access, remote-install-script,
    risky-lifecycle-script, sql-concatenation, string-timer, throw-non-error,
    url-dependency, weak-crypto.
  - `sensitive-data` (8): api-key-pattern, aws-access-key,
    database-url-password, hardcoded-env-value, high-entropy-string,
    jwt-token, pii-pattern, private-key.
  - `size` (4): file-length, function-length, parameter-count,
    stylesheet-length.
  - `test-quality` (15): conditional-logic, exception-type-only,
    global-state-mutation, loop-in-test, magic-number-assertion,
    missing-nearby-test, mock-only-test, no-assertions, no-throw-only-test,
    only-skip, setup-bloat, sleep-in-test, snapshot-only-test,
    trivial-assertion, unused-mock.
  - `waste` (14): any-type, broad-runtime-version, commented-out-code,
    console-log, empty-function, exported-any, redundant-boolean-cast,
    redundant-variable, swallowed-catch, unreachable-code, unused-import,
    unused-parameter, useless-catch, useless-return.
- Each finding carries a stable `fingerprint` so baselines and report
  snapshots round-trip without churn.
- Rule descriptors expose severity, confidence, remediation text, threshold
  values, and option keys; all are visible via `gruff-ts list-rules`.

### Output Formats

- `text` — human terminal output (default).
- `json` — full `gruff.analysis.v1` machine report.
- `html` — self-contained dark inspection report.
- `markdown` — short Markdown summary.
- `github` — GitHub Actions annotation commands.
- `hotspot` — compact `gruff.hotspot.v1` top-offender payload.
- `sarif` — SARIF 2.1.0 code-scanning output.
- `report` supports `html` and `json`.

### Configuration

- Auto-loads `.gruff-ts.yaml` from the project root; `--config <path>` and
  `--no-config` override the default.
- `paths.ignore` extends the default ignored directory list with exact paths,
  prefix paths, or glob patterns.
- `allowlists.acceptedAbbreviations` lowers naming-rule noise; project-local
  short terms can be added without disabling rules.
- `allowlists.secretPreviews` accepts known false-positive redacted previews
  without disabling the underlying sensitive-data rule.
- Per-rule controls: `enabled`, `threshold`, `severity`, and rule-specific
  `options` for tuning knobs.

### Baselines, History, And CI

- `--generate-baseline <path>` writes findings to a `gruff.baseline.v1` file.
- `--baseline <path>` suppresses findings whose fingerprint matches the
  baseline; `--no-baseline` skips the default lookup.
- `--diff` filters findings to changed files. Accepts `working-tree`,
  `staged`, `unstaged`, or a base ref such as `origin/main`.
- `--include-ignored` opts a run into default-ignored and Git-ignored paths.
  Configured `paths.ignore` still applies.
- `--history-file <path>` appends per-run score history as a local JSON file.
- Exit codes: `0` clean, `1` finding met `--fail-on`, `2` scan diagnostics.

### Dashboard

- Local HTTP dashboard with `/` (iframe shell and controls panel), `/health`
  (plain `ok`), and `/scan?projectRoot=<path>&path=<path>` (report HTML).
- Loopback default (`127.0.0.1`); the bind address is the main safety
  boundary because `/scan` accepts filesystem paths from request parameters.

### Source Layout

- Runtime lives under `src/`:
  - `cli.ts` — analyser entry point and scanner orchestration.
  - `cli-program.ts` — Commander program wiring and option normalization.
  - `discovery.ts` — source-file discovery and `.gitignore` handling.
  - `rules.ts` — pillar rule descriptors and matchers.
  - `sensitive-data-rules.ts` — sensitive-data rule descriptors and detectors.
  - `project-config-rules.ts` — package/tsconfig rule descriptors.
  - `baseline.ts`, `config.ts`, `dashboard.ts`, `findings.ts`,
    `rule-list.ts`, `scoring.ts`, `source-text.ts`, `text-scans.ts`,
    `report-renderers.ts`, `constants.ts`, `types.ts`.
- Tests in `src/cli.test.ts`.

### Tooling

- `scripts/bump-version.sh <semver>` bumps `package.json` and
  `src/constants.ts` together; `--check` verifies they agree.
- `scripts/check.sh` runs `npm run check` (`tsc --noEmit && npm test`).
- `scripts/preflight-checks.sh` runs release-readiness gates before
  publishing.
- `scripts/start-dev.sh` starts the dashboard with environment overrides.
- `scripts/test-performance.sh` records a `gruff-perf.v1` matrix and compares
  against a stored baseline.

### Public Schemas

- `gruff.analysis.v1` for full analysis reports.
- `gruff.baseline.v1` for baseline files.
- `gruff.hotspot.v1` for hotspot output.

### Security

- Sensitive-data findings emit redacted previews; raw values are not
  rendered.
- Dashboard binds to `127.0.0.1` by default.
- HTML output is generated without a template engine; interpolated fields are
  escaped at render time.

### License

- Released under the [MIT License](LICENSE).
