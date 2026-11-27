# Using gruff-ts As A Coding-Agent Hook

`gruff-ts` governs AI-generated code (see [Philosophy](philosophy.md) for the reasoning). This guide shows how to wire it in as a forcing function on an agent's edits before a human reviews the diff.

## The model

A coding agent will keep iterating until the checks pass. Running `gruff-ts` on the agent's diff turns that loop into leverage: the agent has to resolve findings - add the missing doc comment, simplify tangled branching, drop the unsafe call, replace the tautological test - before handing the change to you.

For CI-style gates, `analyse` owns the exit code:

- `0` - no finding met `--fail-on`; the change passes.
- `1` - at least one finding met `--fail-on`; the agent must fix it and re-run.
- `2` - fatal error (missing input, parse failure, or bad config); stop and surface it.

For editor or PostToolUse feedback, use the `hook` subcommand instead:

```bash
gruff-ts hook --format json --changed-ranges "12-40,88-90" src/foo.ts
gruff-ts hook --capabilities --format json
```

`hook` outputs `gruff.hook.v2` JSON: a nine-key envelope (`contractVersion`, `analyzer`, `run`, `findings`, `diagnostics`, `suppressed`, `suppressions`, `ignored`, and `config`) with normalized `file` and `scope` per finding, non-null `remediation`, stable identities, and machine-readable threshold metadata.

Hook mode is advisory by default (`--fail-on none`): it reports findings and exits `0`. Only an explicit gate flag blocks the edit, so `hook` uses its own exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Nothing hit a requested gate. The default `--fail-on none` exits `0` regardless of finding severity. |
| `1` | A published finding met `--fail-on`, a finding was new against the baseline under `--fail-on-new`, or `--fail-on-diagnostics` saw a relevant diagnostic. |
| `2` | The run could not complete. A config error also populates `config.error`; an unusable baseline or invalid changed range appears as a fatal entry in `diagnostics`. |

Pair `--fail-on-new` with `--baseline <path>`. A missing baseline, or an input file that is missing or unreadable, exits `2` with a fatal diagnostic.

Parse diagnostics appear in-band in `diagnostics` (`{ type, message, file, line }`). Full scans include diagnostics from every analysed file, `--diff`/`--since` runs include only changed files, and `--changed-ranges` includes every diagnostic for each requested file (a syntax error breaks parsing for the whole file, so line ranges never hide it). By default `hook` still exits `0` when parse diagnostics are present; pass `--fail-on-diagnostics` to exit `1` instead. The capabilities payload advertises this through `supports.diagnostics` and `flags.failOnDiagnostics` (advertisement only - it never changes behavior on its own). A run that could not happen exits `2`: a missing or unreadable input, an unusable baseline, an invalid changed range, or a config error.

## Scan the change, not the repo

> **Goal:** govern only the code the agent changed, so the agent fixes its own diff without getting blocked by unrelated backlog elsewhere in the repo.

Gate the agent on what it actually touched:

```bash
# Uncommitted working-tree changes (typical agent loop)
npx gruff-ts analyse . --diff=working-tree --fail-on=warning

# Staged changes (pre-commit)
npx gruff-ts analyse . --diff=staged --fail-on=warning

# Everything changed since a ref (pre-push or PR)
npx gruff-ts analyse . --since origin/main --fail-on=warning

# Exact hunks, when the agent already knows the line ranges
npx gruff-ts analyse --changed-ranges "12-40,88-90" src/foo.ts --fail-on=warning

# Piped diff
git diff | npx gruff-ts analyse --diff - --fail-on=warning
```

Changed-region scans keep only findings tied to the changed hunk, its enclosing symbol, or a project relationship touching the requested file. In `hook` mode, whole-file rules like `size.file-length` stay suppressed under changed-region attribution (counted in `suppressed.count`) and appear only in full scans or when `--baseline` / `--diff` shows their identity is new. Circular-import findings still appear when a requested file joins a strongly connected component (SCC), keeping the canonical SCC anchor rather than moving to the edited file. In `analyse`, pass `--changed-scope file` when a CI job wants every finding from touched files.

## Respect the project's ignore policy

Hooks pass changed file paths directly, so `paths.ignore` must hold for explicit paths too - otherwise the agent wastes cycles editing generated or vendored files the repo intentionally skips. `paths.ignore` applies in every mode (explicit operands, diffs, and changed regions); skipped files produce no findings and appear in `paths.details` with their `source` and `pattern`. `--include-ignored` opts into Git and default ignores only and never overrides `paths.ignore`.

To pre-filter changed files before scanning, use `check-ignore` - it shares the exact same ignore engine as `analyse` and runs no analysis:

```bash
# Which of the agent's changed files would gruff skip?
gruff-ts check-ignore $CHANGED_FILES --format json
# exit 0 = at least one ignored, 1 = none, 2 = config error
```

## Picking the gate level

`--fail-on` sets the bar the agent must clear. Defaults are `advisory` for `analyse` and `none` for `summary`, `report`, and `hook`:

| Level | Use it as the agent gate when |
| --- | --- |
| `error` | You only want to block the highest-severity issues (`eval`, `new Function`, disabled TLS verification, `javascript:` URLs, remote install scripts, oversized files). Minimal friction, though `sensitive-data.*` findings default to `warning` and will not trip this gate. |
| `warning` | Recommended default. Blocks security, sensitive-data, correctness, and key verifiability checks (missing exported-API docs, weak tests) while leaving advisories as nudges. |
| `advisory` | Strictest. Every finding blocks until resolved. Best when you want full legibility pressure and can accept extra agent turns. |

You can pin per-command levels in `.gruff-ts.yaml` under `failOn:` (see [Configuration](configuration.md)); precedence is CLI flag > config > built-in default.

## Fix, do not suppress

Baselines exist for legacy adoption, not agent governance. Baselining an agent's new output hides the exact signals a human reviewer needs. Scope the hook by changed region (above) instead of suppressing findings.

## In CI

```bash
# Annotate the PR and fail the job on warning-or-higher findings
npx gruff-ts analyse . --since origin/main --format=github --fail-on=warning

# Security and secret gate that ignores any adoption baseline
npx gruff-ts analyse . --no-baseline --fail-on=warning
```

## Why the doc-comment pressure is deliberate

The documentation rules are strict on purpose - even on a private one-liner. When an agent has to state intent, parameters, return behavior, and error conditions in prose, you get a second, independent description to check against the code. A mismatch between the comment and the implementation is a strong signal that the change needs a closer look. Treat doc findings as part of the verifiability gate, not optional polish.
