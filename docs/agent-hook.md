# Using gruff-ts As A Coding-Agent Hook

gruff-ts is built to govern AI-generated code (see [Philosophy](philosophy.md) for the why). This page is the practical how: wiring it in so it acts as a forcing function on an agent's output, before a human is asked to review.

## The model

A coding agent will rewrite code until the checks pass. gruff-ts turns that into leverage: run it on the agent's change and gate on the result, so the agent has to resolve findings - add the missing doc comment, cut the unverifiable branching, drop the unsafe call, replace the mock-only test - before the change reaches you. What lands is already shaped for sign-off.

For CI-style gates, `analyse` owns the exit code:

- `0` - no finding met the `--fail-on` level; the change passes.
- `1` - at least one finding met `--fail-on`; the agent must fix and re-run.
- `2` - fatal (bad input, parse or config error); stop and surface it.

For editor or PostToolUse feedback, use the analyser-owned hook contract instead:

```bash
gruff-ts hook --format json --changed-ranges "12-40,88-90" src/foo.ts
gruff-ts hook --capabilities --format json
```

`hook` emits `gruff.hook.v1` JSON with normalized `file`, `scope`, `suppressed.count`,
`ignored.paths`, non-null `remediation`, stable identities, and machine-readable threshold
metadata. Hook mode is advisory: findings exit `0`; config failures are returned in
`config.error` and exit `2`.

Parse and read diagnostics are file-scoped and reported in-band via the additive
`diagnostics` array (`{ type, message, file, line }`): a full scan carries every
analysed file's diagnostics, a `--diff`/`--since` run carries only diagnostics
from changed target files, and `--changed-ranges` carries every diagnostic of
each requested file (a syntax error breaks parsing of the whole file, so ranges
never filter diagnostics). The default hook exit stays `0` with diagnostics
in-band; pass the explicit consumer request flag `--fail-on-diagnostics` to exit
`2` when relevant diagnostics exist. The capability handshake advertises this via
`supports.diagnostics` and `flags.failOnDiagnostics` - the capability is a
producer advertisement only and never changes behavior by itself. Fatal failures
(analysis could not run at all) keep operational-error exit `2` semantics.

## Scan the change, not the repo

> **Goal:** govern only the code the agent changed, not the whole repo - so the agent resolves findings in its own diff and a clean change is never blocked by pre-existing findings elsewhere.

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

Changed-region scans keep only findings attributable to the changed hunk, its enclosing symbol, or a project relationship that includes the requested file, so the agent fixes its own work instead of inheriting the whole backlog. In `hook` mode, whole-file metrics such as `size.file-length` are omitted under changed-region attribution and counted in `suppressed.count`; they return only in full-scan hook output or when `--baseline` / `--diff` shows their stable identity is new. Circular-import findings can appear as project-scope findings when the requested file participates in the SCC; they keep the canonical SCC anchor rather than re-anchoring to the edited file. In `analyse`, use `--changed-scope file` for CI jobs that intentionally want every finding from a touched file.

## Respect the project's ignore policy

A hook passes the agent's changed files directly, so the project's `paths.ignore` must hold for those explicit paths too - otherwise the agent burns loops "fixing" generated or vendored code the project deliberately excludes. Config `paths.ignore` is authoritative in every invocation (explicit operand, diff, changed-region): a matching path produces no findings and is listed in the report's `paths.skipped` with its `source` and `pattern`. `--include-ignored` opts into git/default ignores only and never overrides `paths.ignore`.

To pre-filter a changed-file list before scanning, ask gruff which paths it would skip - it shares the same engine as `analyse` and runs no analysis:

```bash
# Which of the agent's changed files would gruff skip?
gruff-ts check-ignore $CHANGED_FILES --format json
# exit 0 = at least one ignored, 1 = none, 2 = config error
```

## Picking the gate level

`--fail-on` sets the bar the agent must clear. Built-in defaults are `advisory` for `analyse` and `summary`, `none` for `report`; raise or lower per surface:

| Level | Use it as the agent gate when |
| --- | --- |
| `error` | You only want to block the highest-severity issues (committed secrets, `eval`, disabled TLS). Minimal friction. |
| `warning` | Recommended default. Blocks the security and correctness tier plus the verifiability signals (complexity, missing exported-API docs, weak tests) while leaving advisories as nudges. |
| `advisory` | Strictest. Every finding is friction the agent must clear. Best when you want maximum legibility pressure and can tolerate more agent rework. |

Per-command levels can be pinned in `.gruff-ts.yaml` via the `minimumSeverity:` block (see [Configuration](configuration.md)); precedence is CLI flag > config > built-in default.

## Fix, do not suppress

Baselines exist for legacy adoption, not agent governance. Suppressing an agent's findings defeats the purpose: the goal is code a human can verify, and a baseline hides exactly the things they would check. Gate the agent on its diff (above) rather than baselining its output; if you must scope a run, scope it by changed region, not by suppression.

## In CI

```bash
# Annotate the PR and fail the job on warning-or-higher findings
npx gruff-ts analyse . --since origin/main --format=github --fail-on=warning

# Security-only gate that ignores any adoption baseline
npx gruff-ts analyse . --no-baseline --fail-on=error
```

## Why the doc-comment pressure is deliberate

The documentation pillar is strict on purpose - a doc comment is expected even on a private one-liner. An agent that states intent, usage, contract, and failure behaviour in prose gives you a second, independent description to check the code against, and a mismatch between the comment and the code is itself a signal the change needs a closer look. Treat documentation findings as part of the verifiability gate, not as optional polish.
