# Using gruff-ts As A Coding-Agent Hook

gruff-ts is built to govern AI-generated code (see [Philosophy](philosophy.md) for the why). This page is the practical how: wiring it in so it acts as a forcing function on an agent's output, before a human is asked to review.

## The model

A coding agent will rewrite code until the checks pass. gruff-ts turns that into leverage: run it on the agent's change and gate on the result, so the agent has to resolve findings - add the missing doc comment, cut the unverifiable branching, drop the unsafe call, replace the mock-only test - before the change reaches you. What lands is already shaped for sign-off.

The gate is the exit code:

- `0` - no finding met the `--fail-on` level; the change passes.
- `1` - at least one finding met `--fail-on`; the agent must fix and re-run.
- `2` - fatal (bad input, parse or config error); stop and surface it.

## Scan the change, not the repo

Gate the agent on what it actually touched, so a clean diff is not blocked by pre-existing findings elsewhere:

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

Changed-region scans keep only findings attributable to the changed hunk or its enclosing symbol, so the agent fixes its own work instead of inheriting the whole backlog.

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
