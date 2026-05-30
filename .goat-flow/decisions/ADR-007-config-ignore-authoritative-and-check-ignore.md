# ADR-007: Config paths.ignore Authoritative In Every Invocation; check-ignore Command

**Status:** Implemented
**Date:** 2026-05-30
**Author(s):** Claude, user
**Ticket/Context:** A coding-agent hook surfaced findings for deliberately-excluded files when changed paths were passed explicitly.

## Decision

Config `paths.ignore` is authoritative in every `analyse` / `report` / `summary` invocation shape: the recursive directory walk, explicit file operands, and all diff/changed-region modes (`--diff`, `--diff -`, `--changed-ranges`, `--since`). A path matching `paths.ignore` is excluded from analysis and produces no findings, however it was supplied, and is reported in `paths.skipped` with its `source` and the matching `pattern`.

`--include-ignored` opts into git-ignored and default-ignored paths only. It never overrides config `paths.ignore`.

git-ignore and default-directory ignores stay discovery-walk concerns: per ADR-003 an explicitly supplied supported file is still scannable even when git-ignored, so the explicit-file path applies only config `paths.ignore` (it passes empty gitignore rules to the shared engine).

A new `check-ignore [--format text|json] [--config <path>|--no-config] <path>...` command reports, per path, whether gruff would ignore it and by which `source` + `pattern`, sharing the exact ignore engine as discovery (`classifyIgnore` in `src/discovery.ts`) and performing no analysis. JSON output is `[{ "path", "ignored", "source", "pattern" }]`; exit codes mirror `git check-ignore` (0 = at least one ignored, 1 = none, 2 = error).

## Schema

Additive, no version bump. `gruff.analysis.v2` gains `paths.skipped: Array<{ path, source, pattern }>`; `paths.ignoredPaths: string[]` is retained as the back-compatible list of the same paths. Existing v2 consumers (JSON, SARIF, dashboard) are unaffected. This does not change `Finding`, `gruff.baseline.v1`, `gruff.hotspot.v1`, `package.json`, or `tsconfig.json`.

## Context

`paths.ignore` was applied only during the directory walk (`isIgnoredDiscoveryPath`). `discoverSourceInput` short-circuited for explicit file operands and pushed them straight to the scan set, so `gruff-ts analyse fixtures/sample.ts` analysed and flagged a file the project excluded via `fixtures/**` (verified: analysedFiles 1, 20 findings). A coding-agent hook passes exactly those explicit/changed paths, so it surfaced out-of-scope findings and pushed the agent to "fix" excluded code.

Two consumers need the ignore decision: the analyser (must emit no findings for ignored files in any invocation) and the hook/agent (must be told which files were ignored and why). One shared engine satisfies both without a second glob implementation.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Leave explicit operands bypassing `paths.ignore` | The hook's core use case (pass changed files) ignores project scope policy; the agent wastes loops on excluded code. | Rejected. This is the correctness gap being closed. |
| Make explicit operands honour git/default ignores too | Contradicts ADR-003 (an explicit supported file must stay scannable even if git-ignored). | Rejected. Only config `paths.ignore` is made authoritative for explicit operands. |
| Replace `paths.ignore` array in the report with a richer object | Breaks `gruff.analysis.v2` consumers reading `ignoredPaths: string[]`. | Rejected. Added a parallel `paths.skipped` and kept `ignoredPaths`. |
| Duplicate the glob matcher in a standalone `check-ignore` | Two ignore engines drift; `check-ignore` and `analyse` could disagree. | Rejected. `check-ignore` calls the same `classifyIgnore`. |
| One shared engine; config authoritative; additive `skipped`; new `check-ignore` | Correct in every mode, back-compatible, single source of truth, agent-queryable. | Accepted. |

## Consequences

The explicit-file path in `discoverSourceInput` must keep applying config `paths.ignore` (with empty gitignore rules) before `pushSourceFile`. `check-ignore` must keep calling the discovery engine, never a private copy. Reports now list more `ignoredPaths` entries than before (explicit config-ignored files are recorded) - the intended behaviour change.

## Reversibility

Behavioural contract for the agent-hook use case; treat as stable. Reverting would re-open the bug where explicit/changed config-ignored paths are scanned. Any revisit must preserve `gruff.analysis.v2` and stable fingerprints unless the user approves schema churn.
