---
category: schema-and-cli
last_reviewed: 2026-05-10
---

# Schema + CLI surface footguns

## Footgun: schema version strings are public contract

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

Three string literals in `src/cli.ts` are part of the public output contract: `gruff.analysis.v1` (set in `analyse`, search: `schemaVersion: "gruff.analysis.v1"`), `gruff.baseline.v1` (`writeBaseline` / `applyBaseline`), and `gruff.hotspot.v1` (`renderReport` hotspot branch). Downstream consumers (CI integrations, baseline files already on disk) match on these strings exactly. `applyBaseline` even throws `unsupported baseline schema` on mismatch — bumping the baseline version invalidates every existing `gruff-baseline.json` in users' repos. Bump only when the user explicitly asks AND a migration story is in place.

## Footgun: `exitFor` returns 2 on ANY diagnostic, regardless of `--fail-on`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`exitFor` (`src/cli.ts`, search: `function exitFor`) returns `2` if `report.diagnostics.length > 0` before it ever consults `failOn`. That means a single `read-error`, `missing-path`, `parse-error`, or `history-error` fails the run even with `--fail-on none`. Tests and CI users sometimes assume `--fail-on none` is "always exit 0" — it is not. If you add a new diagnostic type, that diagnostic alone will start failing every consumer's CI on first appearance.

## Footgun: `--no-baseline` and `--no-config` are CommanderJS auto-negations, not custom flags

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`normalizeOptions` (`src/cli.ts`, search: `function normalizeOptions`) reads `rawOptions.config === false` and `rawOptions.noConfig === true` to decide whether to load the default `.gruff.json`; same pattern for baseline (`baselineValue === false || rawOptions.noBaseline === true`). These come from Commander's `--no-config`/`--no-baseline` automatic negations, which set the *positive* option to `false`. If you migrate to a different CLI framework or change the option declaration, both branches must be reviewed together — testing only `noConfig` will leave silent gaps.

## Footgun: default-ignored directories are hardcoded and lowercase-only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`isDefaultIgnoredDir` (`src/cli.ts`, search: `function isDefaultIgnoredDir`) checks the FIRST path segment against a fixed lowercase list (`.git`, `.hg`, `.svn`, `.idea`, `.vscode`, `build`, `cache`, `coverage`, `dist`, `generated`, `node_modules`, `target`, `tmp`, `vendor`). Project conventions like `Build/`, `out/`, `__pycache__/`, `.next/`, `.turbo/`, `.venv/` are NOT ignored by default — they get walked, scanned, and reported. Adding to the list is one line, but every addition is a behavioural change for users who had findings inside those dirs accepted into their baseline.
