---
category: schema-and-cli
last_reviewed: 2026-05-24
---

# Schema + CLI surface footguns

## Footgun: schema version strings are public contract

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

Three string literals in `src/cli.ts` are part of the public output contract: `gruff.analysis.v1` (set in `analyse`, search: `schemaVersion: "gruff.analysis.v1"`), `gruff.baseline.v1` (`writeBaseline` / `applyBaseline`), and `gruff.hotspot.v1` (`renderReport` hotspot branch). Downstream consumers (CI integrations, baseline files already on disk) match on these strings exactly. `applyBaseline` even throws `unsupported baseline schema` on mismatch - bumping the baseline version invalidates every existing `gruff-baseline.json` in users' repos. Bump only when the user explicitly asks AND a migration story is in place.

## Footgun: `exitFor` returns 2 on ANY diagnostic, regardless of `--fail-on`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`exitFor` (`src/cli.ts`, search: `function exitFor`) returns `2` if `report.diagnostics.length > 0` before it ever consults `failOn`. That means a single `read-error`, `missing-path`, `parse-error`, or `history-error` fails the run even with `--fail-on none`. Tests and CI users sometimes assume `--fail-on none` is "always exit 0" - it is not. If you add a new diagnostic type, that diagnostic alone will start failing every consumer's CI on first appearance.

## Footgun: `--no-baseline` and `--no-config` are CommanderJS auto-negations, not custom flags

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`normalizeOptions` (`src/cli.ts`, search: `function normalizeOptions`) reads `rawOptions.config === false` and `rawOptions.noConfig === true` to decide whether to load the default `.gruff-ts.yaml`; same pattern for baseline (`baselineValue === false || rawOptions.noBaseline === true`). These come from Commander's `--no-config`/`--no-baseline` automatic negations, which set the *positive* option to `false`. If you migrate to a different CLI framework or change the option declaration, both branches must be reviewed together - testing only `noConfig` will leave silent gaps.

## Footgun: default-ignored directories are hardcoded and lowercase-only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`isDefaultIgnoredDir` (`src/cli.ts`, search: `function isDefaultIgnoredDir`) checks the FIRST path segment against a fixed lowercase list (`.git`, `.hg`, `.svn`, `.idea`, `.vscode`, `build`, `cache`, `coverage`, `dist`, `generated`, `node_modules`, `target`, `tmp`, `vendor`). Project conventions like `Build/`, `out/`, `__pycache__/`, `.next/`, `.turbo/`, `.venv/` are NOT ignored by default - they get walked, scanned, and reported. Adding to the list is one line, but every addition is a behavioural change for users who had findings inside those dirs accepted into their baseline.

## Footgun: `gruff-ts init --force` regenerates the whole YAML and can wipe user customisations

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

`writeDefaultConfig` (`src/init-config.ts`, search: `function writeDefaultConfig`) overwrites `.gruff-ts.yaml` with the registry-derived default whenever `--force` is set. As of 2026-05-24 the function preserves the existing `paths.ignore` block (via `readExistingIgnoredPaths`, search: `function readExistingIgnoredPaths`), but **everything else is still clobbered**: `allowlists.acceptedAbbreviations` custom entries, any per-rule `threshold`/`severity`/`options` tuning, disabled rules, and so on revert to the rendered defaults. A real incident in 2026-05 dropped a project's curated `paths.ignore` (`.agents/**`, `.claude/**`, `.codex/**`, `.github/**`, `.goat-flow/**`, `fixtures/**`) when init was rerun without `--force` protections; the regression was only noticed after the commit had been pushed. When editing the init flow: NEVER add a new regenerated section without either (a) reading the existing value and preserving it, or (b) writing a loud stderr warning that lists what is about to be lost. When asked to regenerate the config in a real project: review the diff before committing - `git diff -- .gruff-ts.yaml` is the only thing standing between the user and a silent customisation loss.

## Footgun: pre-existing `M <config>` in git status at session start may already represent a customisation loss

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

If a session starts with `M .gruff-ts.yaml` (or any other user-curated config) already in the working tree, do NOT treat that as "fine, the user is mid-edit." Run `git diff -- .gruff-ts.yaml` against `HEAD` before editing the file - a regenerated config from `gruff-ts init` can look like ordinary modifications but actually represent destroyed user customisations (`paths.ignore`, `allowlists.acceptedAbbreviations`, rule tuning). If the diff shows entries vanishing from a sequence, surface that to the user before doing anything else; do not let the loss ride into your own commits or into a user commit that bundles it.
