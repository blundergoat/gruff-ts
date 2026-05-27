---
category: refactoring
last_reviewed: 2026-05-25
---

# Refactoring patterns

## Pattern: split a renderer module via a shared "rows" helper to break circular imports
**Created:** 2026-05-25

**Context:** A renderer module (e.g. `src/report-renderers.ts`) outgrew the `size.file-length` threshold (750 lines) and the natural cut was to extract one output format (HTML + dashboard chrome) into its own module. Both the leftover module and the new module need to keep producing identical Pillars-table output, so they must share `buildPillarRows` and `grade`. The naive split - dispatcher in `report-renderers.ts` imports `renderHtml` from `report-html.ts`, and `report-html.ts` imports `buildPillarRows` back from `report-renderers.ts` - produces `design.circular-import`. Node ESM tolerates it at runtime, but gruff flags it and it makes the dependency direction unreadable.

**Approach:**
1. Create a third module that owns the cross-format helpers. Naming: derive it from the helper's job (`src/pillar-summary.ts` here), not from "shared" or "utils".
2. Move ONLY the helpers that BOTH renderers need into it: `buildPillarRows`, `comparePillarRows`, `applicablePillarSet`, `buildPillarRow`, `countSeverityByPillar`, the `PillarRow` type, and `grade`. Leave format-specific helpers (`renderPillarsBlock`, `renderMarkdownPillarsTable`, `htmlPillars`) inside their renderers.
3. Wire one-way edges:
   - `pillar-summary.ts` → `rules.ts` + `types.ts` (no renderer dependencies)
   - `report-html.ts` → `pillar-summary.ts` + `types.ts`
   - `report-renderers.ts` → `pillar-summary.ts` + `rules.ts` + `report-html.ts`
   - `scoring.ts` and `dashboard.ts` update their direct imports (no compat re-exports)
4. Verify with `grep -rn "from \"./report-renderers\|from \"./report-html\|from \"./pillar-summary" src/` - the resulting graph must be acyclic and consumers like `cli.ts` should still import `renderReport` from `report-renderers.ts`.

**Evidence:** `src/pillar-summary.ts`, `src/report-html.ts`, `src/report-renderers.ts`. Before the split, `report-renderers.ts` was 899 lines; after it sits around 442 with `report-html.ts` at ~384 and `pillar-summary.ts` at ~123. The gruff scan reports `design.circular-import` as zero and the JSON keys in `gruff.summary.v2` are byte-identical to the pre-split output.

## Pattern: preserve a JSON wire key while renaming the internal interface field
**Created:** 2026-05-25

**Context:** `naming.boolean-prefix` fires on interface fields that lack an `is`/`has`/`can`/`should`/`will` prefix. `PillarRow.applicable` triggered the rule, but the JSON output schema `gruff.summary.v2` exposes `applicable: true` as the canonical key - renaming the wire key would be a schema bump (`gruff.summary.v3`) and break every downstream consumer parsing the field.

**Approach:**
1. Rename the TypeScript field to satisfy the prefix rule (`PillarRow.applicable` → `PillarRow.isApplicable`, `src/pillar-summary.ts`, search: `isApplicable: true`).
2. At the SINGLE serialization boundary in the renderer that emits the wire payload (`src/report-renderers.ts`, `renderSummaryJson`, search: `applicable: row.isApplicable`), explicit-map the typed field back to the documented wire key.
3. Verify with a runtime smoke test (`./bin/gruff-ts summary . --format=json --fail-on=none --no-baseline | node -e '…'`) that the parsed payload still has `applicable: true` and `schemaVersion: "gruff.summary.v2"`.

**Why this works:** the typed field and the JSON key are two different surfaces. The TypeScript field exists for compile-time clarity; the JSON key exists for cross-port wire compatibility. Renaming one without the other - via an explicit map at the boundary - keeps both surfaces clean. The reverse is also true for tests parsing the JSON: treat `payload` as `Record<string, unknown>` and access `row.applicable` at runtime to avoid declaring a typed interface whose field name fights the lint (see `assertPillarRowShape` in `src/cli-surfaces.test.ts`).

**When NOT to use:** if the field is consumed by your own TypeScript code (not just at a serialization boundary), the mapping cost spreads everywhere and the dual surface becomes confusing. Bump the schema instead.

## Pattern: "version consistency" check verifies internal surfaces, not registry state
**Created:** 2026-05-25

**Context:** The preflight gate (`scripts/preflight-checks.sh`) historically ran two checks under one "Release version" heading: (a) lockstep across `package.json`, `package-lock.json`, `src/constants.ts`; and (b) `npm view <name>@<version>` against the public registry to confirm the version was not already published. Mixing these collides two unrelated questions - "are our local files consistent?" and "should we bump?" - and the registry probe fails noisily during normal development whenever the current version is already on npm (which is true for every commit after the first publish).

**Approach:**
1. Reframe the step as "Version consistency" (`scripts/preflight-checks.sh`, search: `Version consistency`). Drop the `npm view` call entirely; drop `NPM_REGISTRY_URL` from environment docs.
2. Extend `scripts/bump-version.sh --check` (search: `function check_version_lockstep`) to ALSO verify that `CHANGELOG.md`'s most-recent `## [version]` heading matches `package.json`. Two failure modes are both inconsistency: (a) package bumped without changelog entry, (b) changelog bumped without package bumped. The error message names both remediations - "run `scripts/bump-version.sh <changelog-version>` or add a CHANGELOG.md entry for <package-version>".
3. The "should we bump?" question moves out of the preflight - either it lives in the release process, or the user runs `npm view` ad-hoc. Local development never hits the noisy "already published" failure.

**Evidence:** `scripts/preflight-checks.sh` `version_consistency_check`; `scripts/bump-version.sh` `check_version_lockstep` (reads `CHANGELOG.md` via `read_changelog_latest_version`). After the rework, `scripts/preflight-checks.sh` ran 5/5 green at 0.1.2 with the CHANGELOG, package files, and `src/constants.ts` all in agreement; a deliberately desynced CHANGELOG triggers a clear failure that names both fix paths.
