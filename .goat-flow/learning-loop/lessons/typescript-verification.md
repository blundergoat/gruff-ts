---
category: typescript-verification
last_reviewed: 2026-08-07
---

# TypeScript verification lessons

## Lesson: project shared structural fields instead of spreading broader objects

**Created:** 2026-07-12

**What happened:** Declaration ownership reused `CallableMatchPoint` as an `IdentifierOwner` because it structurally contains `ownerId`, `ownerKind`, and `ownerName`. The first implementation spread that whole callable object into a parameter inventory row. Its unrelated `name` field then overwrote the parameter name, so the focused owner test reported `# pass 45` / `# fail 1` even though both rows carried the correct function id.

**Evidence:** `src/class-rules.ts` (search: `ownerId: owner.ownerId`) now projects only the three owner fields; the parameter/local probe shows `note_id` and `noteId` under the same `function:0:94` owner, and the focused suite reports `# tests 46` / `# pass 46` / `# fail 0`.

**Prevention:** When a narrower TypeScript interface accepts a structurally broader runtime object, do not assume object spread narrows it. Explicitly project the allowed fields before merging with another domain row, especially when both shapes use common keys such as `name`, `line`, or `kind`.

## Lesson: narrow regex-backed strings before joining a typed syntax inventory

**Created:** 2026-07-12

**What happened:** The syntax-backed public-export inventory exposed a closed declaration-kind union, while the retained regex fallback returned the same five values through an older `kind: string` interface. The first `npx tsc --noEmit` stopped with `ExportedDeclaration[]` not assignable to `PublicExportDeclaration[]`, even though the runtime regex cannot produce another kind.

**Evidence:** `src/class-rules.ts` (search: `kind: declaration.kind as PublicExportDeclaration`) now narrows only at the legacy adapter boundary; the next `npx tsc --noEmit` exits 0 and the syntax path remains union-typed end to end.

**Prevention:** When a new syntax model meets a legacy regex model, do not widen the new union to `string`. Translate or narrow the legacy value at one reviewed boundary, and keep downstream user-facing metadata closed over the documented vocabulary.

## Lesson: metric semantics changes require a full assertion inventory

**Created:** 2026-07-13

**What happened:** The focused substantive-line regressions passed, but the first full `npm run check` failed because two changed-region and hook contract assertions still expected physical line totals. Both fixtures intentionally contained a comment-only line or trailing blank line, so their old `metadata.lines` expectations were no longer the public metric being implemented.

**Evidence:** `src/changed-region-scope.test.ts` (search: `lines: 7, threshold: 3`) and `src/hook-contract.test.ts` (search: `FIXTURE_SUBSTANTIVE_LINES`) now assert the substantive count; the failing full run reported `# pass 421` / `# fail 2` before those expectations were corrected.

**Prevention:** Before changing a metric's meaning, grep the whole test suite for its metadata keys and rendered measurements, not only the rule's focused suite. Classify each assertion as identity, threshold, or measurement semantics and update only the semantic expectations.

## Lesson: source-scanning contract tests must follow refactors across helper contexts

**Created:** 2026-05-17

**What happened:** During self-scan cleanup, `npm run check` failed after threshold-backed rules were refactored to read thresholds through `context.config` instead of a direct `config` parameter. The analyzer behavior was intact, but the descriptor/config threshold contract test only searched for `threshold(config, ...)`, so it undercounted implemented thresholds until the regex was widened.

**Evidence:** `src/cli.test.ts` + `(search: "function thresholdUsages")`; the failing run reported missing implementation thresholds for `size.function-length`, `size.parameter-count`, `complexity.cyclomatic`, `complexity.cognitive`, and `complexity.npath`.

**Prevention:** When a contract test scans source text instead of calling a structured API, update its extractor in the same refactor that changes call shape. Prefer matching the semantic argument form, such as optional context prefixes, over one local variable spelling.
