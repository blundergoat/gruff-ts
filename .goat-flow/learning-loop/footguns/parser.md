---
category: parser
last_reviewed: 2026-08-09
hallucination-risk: high
---

# Parser footguns (`src/source-text.ts`)

Static-analysis surfaces that look like a real TS parser may still be regex/character heuristics, syntax-only parser passes, or single-file text scans. Agents reading the code from names alone (`functionBlocks`, `parseDiagnostics`, `analyseDeadCode`) tend to over-trust them - that is the trap.

## Footgun: `functionBlocks` is AST-backed only when its caller supplies the shared parse

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-08-09 | **Evidence:** OBSERVED
**Decision changed:** Thread the run-owned `ParsedScript` into every analysis-path `functionBlocks` call; never reparse locally, and treat parse-less callers as the legacy compatibility path.

`functionBlocks(source, codeSource, parsed?)` has two discovery modes. A caller that supplies the run's shared `ParsedScript` uses syntax-backed callable points, including generic and multi-line signatures. A caller that omits it falls back to the four hand-written line patterns. Over-budget scripts intentionally omit the parse, so their fallback does not gain AST-only callable coverage.

The legacy fallback does not understand generic or multi-line parameter lists, decorators and overload groups, or every object-method shape. Both modes preserve the historical `FunctionBlock.startLine` contract for leading comments and decorators; declaration-anchored rules must still use the separate declaration line.

**Evidence:** `src/blocks.ts` (search: `function matchPointsFor`) selects AST points only when `parsed` exists; `src/analyser.ts` (search: `sources.set(file.displayPath`) retains the budget-gated parse; `src/changed-regions.ts` (search: `function declarationRegions`) passes that same parse into symbol-scope discovery.

When changing a per-block rule, test the relevant callable shape. When adding an analysis-path caller, thread the existing parse through instead of calling `parseScript` again; retain the fallback only for utilities that do not own an analysis-run parse.

## Footgun: `parseDiagnostics` is syntax-only TypeScript parsing, not typechecking

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-06-10 | **Evidence:** OBSERVED

`parseDiagnostics` (`src/source-text.ts`, search: `function parseDiagnostics`) now uses `typescript.createSourceFile(...).parseDiagnostics` for script files and picks `ScriptKind` by extension. That fixes delimiter false positives in valid TSX/JSX, but the pass is syntax-only. It does not run semantic TypeScript checking, module resolution, JSX type checks, or project compiler options.

Two traps from M08:

- Over-budget files intentionally skip parse diagnostics through the scan-surface guardrail. Do not move parser calls above that budget check.
- `SourceFile.parseDiagnostics` is present at runtime but is not exposed on the public TypeScript `SourceFile` type used by this repo's TS version. A direct `sourceFile.parseDiagnostics` caused `tsc` failure. Keep the local typed bridge (`ParsedSourceFileWithDiagnostics`) or verify the installed TypeScript types before changing it.

Implication: keep a valid TSX false-positive fixture and a broken TSX counter-fixture when changing this area. Do not claim parse diagnostics are equivalent to `tsc --noEmit`; they are only parser diagnostics.

## Footgun: `analyseDeadCode` private-method check is single-file only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseDeadCode` (search: `function analyseDeadCode`) flags a `private` method as unused when its name appears `<= 1` times in the same source file. It cannot detect:

- Methods called via `this[name](...)` indirection.
- Methods referenced by string in decorator metadata or DI containers.
- Methods called from sibling files in the same package (the analyser is per-file).

The rule is intentionally `confidence: "low"` and `severity: "advisory"` for that reason. Do not promote severity without first replacing the substring scan with a cross-file symbol index.

## Footgun: `analyseUnreachable` requires the terminating statement to end in `;`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseUnreachable` (search: `function analyseUnreachable`) only marks the previous line as terminating when its trimmed form matches `/\b(return|throw|process\.exit)\b/` AND ends with `;`. ASI-style code (no trailing semicolon) silently bypasses the check. If you adjust this rule, consider that the project's own style writes most returns with `;`, so a fix that emits more findings will mostly trip the project itself.
