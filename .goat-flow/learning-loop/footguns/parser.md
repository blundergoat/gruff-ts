---
category: parser
last_reviewed: 2026-06-10
hallucination-risk: high
---

# Parser footguns (`src/source-text.ts`)

Static-analysis surfaces that look like a real TS parser may still be regex/character heuristics, syntax-only parser passes, or single-file text scans. Agents reading the code from names alone (`functionBlocks`, `parseDiagnostics`, `analyseDeadCode`) tend to over-trust them - that is the trap.

## Footgun: `functionBlocks` is regex-based, not a TS AST

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`functionBlocks` (search: `function functionBlocks`) walks lines and matches one of four hand-rolled patterns. It does NOT understand:

- Generics in parameter lists (`<T>(...)`) - the param regex `\(([^)]*)\)` stops at the first `)`.
- Multi-line parameter lists - only the first line of the signature is captured for `params`.
- Decorators or overload signatures - `functionStartIndex` walks back over `@`/`/**`/`*`/blank lines but not over multiple overload declarations.
- Object-method shorthand inside object literals - matches anything with `name(args):` pattern, so config-like literals can be mistaken for methods.
- The "test" classifier (`block.isTest`) trips on any function whose name `startsWith("test")`, not only Node-test/Vitest/Mocha calls.
- `FunctionBlock.startLine` intentionally points at the leading comment/decorator prefix when one exists. Declaration-anchored rules need a separate declaration-line value from the raw match index.

If you change a per-block rule (size/complexity/cyclomatic/cognitive/test-quality), do not assume blocks are clean function units. Add a fixture exercising the edge case to `src/cli.test.ts` before changing thresholds.

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
