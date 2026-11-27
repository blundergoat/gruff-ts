---
category: parser
last_reviewed: 2026-11-28
hallucination-risk: high
---

# Parser footguns (`src/source-text.ts`, `src/parsed-script.ts`)

Static-analysis surfaces that look like a real TS parser may still be regex/character heuristics, syntax-only parser passes, or single-file text scans. Agents reading the code from names alone (`functionBlocks`, `parseDiagnostics`, `analyseDeadCode`) tend to over-trust them - that is the trap.

## Footgun: `functionBlocks` is AST-backed only when its caller supplies the shared parse

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-08-09 | **Evidence:** OBSERVED
**Decision changed:** Thread the run-owned `ParsedScript` into every analysis-path `functionBlocks` call; never reparse locally, and treat parse-less callers as the legacy compatibility path.

`functionBlocks(source, codeSource, parsed?)` has two discovery modes. A caller that supplies the run's shared `ParsedScript` uses syntax-backed callable points, including generic and multi-line signatures. A caller that omits it falls back to the four hand-written line patterns. Over-budget scripts intentionally omit the parse, so their fallback does not gain AST-only callable coverage.

The legacy fallback does not understand generic or multi-line parameter lists, decorators and overload groups, or every object-method shape. Both modes preserve the historical `FunctionBlock.startLine` contract for leading comments and decorators; declaration-anchored rules must still use the separate declaration line.

**Evidence:** `src/blocks.ts` (search: `function matchPointsFor`) selects AST points only when `parsed` exists; `src/analyser.ts` (search: `sources.set(file.displayPath`) retains the budget-gated parse; `src/changed-regions.ts` (search: `function declarationRegions`) passes that same parse into symbol-scope discovery.

When changing a per-block rule, test the relevant callable shape. When adding an analysis-path caller, thread the existing parse through instead of calling `parseScript` again; retain the fallback only for utilities that do not own an analysis-run parse.

## Footgun: `parseDiagnostics` is syntax-only TypeScript parsing, not typechecking

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-11-23 | **Evidence:** OBSERVED

`parseDiagnostics` (`src/source-text.ts`, search: `function parseDiagnostics`) delegates to the shared `parseScript` (`src/parsed-script.ts`, search: `export function parseScript`). That function reads `typescript.createSourceFile(...).parseDiagnostics` for script files, picks `ScriptKind` by extension through `scriptKindFor`, and reports one summarized diagnostic per malformed file. That fixes delimiter false positives in valid TSX/JSX, but the pass is syntax-only. It does not run semantic TypeScript checking, module resolution, JSX type checks, or project compiler options.

Two traps from M08:

- Over-budget files intentionally skip parse diagnostics through the scan-surface guardrail. Do not move parser calls above that budget check.
- `SourceFile.parseDiagnostics` is present at runtime but is not exposed on the public TypeScript `SourceFile` type used by this repo's TS version. A direct `sourceFile.parseDiagnostics` caused `tsc` failure. Keep the typed bridge (`ParsedSourceFileWithDiagnostics` in `src/parsed-script.ts`) or verify the installed TypeScript types before changing it.

Implication: keep a valid TSX false-positive fixture and a broken TSX counter-fixture when changing this area. Do not claim parse diagnostics are equivalent to `tsc --noEmit`; they are only parser diagnostics.

## Footgun: `analyseDeadCode` private-method check is single-file only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseDeadCode` (`src/dead-code-rules.ts`, search: `function analyseDeadCode`) flags a `private` method as unused when `name(` appears `<= 1` times in the same source file and no `this.name` or `this?.name` reference exists there. It cannot detect:

- Methods called via `this[name](...)` indirection.
- Methods referenced by string in decorator metadata or DI containers.
- Methods called from sibling files in the same package (the analyser is per-file).

The rule is intentionally `confidence: "low"` and `severity: "advisory"` for that reason. Do not promote severity without first replacing the substring scan with a cross-file symbol index.

## Footgun: `analyseUnreachable` requires the terminating statement to end in `;`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseUnreachable` only marks the previous line as terminating when `isTerminatingStatement` (`src/dead-code-rules.ts`, search: `function isTerminatingStatement`) sees its trimmed form start with `return`, `throw`, or `process.exit` AND end with `;`. ASI-style code (no trailing semicolon) silently bypasses the check. If you adjust this rule, consider that the project's own style writes most returns with `;`, so a fix that emits more findings will mostly trip the project itself.

## Footgun: retaining parsed ASTs or full line arrays across all scanned files causes 4 GB OOM on large monorepos

**Status:** active | **Created:** 2026-11-25 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Compute lightweight per-file projections inside `scanDiscoveredSources` and drop `ParsedScript` and raw `source` immediately unless the file is a changed-region target or emitted an inline-suppression-relevant rule.
**Trigger phase:** ACT
**Caught at:** VERIFY

**Prevention:** Never store full `ParsedScript` ASTs, raw source strings, or split line arrays per file across a whole-repository scan. Extract only compact outputs per file inside the scan loop (`fileDeclarationSpans` for baseline ordinals, pre-extracted `importStatements` and `codeLineCount` for `ProjectSource`) and gate raw-source retention on `shouldRetainParsedForChangedScope` or `isInlineSuppressionRelevantRule`.

**Symptoms:** Unit tests and sub-1,000-file repositories pass quickly, while full scans of 10,000+ file TypeScript monorepos (`openclaw` at 17,296 files and `vscode` at 12,867 files, measured 2026-11-24) abort with V8's default 4 GB JavaScript heap limit (`EXIT 134`).

**Why it happens:** Holding every file's TypeScript `SourceFile` AST until post-loop baseline resolution, alongside per-file `lines` and `templateMaskedLines` arrays in `ProjectSource`, scales peak heap linearly with repository size rather than single-file size.

**Evidence:** `src/analyser.ts` (search: `function scanDiscoveredSources`), `src/analyser.ts` (search: `function fileDeclarationSpans`), `src/analyser.ts` (search: `function shouldRetainParsedForChangedScope`), `src/inline-suppressions.ts` (search: `export function isInlineSuppressionRelevantRule`), and `src/project-rules.ts` (search: `export function extractImportStatements`). After streaming spans and import statements, both 10,000+ file repositories completed with exit 0 under Node's default heap.

## Footgun: a `typescript` major version is not a drop-in parser upgrade

**Status:** active | **Created:** 2026-11-28 | **Evidence:** OBSERVED
**Decision changed:** Keep the parser on the `typescript` 6.x line. Treat a 7.x bump as a parser rewrite onto `typescript/unstable/*`, not a dependency update, and keep `"types": ["node"]` in `tsconfig.json`.

`npm outdated` lists `typescript@7.0.2` as the latest version because it carries the `latest` tag, but its main entry exports only `./lib/version.cjs`; the compiler API sits under `./unstable/*`, and the package depends on per-platform native binaries. Seven analysis modules load the 5.x/6.x API with `require("typescript")`, and `src/parsed-script.ts` and `src/security-flow-rules.ts` parse with `createSourceFile`, so installing 7.x breaks parsing instead of upgrading it.

TypeScript 6.0 also changed the `types` default to `[]`. Without `"types": ["node"]`, `tsc --noEmit` stops loading `@types/node` and every `node:` import fails with TS2591.

**Evidence:** `npm view typescript@7.0.2 exports dependencies` lists `./lib/version.cjs`, the `./unstable/*` entries, and `@typescript/typescript-<platform>` packages; `src/parsed-script.ts` (search: `require("typescript")`); `tsconfig.json` (search: `"types": ["node"]`). Moving from 5.9.3 to 6.0.3 produced identical findings and diagnostics on gruff-ts, zod, nest, sequelize, juice-shop, express, and angular (88,738 findings, 518 diagnostics).

**Prevention:** Before bumping `typescript`, confirm the target version still exports the compiler API at its main entry, then diff a corpus scan before and after. Identical finding and diagnostic tuples are the bar; a passing test suite alone is not.
