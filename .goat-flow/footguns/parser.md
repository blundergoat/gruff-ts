---
category: parser
last_reviewed: 2026-05-10
hallucination-risk: high
---

# Parser footguns (`src/cli.ts`)

Static-analysis surfaces that look like a real TS parser but are actually regex/character heuristics. Agents reading the code from names alone (`functionBlocks`, `parseDiagnostics`, `analyseDeadCode`) tend to over-trust them — that is the trap.

## Footgun: `functionBlocks` is regex-based, not a TS AST

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`functionBlocks` (`src/cli.ts`, search: `function functionBlocks`) walks lines and matches one of four hand-rolled patterns. It does NOT understand:

- Generics in parameter lists (`<T>(...)`) — the param regex `\(([^)]*)\)` stops at the first `)`.
- Multi-line parameter lists — only the first line of the signature is captured for `params`.
- Decorators or overload signatures — `functionStartIndex` walks back over `@`/`/**`/`*`/blank lines but not over multiple overload declarations.
- Object-method shorthand inside object literals — matches anything with `name(args):` pattern, so config-like literals can be mistaken for methods.
- The "test" classifier (`block.isTest`) trips on any function whose name `startsWith("test")`, not only Node-test/Vitest/Mocha calls.

If you change a per-block rule (size/complexity/cyclomatic/cognitive/test-quality), do not assume blocks are clean function units. Add a fixture exercising the edge case to `src/cli.test.ts` before changing thresholds.

## Footgun: `parseDiagnostics` brace counting ignores strings, comments, and regex literals

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`parseDiagnostics` (`src/cli.ts`, search: `function parseDiagnostics`) increments/decrements counters on every literal `{`, `}`, `(`, `)`, `[`, `]` — including those inside string literals, template strings, regex literals, and comments. Files that legitimately contain unbalanced delimiters in those contexts (e.g., a regex `/[}{]/`, a template containing `${...}` whose value embeds an unmatched bracket as a string) will emit a `parse-error` diagnostic that forces exit code 2 in `exitFor` regardless of `--fail-on`.

Implication: do not add new "parse-error"-class diagnostics on top of this scaffolding without first replacing the counter with a real tokenizer. Today's behaviour is "good enough for hand-written source, broken on adversarial fixtures" — that is intentional, not a bug to fix in passing.

## Footgun: `analyseDeadCode` private-method check is single-file only

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseDeadCode` (`src/cli.ts`, search: `function analyseDeadCode`) flags a `private` method as unused when its name appears `<= 1` times in the same source file. It cannot detect:

- Methods called via `this[name](...)` indirection.
- Methods referenced by string in decorator metadata or DI containers.
- Methods called from sibling files in the same package (the analyser is per-file).

The rule is intentionally `confidence: "low"` and `severity: "advisory"` for that reason. Do not promote severity without first replacing the substring scan with a cross-file symbol index.

## Footgun: `analyseUnreachable` requires the terminating statement to end in `;`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`analyseUnreachable` (`src/cli.ts`, search: `function analyseUnreachable`) only marks the previous line as terminating when its trimmed form matches `/\b(return|throw|process\.exit)\b/` AND ends with `;`. ASI-style code (no trailing semicolon) silently bypasses the check. If you adjust this rule, consider that the project's own style writes most returns with `;`, so a fix that emits more findings will mostly trip the project itself.
