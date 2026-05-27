---
category: error-handling
last_reviewed: 2026-05-27
---

# Error-handling patterns

## Pattern: named error class + action-handler wrapper for graceful user-facing errors

**Created:** 2026-05-27

**Context:** Any CLI command that consumes user-controlled input (config files, baseline files, CLI flag values, file paths, etc.) can fail for two distinct reasons: the user provided something invalid, or there is a bug in the analyser. Treating both the same way produces hostile output - a raw Node stack trace on a `.gruff-ts.yaml` typo reads as "this tool is broken" rather than "fix line 3 of your config." The discipline is to split the two cases at the throw site, then route each one to its own renderer.

Reference implementation: `src/config-load-error.ts` (the named error class) and `src/cli-program.ts` (`runWithConfigErrorHandling` plus the wrapped action handlers for `analyse` / `summary` / `report`).

**Approach:**

1. **Define a named error class for the user-facing failure mode**, in its own file so `naming.class-file-mismatch` does not fire. Carry the suggested fix alongside the message as a readonly field so the CLI formatter can render both without re-deriving the suggestion from error text. The class extends `Error` and sets a `name` property so `error.name === "ConfigLoadError"` works as a discriminator if `instanceof` is unavailable (e.g. across realms).

   ```ts
   // src/config-load-error.ts
   export class ConfigLoadError extends Error {
     readonly suggestion: string;
     constructor(message: string, suggestion: string) {
       super(message);
       this.name = "ConfigLoadError";
       this.suggestion = suggestion;
     }
   }
   ```

2. **Throw the named class from every validator**, never plain `Error`. Each throw site supplies a context-appropriate suggestion sentence so the user knows what to do next without reading source. Hoist common suggestion strings to module-level constants (e.g. `SUGGEST_INIT_FORCE`, `SUGGEST_EDIT_CONFIG`) so a future doc-link or wording tweak lands in one place instead of N call sites. The validator does NOT format output - it only throws with structured fields.

3. **Wrap each CLI action handler** in a helper that catches the named class, formats stderr, sets `process.exitCode`, and rethrows everything else. The rethrow is the critical part: a bug in the analyser must still surface its stack trace so the maintainer can debug it. Use `instanceof` to discriminate.

   ```ts
   // src/cli-program.ts
   async function runWithConfigErrorHandling(action: () => Promise<void> | void): Promise<void> {
     try {
       await action();
     } catch (error) {
       if (error instanceof ConfigLoadError) {
         process.stderr.write(`gruff-ts: config error\n  ${error.message}\n\nSuggested fix:\n  ${error.suggestion}\n`);
         process.exitCode = 2;
         return;
       }
       throw error;
     }
   }
   ```

4. **Render the user message with deliberate formatting**, not via `console.error(err)` or `program.error(...)`. Two paragraphs - the error description, then the suggested fix - reads as documentation rather than a dump:

   ```
   gruff-ts: config error
     <message>

   Suggested fix:
     <suggestion>
   ```

   No stack trace. No file paths from inside the package. Exit code matches the documented diagnostic convention for the project (`2` in this repo, defined alongside `exitFor` in `src/scoring.ts`).

5. **Test both layers**. The error-class data wrapper gets a co-located test (`src/config-load-error.test.ts`) asserting `message`, `suggestion`, `name`, and `instanceof Error`. The thrown-from-validators contract gets coverage in the consumer test file (`src/project-config-rules.test.ts`) via `assert.throws(..., /Config must include.*schemaVersion/)` and similar regexes that match the actual class's message text.

**Why this works:**

- The triage criterion is explicit at the throw site: "Is this caused by user input?" If yes, throw the named class. If no (internal invariant, programmer mistake, unreachable state), throw a plain `Error`.
- The action wrapper centralises the user-facing formatting in one place. New CLI commands inherit graceful errors by calling the wrapper - they do not each reinvent stderr formatting.
- The rethrow on unknown error types preserves the stack-trace path for genuine bugs. Two failure modes, two renderers, one branch.
- The pattern composes: a future `BaselineLoadError`, `DiscoveryError`, or `RemoteFetchError` can use the same shape (named class + suggestion + wrapper that catches a union of types). The user-facing format stays consistent across the CLI surface.

**When NOT to use:**

- Internal invariant violations ("this branch should be unreachable", "Map should have this key by now") should stay as plain `Error` / `assert` failures. The named-class layer is for input validation, not for unreachable-code guards.
- Library code (not the CLI surface) should generally not catch its own thrown errors. The catch belongs at the CLI boundary where it owns the user-facing output.
- Do not use `program.error()` (Commander's helper) as a substitute. Commander's formatter does not separate message from suggestion and re-prints the usage help, which dilutes the actionable text. Write directly to `process.stderr` from the wrapper.

**Evidence:** `src/config-load-error.ts` (8 lines), `src/cli-program.ts:runWithConfigErrorHandling` and the three action handlers, `src/config.ts` (every validator throws `ConfigLoadError`), `src/project-config-rules.test.ts` (validator throw-type tests), `src/config-load-error.test.ts` (class data-wrapper test). User-visible behaviour: `cd /tmp/bad-config && gruff-ts summary .` produces five lines of formatted stderr and exits 2; a malformed analyser fixture still produces a stack trace because the wrapper rethrows.

**Cross-reference:** the originating incident is in `.goat-flow/lessons/workflow.md` under "user-facing CLI commands must catch known error classes and print graceful messages" (2026-05-27). The lesson captures what went wrong; this pattern is the reusable shape to apply going forward.
