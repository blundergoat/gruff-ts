---
category: rule-scanners
last_reviewed: 2026-05-26
---

# Rule scanner footguns

## Footgun: per-line walkers miss multi-line conditional context

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED (goat-flow scan, dashboard.ts:286)

`analyseUnreachable` (`src/dead-code-rules.ts`, search: `function analyseUnreachable`) walks lines one at a time and originally tracked "previous line was a braceless conditional opener" as a single boolean. That works for `if (x)\n  return;\nnext` (single-line predicate), but for the multi-line variant - `if (\n  a &&\n  b\n)\n  return;\nnext` - the boolean only set true on line 1 and was already false by the time the walker reached `return;`, so the next line got falsely flagged as unreachable.

The fix at `src/dead-code-rules.ts:37` tracks open-paren depth across lines plus a `isConsequentPending` flag for the one-line consequent that follows the closing `)`. Both states must be active for `isInConditionalBranch` to be true.

When writing or extending a per-line walker that depends on the prior line being part of a control-flow construct, account for the construct spanning multiple lines. Single-line opener-detection booleans WILL miss multi-line predicates. Use paren-depth or brace-depth tracking, scoped to the construct, and remember the masked `codeSource` already blanks parens inside string literals so the count is reliable.

## Footgun: widening any rule's suppression criteria breaks coverage fixtures

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED (M01 §2.2, M03 §2.6)

Every rule's suppression heuristic - whether a rationale-comment regex (M01), a fixture-loop iterable+body check (M03), or any other "this case isn't really a defect" gate - has at least two failure modes when widened:

1. **Coverage fixtures**: `src/test-fixtures.ts:ruleCatalogueCoverageRuleIds` (and similar broad-coverage scans) prove rule descriptors are emitted by running a synthetic project. If the synthetic fixture USED the rule's now-suppressed case as proof of coverage, the descriptor drops from the emitted set and `rule descriptors cover emitted rules` fails. Example: the cumulative fixture's `for (const setupEntry of [one, two, three]) { sleep(...); assert.ok(...); }` was a literal-array fixture loop after M03 widened `test-quality.loop-in-test`. Fix: add a confounder inside the body (`if (setupEntry) { ... }`) so the suppression heuristic exits.

2. **Placeholder fixtures**: per-rule fixtures (in `false-positive-fixes.test.ts`, `cumulative-fixture.test.ts`, etc.) use specific tokens or shapes as "this fixture deliberately fires the rule." Widening makes those tokens no longer fire. Example: M01 widened `hasIntentionalCatchRationale` to accept `ignore|ignored|cleanup|teardown|noop|no-op`; FOUR fixtures using `// ignored` as a placeholder swallow had to migrate to `// FIXME`:
   - `src/baseline-and-project.test.ts:140`
   - `src/test-fixtures.ts:461` (shared fixture; cascades to multiple tests)
   - `src/cumulative-fixture.test.ts:331`
   - `src/security-and-config.test.ts:59`

The failure mode is silent at type-check time and only surfaces in `npm test`. Before widening any rule's suppression criteria:

1. Grep for every fixture using the newly-suppressed shape as proof the rule fires.
2. For per-rule placeholder fixtures: migrate to a still-non-suppressed shape (different token, different iterable, different body branch).
3. For coverage fixtures (`ruleCatalogueCoverageRuleIds`): add a deliberate confounder so the rule keeps firing as catalogue proof.
4. Don't trust the type system to catch this - the affected tests assert finding existence, not types.

## Footgun: rule-descriptor prose triggers the rule it describes

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED (M01 close-out self-scan)

When M01 added a comment explaining the catch-rationale widening, the comment mentioned `TODO`/`FIXME`/`XXX` to explain which markers were excluded - and `docs.todo-without-tracking` immediately fired on the descriptor itself. Two findings appeared: one in `src/safety-rules.ts` (the function comment) and one in `src/false-positive-fixes.test.ts` (the test's purpose comment).

Several gruff rules scan source-wide and don't distinguish "comment explaining what the rule does" from "actual TODO marker." Affected rules include `docs.todo-without-tracking`, `waste.commented-out-code` (matches code-shaped strings in comments), and `docs.stale-comment` (matches `--unknown-flag` mentions).

When writing rule-descriptor prose or test-naming prose that has to mention a trigger token, either:
- Rephrase to avoid the literal token ("deferred-work markers" rather than "FIXME/XXX").
- Use a tracking suffix that satisfies the rule (e.g. `// TODO #123` for `docs.todo-without-tracking`).

Skipping the rule for descriptor files is NOT an option - the file-level granularity isn't there, and the broader principle is "every finding stays visible."


## Footgun: `process-exec` matches `RegExp.exec` source text

**Status:** active | **Created:** 2026-05-17 | **Evidence:** OBSERVED

`processExecCandidate` (`src/cli.ts`, search: `function processExecCandidate`) matches bare `exec(`, `spawn(`, or `execFile(` in masked code. That intentionally catches child-process helpers, but it also catches ordinary `RegExp.exec(...)` calls because the current regex does not require a child-process receiver or import context.

When adding hot-path regex loops, avoid writing `.exec(` in scanner source unless you also refine the rule. This performance pass used bracket dispatch (`src/text-scans.ts`, search: `globalPattern["exec"]`) to keep the source self-scan from adding `security.process-exec` noise.

## Footgun: context-doc rules only see the LAST `//` line as the leading comment

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`leadingCommentForLine` (`src/comment-rules.ts`, search: `function leadingCommentForLine`) reverse-walks `comments[]` and returns the FIRST CommentRecord whose `endLine < declarationLine`. The comment lexer (`src/comment-scanner.ts`, search: `function lineCommentRecord`) emits ONE CommentRecord per `//` line. So a five-line `// ... // ... // ... // ... // ...` block above a function produces five separate records, and the rule only inspects the one immediately before the declaration.

That breaks `docs.missing-invariant-doc` and `docs.missing-why-for-complex-code` (`src/context-doc-rules.ts`, search: `hasInvariantMarker`, `hasComplexWhyMarker`): if the marker word (`invariant`, `contract`, `must`, `stable`, `deterministic`, `schema`, `fingerprint`, or `because`, `why`, `intentional`, `tradeoff`, `compat`, `avoid`, `preserve`) sits on any line OTHER than the last `//`, the rule fires anyway and the author has no obvious clue why.

When documenting a complex function or contract-bearing declaration, either (a) put the marker word on the LAST `//` line above the declaration, or (b) use a `/* ... */` block comment - block comments produce ONE CommentRecord whose `text` is the joined body (search: `function normalizedBlockCommentText`). Block form is preferred for any multi-sentence comment that explains a contract.

## Footgun: `naming.acronym-case` is file-wide, not per-symbol

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`naming.acronym-case` (`src/class-rules.ts`, search: `ruleId: "naming.acronym-case"`) fires when the same known acronym appears in more than one casing anywhere in a single source file. Identifier casings like `Html` (titled), `HTML` (all-caps), and `html` (all-lower) are all counted independently; a single file that uses `parseHtmlPillarRows` AND a constant named `HTML_PILLAR_HEADERS` will get a finding even though both names are internally consistent on their own.

When extracting helpers in a file that already uses the titled form (`Html`, `Css`, `Sql`, `Url`, etc.), match the existing casing for new identifiers - including SCREAMING_SNAKE_CASE constants. Either rename the constant to `pillarHeaderColumns` (camelCase, no acronym) or accept that the codebase convention is title-cased acronyms even in constants. The rule has no per-symbol override; only file-wide consistency clears it.
