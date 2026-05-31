---
category: rule-scanners
last_reviewed: 2026-06-01
---

# Rule scanner footguns

## Footgun: context-doc rules read ONLY the last `//` line above a declaration

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED (named-profiles self-scan)

The context-doc rules - `docs.missing-error-behavior-doc`, `docs.missing-why-for-complex-code`, `docs.missing-side-effect-doc`, `docs.missing-invariant-doc` (`src/context-doc-rules.ts`, search: `function functionContextDocFindings`) - test their marker vocabulary (`hasErrorBehaviorMarker`, search: `function hasErrorBehaviorMarker`; `hasComplexWhyMarker`, etc.) against `comment.text` from `leadingCommentForLine` (`src/comment-rules.ts`, search: `function leadingCommentForLine`). `commentRecords` (`src/comment-scanner.ts`, search: `emits one CommentRecord per`) emits ONE record per `//` line and does NOT merge a run of consecutive `//` lines, so `leadingCommentForLine` returns only the SINGLE comment line directly above the declaration. A `/* ... */` block, by contrast, is one record whose whole body is checked.

Consequence: for a function documented with stacked `//` lines, the marker word (`throws`/`reports`/`exits` for error-behavior; `because`/`why`/`avoid`/`preserve` for complex-why) MUST appear on the FINAL `//` line, the one immediately above the signature. Putting "Throws ConfigLoadError" on line 2 of a 3-line `//` comment does NOT clear `docs.missing-error-behavior-doc` - the rule never sees line 2. During the profiles work, four `//`-commented throwing helpers and one complex renderer kept firing until each marker was moved to the last line (or the comment was made a single line ending in the marker). When clearing a context-doc finding on a `//`-commented declaration, put the marker on the last line or convert the comment to a `/* */` block.

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

## Footgun: widening commented-out-code calls needs a prose-shape guard

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED (review feedback + focused tests)

`isCommentedOutCode` (`src/findings-helpers.ts`, search: `function isDisabledCall`) used to require a semicolon for disabled calls, so `// cleanup()` and `// service.reset()` were false negatives in semicolonless projects. Dropping the semicolon requirement fixed that, but immediately made prose headings like `// scanSectionAgainstSnapshot (claim patterns)` look like disabled calls. The existing uppercase-heading guard did not cover lower-camel helper names used as section labels.

When widening a disabled-code detector from "strict syntax" to "common style", add a paired prose/heading regression in the same patch. For call-shaped comments, the guard must distinguish `identifier()` / `object.method()` from label text with a space before the parenthetical, while preserving real control-flow comments such as `// if (ready)`. Tests: `src/findings-helpers.test.ts`, search: `service.reset()` and `scanSectionAgainstSnapshot`.

## Footgun: context-doc rules only see the LAST `//` line as the leading comment

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`leadingCommentForLine` (`src/comment-rules.ts`, search: `function leadingCommentForLine`) reverse-walks `comments[]` and returns the FIRST CommentRecord whose `endLine < declarationLine`. The comment lexer (`src/comment-scanner.ts`, search: `function lineCommentRecord`) emits ONE CommentRecord per `//` line. So a five-line `// ... // ... // ... // ... // ...` block above a function produces five separate records, and the rule only inspects the one immediately before the declaration.

That breaks `docs.missing-invariant-doc` and `docs.missing-why-for-complex-code` (`src/context-doc-rules.ts`, search: `hasInvariantMarker`, `hasComplexWhyMarker`): if the marker word (`invariant`, `contract`, `must`, `stable`, `deterministic`, `schema`, `fingerprint`, or `because`, `why`, `intentional`, `tradeoff`, `compat`, `avoid`, `preserve`) sits on any line OTHER than the last `//`, the rule fires anyway and the author has no obvious clue why.

When documenting a complex function or contract-bearing declaration, either (a) put the marker word on the LAST `//` line above the declaration, or (b) use a `/* ... */` block comment - block comments produce ONE CommentRecord whose `text` is the joined body (search: `function normalizedBlockCommentText`). Block form is preferred for any multi-sentence comment that explains a contract.

## Footgun: header-shape exemptions that key off the regex match prefix leak to sibling loop forms

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED (PR #4 review, codex P2)

`VARIABLE_DECLARATIONS` (`src/line-rules.ts`, search: `const VARIABLE_DECLARATIONS`) captures the binding name out of `const`, `let`, `for ( const`, and `for ( let` headers in one regex. The M02 §2.8(b) for-of exemption originally gated on `matchText.startsWith("for")` to decide whether to compute the body span. Problem: that prefix is also present for classic `for (let i = 0; ...)` and `for (const k in obj)`. A one-char binding inside a short C-style or for-in body got silently exempted from `naming.short-variable`, against the documented scope.

The fix (`pushVariableNameFindings`, search: `function pushVariableNameFindings`) verifies an `of` token follows the binding by slicing the codeLine from the end of the matched substring and matching `/^\s+of\b/`. The regex itself stays broad because the same VARIABLE_DECLARATIONS pattern feeds other rules; the exemption gate gets tightened where it matters.

When adding an exemption that targets a specific control-flow header shape, do not key off the matched substring's prefix - that's just the part of the header the binding regex captured. Inspect the broader header (the slice of `codeLine` after the match) for the actual discriminator token (`of`, `in`, `;`, `=`). Tests: `naming-rules.test.ts`, search: `naming short-variable still flags C-style for binding`.

## Footgun: line-local `^export` detection misses re-exported declarations

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED (PR #4 review, codex P2)

`functionBlockFromMatch` (`src/blocks.ts`, search: `function functionBlockFromMatch`) originally set `isExported: /^\s*export\b/.test(scan.codeLines[index])` - a line-local check on the declaration line only. Common module pattern is to declare locally and re-export at the bottom: `function foo() {}` followed by `export { foo };` (search: `^export \{` across `src/`). That declaration's `isExported` came back false, so `docs.missing-exported-function-doc` (warning) silently downgraded to `docs.missing-internal-function-doc` (advisory) - undercutting the public-API doc gate for a pervasive shape.

The fix runs `collectReExportedNames` (`src/blocks.ts`, search: `function collectReExportedNames`) once per file, scanning the masked codeSource for `export { ... }` (multi-name, alias-aware) and `export default <Ident>`. `isExported` ORs the line-local check with the file-level set, so a function declared inline gets the export classification when its name is re-exported anywhere in the file.

Two implications: (1) when adding a per-symbol classification rule that depends on "is this exported," do the file-level re-export scan once and thread the result; do not rely on per-line patterns alone. (2) `isPublic` (which considers `public` keyword too) was unaffected, but the moral is identical for any future "this declaration is part of the public surface" gate. Tests: `false-positive-fixes.test.ts`, search: `FP-#33b docs.missing-exported-function-doc fires on re-exported function`.

## Footgun: `naming.acronym-case` is file-wide, not per-symbol

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`naming.acronym-case` (`src/class-rules.ts`, search: `ruleId: "naming.acronym-case"`) fires when the same known acronym appears in more than one casing anywhere in a single source file. Identifier casings like `Html` (titled), `HTML` (all-caps), and `html` (all-lower) are all counted independently; a single file that uses `parseHtmlPillarRows` AND a constant named `HTML_PILLAR_HEADERS` will get a finding even though both names are internally consistent on their own.

When extracting helpers in a file that already uses the titled form (`Html`, `Css`, `Sql`, `Url`, etc.), match the existing casing for new identifiers - including SCREAMING_SNAKE_CASE constants. Either rename the constant to `pillarHeaderColumns` (camelCase, no acronym) or accept that the codebase convention is title-cased acronyms even in constants. The rule has no per-symbol override; only file-wide consistency clears it.

## Footgun: `CORRELATED_COMPLEXITY_RULE_IDS` is defined twice and must be edited in lockstep

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED (design.god-function removal, ADR-011)

The complexity-cluster rule-id set lives in TWO files with identical literals: `src/scoring.ts` (search: `const CORRELATED_COMPLEXITY_RULE_IDS`) drives penalty clustering, and `src/report-renderers.ts` (search: `const CORRELATED_COMPLEXITY_RULE_IDS`) drives the "Correlated complexity clusters" text/markdown output. Neither imports the other and no test asserts they match, so editing only one leaves scoring and reporting silently disagreeing about which findings cluster.

When you add or remove a rule from the complexity cluster (e.g. retiring `design.god-function` per ADR-011, or the inverse), change BOTH literals in the same pass, then grep `CORRELATED_COMPLEXITY_RULE_IDS` to confirm exactly two hits with the same contents. The P5 cluster contract (ADR-009) depends on the two staying in sync.

## Footgun: a removed rule id left in a comment trips `docs.stale-comment` unless the SAME line carries a historical marker

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED (design.god-function removal self-scan)

After removing a rule from the catalogue, any committed comment that still names the dotted id (`pillar.name`) becomes an "unknown rule id" to `pushStaleRuleReferenceFindings` (`src/comment-rules.ts`, search: `function pushStaleRuleReferenceFindings`), which checks each id against `DESCRIPTOR_IDS`. The escape hatch is `hasHistoricalContext` (`src/comment-rules.ts`, search: `function hasHistoricalContext`): it matches `previously|legacy|compat|migration|ADR` and is checked PER comment line, because the scanner emits one record per `//` line. So the historical marker MUST sit on the SAME `//` line as the removed id - "retired"/"removed" are NOT in the vocabulary, and an `ADR-NNN` reference on the next line does not count.

When a comment explains a retired rule (e.g. an ADR cross-reference about `design.god-function`), keep the id and an `ADR-NNN` (or `legacy`/`migration`) token on one line: `// ... the retired design.god-function (ADR-011) composite ...`. This compounds with the context-doc footgun above (the invariant/why marker must be on the LAST `//` line above the declaration), so one explanatory comment near a contract-owning declaration must satisfy both per-line constraints at once.

## Footgun: a milestone may name "new" dependency rules that already exist under different ids

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED (M25 supply-chain slice, 0.3.0)

The M25 task list named three "new" hardened-dependency rule ids to add - `security.dependency-install-script`, `security.dependency-git-url-reference`, `security.dependency-unpinned-version` - but `src/project-config-rules.ts` already ships the same coverage under older ids: `security.risky-lifecycle-script` (preinstall/install/postinstall/prepare/prepublish hooks), `security.remote-install-script` (`curl|wget … | sh`), `security.url-dependency` (https/git/ssh/github-shorthand specs), and `waste.broad-runtime-version` (`*`/`x`/`latest`/unbounded `>=`/`||`). The capability matrix even rated this row `dependency ◑(3)` - the `(3)` was those existing checks - so "◑ → ✅" meant HARDEN the existing rules, not add parallel ids. Adding the named ids would have produced two findings for one root cause: the exact P5/ADR-011 anti-pattern (a composite restating findings already on the symbol).

Before implementing any rule a plan calls "new", `grep -oE '"<pillar>\\.[a-z-]+"' src/rules.ts | sort -u` and read the owning module - a milestone written before the cli.ts split (or before a sibling milestone landed) can predate coverage that now exists. If the gap is real it is usually narrow (here: only `file:` protocol deps escape `isUrlDependency`, and that is low-signal at advisory), so prefer extending the existing rule's predicate over minting a duplicate id.

## Footgun: caching a parsed AST by `SourceFile` identity goes stale when the object is reused

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED (M25 AST-flow slice, security-flow tests)

The syntax-only parser adapter `getSourceFile` (`src/security-flow-rules.ts`, search: `function getSourceFile`) was first written to memoise `ts.createSourceFile` output in a `WeakMap` keyed by the discovery `SourceFile` object. That is safe in a real run - each discovered file has its own `SourceFile` instance and is parsed once - but the tests (`src/security-flow-rules.test.ts`) reuse a single `fileStub` across cases with DIFFERENT source strings. The object-keyed cache returned the FIRST case's AST for every later case, so each test produced a byte-identical finding regardless of input: the SSRF positive misfired as `security.path-traversal-candidate`, and every "expect zero" negative fired. `tsc` was clean; the failure surfaced only in `npm test`.

Three takeaways: (1) `analyseSecurityFlow` is the only caller and runs once per file, so the cache bought nothing - it was an unrequested abstraction that only introduced a bug (CLAUDE.md: "No new abstractions ... beyond what was asked"). The fix was to delete the cache and parse per call. (2) If a per-run AST cache is ever actually needed, key it on the source text (or a content hash), never on the file-descriptor object, because tests and any future reuse of a `SourceFile` across sources will alias. (3) When rule output is byte-identical across genuinely different inputs, suspect shared or aliased state - a cache, a module-level mutable, or a global regex's `lastIndex` - before the rule logic.

## Footgun: AST sink argument walkers descend into non-sink callback bodies

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED (review feedback + security-flow tests)

`taintedInput` (`src/security-flow-rules.ts`, search: `function taintedInput`) originally walked every node under every sink argument. That is too broad for callback-style APIs: `fs.readFile("./safe.json", () => log(target))` mentions a tainted local inside the callback, but the tainted value is not the filesystem path argument. The same text-walk mistake also applies to literal text such as `"req.query.path"`; raw `getText()` matching turns documentation-shaped strings into fake sources.

For syntax-only source-to-sink rules, inspect only sink-relevant expression trees. Prune nested function-like nodes while walking arguments, and treat string/no-substitution-template literals as literal text, not source evidence. Add a negative test any time a scanner starts using `node.getText()` over a subtree: one callback-only taint reference and one literal that names the source token. Tests: `src/security-flow-rules.test.ts`, search: `callback-only taint` and `string literals that only mention source tokens`.
