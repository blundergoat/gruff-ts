---
category: rule-scanners
last_reviewed: 2026-08-12
---

# Rule scanner footguns

## Footgun: nested template interpolation can mask the rest of a scanned file

**Status:** active | **Created:** 2026-07-12 | **Evidence:** OBSERVED
**Evidence context:** Markdown renderer self-scan.

`maskNonCode` (`src/source-text.ts`, search: `function maskNonCode`) tracks template interpolation with one numeric `templateInterpolationDepth`. An inner template literal opened inside an outer `${...}` expression can enter its own `${...}` expression, but closing the inner expression only decrements that shared depth; it does not restore the inner template's quote state. The inner closing backtick can then be treated as a new opener, masking valid code later in the file.

The user-visible symptom is a cascade far from the new line: a valid nested interpolation in `src/report-renderers.ts` made the self-scan claim that later parameters were unused and several later functions were empty even though TypeScript and all 395 tests passed. Precomputing the inner path-symbol label before interpolating it into the outer row reduced the scan from 12 findings to the one independent comment-contract finding.

Until `maskNonCode` gains a template quote stack, avoid a template literal directly inside another template's interpolation in gruff-scanned source. Name the inner user-facing value first, interpolate that variable into the outer string, and run the full self-scan because `tsc` cannot expose this text-mask failure.

## Footgun: line-rule emitters hardcode severity, so config `severity:` overrides are silently dropped

**Status:** active | **Created:** 2026-06-03 | **Evidence:** ACTUAL_MEASURED
**Evidence context:** security.new-function CONFIGURE gap.

There is no central pass that re-applies config severity to findings - each rule must consult config itself via `ruleSeverity(config, ruleId, default)` (`src/config.ts`, search: `function ruleSeverity`). So any emitter that passes a literal `severity:` makes a project's `rules.<id>.severity` override in `.gruff-ts.yaml` a silent no-op (no error, no warning). The pillar rules wired correctly are the model (`src/analyser.ts`, search: `"size.file-length"`; `src/blocks.ts`, search: `"size.function-length"`).

`pushPatternCheckFindings` (`src/line-rules.ts`, search: `function pushPatternCheckFindings`) was fixed to route severity through `ruleSeverity`, so the `security.*`/`modernisation.*`/`waste.*` regex checks (e.g. `security.new-function`) now honor overrides - this is what lets a project running a legitimate `new Function`/eval shape set `severity: warning` instead of failing an `--fail-on error` gate, rather than the analyzer deciding that for every consumer. But sibling emitters in the same module still hardcode (`src/line-rules.ts`, search: `function pushCommentedOutCodeFinding`; search: `function pushLooseEqualityFinding`), as do the naming/type-safety/reliability passes. When adding or debugging a line rule, route severity through `ruleSeverity` or a `rules.<id>.severity` override is ignored. Regression proof: `src/security-and-config.test.ts` (search: `security line-rule severity honours config overrides`).

## Footgun: `typeof x === "function"` is often runtime behavior, not code shape

**Status:** active | **Created:** 2026-06-03 | **Evidence:** OBSERVED
**Evidence context:** static-analysis-redundant-test QA.

`test-quality.static-analysis-redundant-test` (`src/static-analysis-redundant-rules.ts`, search: `function typeofFunctionAssertions`) must not treat every `typeof <identifier-or-member> === "function"` assertion as a static-analysis-redundant candidate. The same syntax is a legitimate runtime contract when the operand comes from a factory, plugin loader, parsed module, dependency injection container, callback registry, or any other call result:

```ts
const handler = createMiddleware(options);
assert.equal(typeof handler, "function");

const plugin = loadPlugin("formatter");
assert.equal(typeof plugin.activate, "function");
```

Directly referencing `handler` or `plugin.activate` does not prove a statically named function exists; TypeScript can only validate the variable/member's declared type if the scanner has actual static evidence for that operand. A message claiming "TypeScript type checking or module loading can validate" unresolved locals is factually false and pushes reviewers to delete useful behavior tests.

When implementing or extending this rule, require static evidence before emitting a high-confidence `typeof ... "function"` finding: a visible function declaration, function-valued const, named import, namespace import member, or another source-backed fact with a source proof. Suppress or downgrade unresolved locals and members bound from calls. Add paired fixtures: one shape-only hit and one runtime-callable non-hit using the same assertion syntax (`src/test-block-rules.test.ts`, search: `keeps runtime callable typeof assertions quiet`).

## Footgun: per-line walkers miss multi-line conditional context

**Status:** active | **Created:** 2026-05-26 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** When a rule needs a structural property of a declaration, read it from the shared parse instead of inspecting lines; a line walker only sees the shape the first line happens to show.
**Trigger phase:** ACT
**Incident count:** 2
**Latest occurrence:** 2026-08-08

`analyseUnreachable` (`src/dead-code-rules.ts`, search: `function analyseUnreachable`) walks lines one at a time and originally tracked "previous line was a braceless conditional opener" as a single boolean. That works for `if (x)\n  return;\nnext` (single-line predicate), but for the multi-line variant - `if (\n  a &&\n  b\n)\n  return;\nnext` - the boolean only set true on line 1 and was already false by the time the walker reached `return;`, so the next line got falsely flagged as unreachable.

The fix in `src/dead-code-rules.ts` (search: `isConsequentPending`) tracks open-paren depth across lines plus a `isConsequentPending` flag for the one-line consequent that follows the closing `)`. Both states must be active for `isInConditionalBranch` to be true.

Second occurrence, 2026-08-08: `isBodyLessDeclaration` (`src/blocks.ts`, search: `function isBodyLessDeclaration`) decided whether a callable had an implementation by testing the first non-comment line for `)...;`. A single-line interface method matched, but a multi-line one starts at `findMany(`, so the walker called it an implementation and `waste.empty-function` plus `waste.unused-parameter` fired on a signature that cannot have a body. Reported on PR #9 and reproduced with a two-parameter interface method.

That fix threads AST truth instead of improving the heuristic: `CallableMatchPoint` (`src/parsed-script.ts`, search: `function callableNodeHasBody`) carries `hasBody`, and the text walk survives only as the legacy regex-block fallback. When the shared parse already knows a property, a better line heuristic is the wrong repair - it will fail again on the next multi-line shape.

When writing or extending a per-line walker that depends on the prior line being part of a control-flow construct, account for the construct spanning multiple lines. Single-line opener-detection booleans WILL miss multi-line predicates. Use paren-depth or brace-depth tracking, scoped to the construct; the masked `codeSource` already blanks parens inside string literals, so its count is reliable.

## Footgun: widening any rule's suppression criteria breaks coverage fixtures

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED
**Evidence context:** M01 §2.2 and M03 §2.6; recurred 2026-08-04 when `naming.acronym-case` stopped counting SCREAMING constants and the catalogue coverage fixture's `DATABASE_URL`/`databaseUrl` proof pair went quiet, then cleared after switching to `rawURL`/`databaseUrl`.

Every rule's suppression heuristic - whether a rationale-comment regex (M01), a fixture-loop iterable+body check (M03), or any other "this case isn't really a defect" gate - has at least two failure modes when widened:

1. **Coverage fixtures**: `src/test-fixtures.ts:ruleCatalogueCoverageRuleIds` (and similar broad-coverage scans) prove rule descriptors are emitted by running a synthetic project. If the synthetic fixture USED the rule's now-suppressed case as proof of coverage, the descriptor drops from the emitted set and `rule descriptors cover emitted rules` fails. Example: the cumulative fixture's `for (const setupEntry of [one, two, three]) { sleep(...); assert.ok(...); }` was a literal-array fixture loop after M03 widened `test-quality.loop-in-test`. Fix: add a confounder inside the body (`if (setupEntry) { ... }`) so the suppression heuristic exits.

2. **Placeholder fixtures**: per-rule fixtures (in `false-positive-fixes.test.ts`, `cumulative-fixture.test.ts`, etc.) use specific tokens or shapes as "this fixture deliberately fires the rule." Widening makes those tokens no longer fire. Example: M01 widened `hasIntentionalCatchRationale` to accept `ignore|ignored|cleanup|teardown|noop|no-op`; FOUR fixtures using `// ignored` as a placeholder swallow had to migrate to `// FIXME`:
   - `src/baseline-and-project.test.ts` (search: `// FIXME`)
   - `src/test-fixtures.ts` (search: `// FIXME`) (shared fixture; cascades to multiple tests)
   - `src/cumulative-fixture.test.ts` (search: `// FIXME`)
   - `src/security-and-config.test.ts` (search: `// FIXME`)

The failure mode is silent at type-check time and only surfaces in `npm test`. Before widening any rule's suppression criteria:

The same trap appeared when `naming.class-file-mismatch` changed from every mismatched exported class to a sole-public-declaration policy. The broad catalogue, core-expansion, and cumulative fixtures still declared mismatched classes, but their other public declarations correctly suppressed the finding, so three coverage assertions lost the rule. Each project gained a dedicated `helpers.ts` fixture with one documented `PaymentController` export instead of weakening the new policy.

1. Grep for every fixture using the newly-suppressed shape as proof the rule fires.
2. For per-rule placeholder fixtures: migrate to a still-non-suppressed shape (different token, different iterable, different body branch).
3. For coverage fixtures (`ruleCatalogueCoverageRuleIds`): add a deliberate confounder so the rule keeps firing as catalogue proof.
4. Don't trust the type system to catch this - the affected tests assert finding existence, not types.

## Footgun: rule descriptor threshold tests need literal rule ids

**Status:** active | **Created:** 2026-06-10 | **Evidence:** OBSERVED
**Evidence context:** 0.4.0 M01 execution gating.

`src/rule-catalogue.test.ts` extracts implementation defaults with regexes over source text:
`threshold(config, "rule.id", default)` and `optionNumber(config, "rule.id", "key", default)`.
The extractor deliberately proves descriptor/default drift from readable call sites; it does not
resolve constants. Replacing threshold or option call-site rule ids with constants makes
`rule descriptor thresholds and options match implementation and config defaults` fail even when
runtime behavior is unchanged.

Use constants for gates, findings, and repeated non-contract strings if helpful, but keep the
rule-id string literal at threshold/option call sites that descriptor tests audit. If a threshold
call must be abstracted, update the extractor/test in the same change instead of assuming the
catalogue test can infer aliases.

## Footgun: rule-descriptor prose triggers the rule it describes

**Status:** active | **Created:** 2026-05-26 | **Evidence:** OBSERVED
**Resolution note:** Partially resolved 2026-08-04; the underlying self-referential prose risk remains active.
**Evidence context:** M01 close-out self-scan.

When M01 added a comment explaining the catch-rationale widening, the comment mentioned `TODO`/`FIXME`/`XXX` to explain which markers were excluded - and `docs.todo-without-tracking` immediately fired on the descriptor itself. Two findings appeared: one in `src/safety-rules.ts` (the function comment) and one in `src/false-positive-fixes.test.ts` (the test's purpose comment).

Several gruff rules scan source-wide and don't distinguish "comment explaining what the rule does" from "actual TODO marker." Affected rules include `docs.todo-without-tracking`, `waste.commented-out-code` (matches code-shaped strings in comments), and `docs.stale-comment` (matches `--unknown-flag` mentions).

Resolved for `docs.todo-without-tracking` on 2026-08-04: the marker must now introduce a comment body line with a marker delimiter (`src/comment-rules.ts`, search: `function leadingTodoMarker`), so mid-sentence, quoted, backticked, and fenced-example mentions stay quiet. `waste.commented-out-code` and `docs.stale-comment` still behave as described above.

Same shape for suppression directives in test fixtures: `docs.suppression-without-rationale` scans comments in the test source, so a test comment or template-literal fixture that contains a raw lint-disable directive can flag the test file instead of only exercising the generated fixture. During M07, `src/scan-surface.test.ts` (search: `const eslintDisable`) had to assemble the directive from split strings and rephrase the surrounding comment to avoid a self-scan finding while still writing a bare directive into the generated source under test.

When writing rule-descriptor prose or test-naming prose that has to mention a trigger token, either:
- Rephrase to avoid the literal token ("deferred-work markers" rather than "FIXME/XXX").
- Use a tracking suffix that satisfies the rule (e.g. `// TODO #123` for `docs.todo-without-tracking`).

Skipping the rule for descriptor files is NOT an option - the file-level granularity isn't there, and the broader principle is "every finding stays visible."


## Footgun: widening commented-out-code calls needs a prose-shape guard

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED
**Evidence context:** review feedback plus focused tests.

`isCommentedOutCode` (`src/findings-helpers.ts`, search: `function isDisabledCall`) used to require a semicolon for disabled calls, so `// cleanup()` and `// service.reset()` were false negatives in semicolonless projects. Dropping the semicolon requirement fixed that, but immediately made prose headings like `// scanSectionAgainstSnapshot (claim patterns)` look like disabled calls. The existing uppercase-heading guard did not cover lower-camel helper names used as section labels.

When widening a disabled-code detector from "strict syntax" to "common style", add a paired prose/heading regression in the same patch. For call-shaped comments, the guard must distinguish `identifier()` / `object.method()` from label text with a space before the parenthetical, while preserving real control-flow comments such as `// if (ready)`. Tests: `src/findings-helpers.test.ts`, search: `service.reset()` and `scanSectionAgainstSnapshot`.

## Footgun: context-doc rules only see the LAST `//` line as the leading comment

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED

`leadingCommentForLine` (`src/comment-rules.ts`, search: `function leadingCommentForLine`) reverse-walks `comments[]` and returns the FIRST CommentRecord whose `endLine < declarationLine`. The comment lexer (`src/comment-scanner.ts`, search: `function lineCommentRecord`) emits ONE CommentRecord per `//` line. So a five-line `// ... // ... // ... // ... // ...` block above a function produces five separate records, and the rule only inspects the one immediately before the declaration.

That breaks `docs.missing-invariant-doc` and `docs.missing-why-for-complex-code` (`src/context-doc-rules.ts`, search: `hasInvariantMarker`, `hasComplexWhyMarker`): if the marker word (`invariant`, `contract`, `must`, `stable`, `deterministic`, `schema`, `fingerprint`, or `because`, `why`, `intentional`, `tradeoff`, `compat`, `avoid`, `preserve`) sits on any line OTHER than the last `//`, the rule fires anyway and the author has no obvious clue why.

When documenting a complex function or contract-bearing declaration, either (a) put the marker word on the LAST `//` line above the declaration, or (b) use a `/* ... */` block comment - block comments produce ONE CommentRecord whose `text` is the joined body (search: `function normalizedBlockCommentText`). Block form is preferred for any multi-sentence comment that explains a contract.

## Footgun: header-shape exemptions that key off the regex match prefix leak to sibling loop forms

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED
**Evidence context:** PR #4 review, Codex P2.

`VARIABLE_DECLARATIONS` (`src/line-rules.ts`, search: `const VARIABLE_DECLARATIONS`) captures the binding name out of `const`, `let`, `for ( const`, and `for ( let` headers in one regex. The M02 §2.8(b) for-of exemption originally gated on `matchText.startsWith("for")` to decide whether to compute the body span. Problem: that prefix is also present for classic `for (let i = 0; ...)` and `for (const k in obj)`. A one-char binding inside a short C-style or for-in body got silently exempted from `naming.short-variable`, against the documented scope.

The fix (`pushVariableNameFindings`, search: `function pushVariableNameFindings`) verifies an `of` token follows the binding by slicing the codeLine from the end of the matched substring and matching `/^\s+of\b/`. The regex itself stays broad because the same VARIABLE_DECLARATIONS pattern feeds other rules; the exemption gate gets tightened where it matters.

When adding an exemption that targets a specific control-flow header shape, do not key off the matched substring's prefix - that's just the part of the header the binding regex captured. Inspect the broader header (the slice of `codeLine` after the match) for the actual discriminator token (`of`, `in`, `;`, `=`). Tests: `naming-rules.test.ts`, search: `naming short-variable still flags C-style for binding`.

## Footgun: line-local `^export` detection misses re-exported declarations

**Status:** active | **Created:** 2026-05-27 | **Evidence:** OBSERVED
**Evidence context:** PR #4 review, Codex P2.

The block builder in `src/blocks.ts` originally set `isExported` from a line-local `/^\s*export\b/` test on the declaration line only; the function that did so has since been refactored away, so classify against the current owner (`src/blocks.ts`, search: `isExported: boolean`). Common module pattern is to declare locally and re-export at the bottom: `function foo() {}` followed by `export { foo };` (search: `^export \{` across `src/`). That declaration's `isExported` came back false, so `docs.missing-exported-function-doc` (warning) silently downgraded to `docs.missing-internal-function-doc` (advisory) - undercutting the public-API doc gate for a pervasive shape.

The fix runs `collectReExportedNames` (`src/blocks.ts`, search: `function collectReExportedNames`) once per file, scanning the masked codeSource for `export { ... }` (multi-name, alias-aware) and `export default <Ident>`. `isExported` ORs the line-local check with the file-level set, so a function declared inline gets the export classification when its name is re-exported anywhere in the file.

Two implications: (1) when adding a per-symbol classification rule that depends on "is this exported," do the file-level re-export scan once and thread the result; do not rely on per-line patterns alone. (2) `isPublic` (which considers `public` keyword too) was unaffected, but the moral is identical for any future "this declaration is part of the public surface" gate. Tests: `src/false-positive-fixes.test.ts`, search: `FP-#33b docs.missing-exported-function-doc fires on plain and aliased re-exports`.

## Footgun: `naming.acronym-case` is file-wide, not per-symbol

**Status:** active | **Created:** 2026-05-25 | **Evidence:** OBSERVED
**Resolution note:** Resolved 2026-08-04 for convention-forced surfaces; other file-wide comparisons remain relevant.

`naming.acronym-case` (`src/class-rules.ts`, search: `ruleId: "naming.acronym-case"`) fired when the same known acronym appeared in more than one casing anywhere in a single source file. Identifier casings like `Html` (titled), `HTML` (all-caps), and `html` (all-lower) were all counted independently; a single file that used `parseHtmlPillarRows` AND a constant named `HTML_PILLAR_HEADERS` got a finding even though both names were internally consistent on their own.

Resolved 2026-08-04: SCREAMING_SNAKE constants and all-lower names are convention-forced surfaces and no longer contribute observations (search: `isConventionForcedAcronymCasing`), so the `parseHtmlPillarRows` + `HTML_PILLAR_HEADERS` mix is quiet. The rule stays file-wide across CHOSEN casings: `parsedHtml` beside `rawHTML` still fires, including across separate function owners.

When extracting helpers in a file that already uses the titled form (`Html`, `Css`, `Sql`, `Url`, etc.), match the existing casing for new identifiers - including SCREAMING_SNAKE_CASE constants. Either rename the constant to `pillarHeaderColumns` (camelCase, no acronym) or accept that the codebase convention is title-cased acronyms even in constants. The rule has no per-symbol override; only file-wide consistency clears it.

## Footgun: `CORRELATED_COMPLEXITY_RULE_IDS` is defined twice and must be edited in lockstep

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Evidence context:** design.god-function removal and ADR-011.

The complexity-cluster rule-id set lives in TWO files with identical literals: `src/scoring.ts` (search: `const CORRELATED_COMPLEXITY_RULE_IDS`) drives penalty clustering, and `src/report-renderers.ts` (search: `const CORRELATED_COMPLEXITY_RULE_IDS`) drives the "Correlated complexity clusters" text/markdown output. Neither imports the other and no test asserts they match, so editing only one leaves scoring and reporting silently disagreeing about which findings cluster.

When you add or remove a rule from the complexity cluster (e.g. retiring `design.god-function` per ADR-011, or the inverse), change BOTH literals in the same pass, then grep `CORRELATED_COMPLEXITY_RULE_IDS` to confirm exactly two hits with the same contents. The P5 cluster contract (ADR-009) depends on the two staying in sync.

## Footgun: a removed rule id left in a comment trips `docs.stale-comment` unless the SAME line carries a historical marker

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Evidence context:** design.god-function removal self-scan.

After removing a rule from the catalogue, any committed comment that still names the dotted id (`pillar.name`) becomes an "unknown rule id" to `pushStaleRuleReferenceFindings` (`src/comment-rules.ts`, search: `function pushStaleRuleReferenceFindings`), which checks each id against `DESCRIPTOR_IDS`. The escape hatch is `isHistoricalContextComment` (`src/comment-rules.ts`, search: `function isHistoricalContextComment`): it matches `previously|legacy|compat|migration|ADR` and is checked PER comment line, because the scanner emits one record per `//` line. So the historical marker MUST sit on the SAME `//` line as the removed id - "retired"/"removed" are NOT in the vocabulary, and an `ADR-NNN` reference on the next line does not count.

When a comment explains a retired rule (e.g. an ADR cross-reference about `design.god-function`), keep the id and an `ADR-NNN` (or `legacy`/`migration`) token on one line: `// ... the retired design.god-function (ADR-011) composite ...`. This compounds with the context-doc footgun above (the invariant/why marker must be on the LAST `//` line above the declaration), so one explanatory comment near a contract-owning declaration must satisfy both per-line constraints at once.

## Footgun: a milestone may name "new" dependency rules that already exist under different ids

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Evidence context:** M25 supply-chain slice in 0.3.0.

The M25 task list named three "new" hardened-dependency rule ids to add - `security.dependency-install-script`, `security.dependency-git-url-reference`, `security.dependency-unpinned-version` - but `src/project-config-rules.ts` already ships the same coverage under older ids: `security.risky-lifecycle-script` (preinstall/install/postinstall/prepare/prepublish hooks), `security.remote-install-script` (`curl|wget … | sh`), `security.url-dependency` (https/git/ssh/github-shorthand specs), and `waste.broad-runtime-version` (`*`/`x`/`latest`/unbounded `>=`/`||`). The capability matrix even rated this row `dependency ◑(3)` - the `(3)` was those existing checks - so "◑ → ✅" meant HARDEN the existing rules, not add parallel ids. Adding the named ids would have produced two findings for one root cause: the exact P5/ADR-011 anti-pattern (a composite restating findings already on the symbol).

Before implementing any rule a plan calls "new", `grep -oE '"<pillar>\\.[a-z-]+"' src/rules.ts | sort -u` and read the owning module - a milestone written before the cli.ts split (or before a sibling milestone landed) can predate coverage that now exists. If the gap is real it is usually narrow (here: only `file:` protocol deps escape `isUrlDependency`, and that is low-signal at advisory), so prefer extending the existing rule's predicate over minting a duplicate id.

## Footgun: caching a parsed AST by `SourceFile` identity goes stale when the object is reused

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED
**Evidence context:** M25 AST-flow slice and security-flow tests.

The syntax-only parser adapter `getSourceFile` (`src/security-flow-rules.ts`, search: `function getSourceFile`) was first written to memoise `ts.createSourceFile` output in a `WeakMap` keyed by the discovery `SourceFile` object. That is safe in a real run - each discovered file has its own `SourceFile` instance and is parsed once - but the tests (`src/security-flow-rules.test.ts`) reuse a single `fileStub` across cases with DIFFERENT source strings. The object-keyed cache returned the FIRST case's AST for every later case, so each test produced a byte-identical finding regardless of input: the SSRF positive misfired as `security.path-traversal-candidate`, and every "expect zero" negative fired. `tsc` was clean; the failure surfaced only in `npm test`.

Three takeaways: (1) `analyseSecurityFlow` is the only caller and runs once per file, so the cache bought nothing - it was an unrequested abstraction that only introduced a bug (CLAUDE.md: "No new abstractions ... beyond what was asked"). The fix was to delete the cache and parse per call. (2) If a per-run AST cache is ever actually needed, key it on the source text (or a content hash), never on the file-descriptor object, because tests and any future reuse of a `SourceFile` across sources will alias. (3) When rule output is byte-identical across genuinely different inputs, suspect shared or aliased state - a cache, a module-level mutable, or a global regex's `lastIndex` - before the rule logic.

## Footgun: AST sink argument walkers descend into non-sink callback bodies

**Status:** active | **Created:** 2026-06-01 | **Evidence:** OBSERVED
**Evidence context:** review feedback plus security-flow tests.

`taintedInput` (`src/security-flow-rules.ts`, search: `function taintedInput`) originally walked every node under every sink argument. That is too broad for callback-style APIs: `fs.readFile("./safe.json", () => log(target))` mentions a tainted local inside the callback, but the tainted value is not the filesystem path argument. The same text-walk mistake also applies to literal text such as `"req.query.path"`; raw `getText()` matching turns documentation-shaped strings into fake sources.

For syntax-only source-to-sink rules, inspect only sink-relevant expression trees. Prune nested function-like nodes while walking arguments, and treat string/no-substitution-template literals as literal text, not source evidence. Add a negative test any time a scanner starts using `node.getText()` over a subtree: one callback-only taint reference and one literal that names the source token. Tests: `src/security-flow-rules.test.ts`, search: `callback-only taint` and `string literals that only mention source tokens`.

## Resolved Entries

## Footgun: `process-exec` matches `RegExp.exec` source text

**Status:** resolved | **Created:** 2026-05-17 | **Evidence:** ACTUAL_MEASURED
**Resolved:** 2026-08-08
**Evidence context:** probe file asserting the false positive no longer fires.

`processExecCandidate` matched bare `exec(`, `spawn(`, or `execFile(` in masked code without requiring a child-process receiver or import context, so ordinary `RegExp.exec(...)` calls were reported as `security.process-exec`. Authors worked around it by avoiding `.exec(` in scanner source, including the bracket dispatch still visible at `src/text-scans.ts` (search: `globalPattern["exec"]`).

Resolved 2026-08-08 on two counts. The symbol is gone: `processExecCandidate` returns zero hits anywhere under `src/`, and the rule now lives in `src/line-rules.ts` (search: `ruleId: "security.process-exec"`) with evidence grading from `src/process-exec-metadata.ts` per ADR-018. The behaviour is gone too: a probe file whose only `exec` call is `pattern.exec(input)` on a `RegExp` scored zero `security.process-exec` findings. The bracket dispatch in `src/text-scans.ts` is now a historical workaround, not a required defence.

## Footgun: fixture-purpose rules read ONLY the last `//` line above a fixture

**Status:** resolved | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Resolved:** 2026-08-04
**Evidence context:** named-profiles self-scan.

`docs.fixture-purpose-missing` (`src/fixture-purpose-rules.ts`, search: `function hasFixturePurposeComment`; search: `function leadingFixturePurposeComment`) checked its marker vocabulary (`fixture`/`covers`/`regression`/`baseline`/`fingerprint`/`because`/...) against only the single `//` line directly above a large template-literal fixture. A marker on an earlier line of a stacked `//` header did not clear it. The rule engages only above `FIXTURE_PURPOSE_MIN_LINES` (12), and an object-literal fixture whose backtick begins after the `const` line is not a candidate.

Observed in `src/changed-region-contract.test.ts` (search: `const REGION_FIXTURE`): a multi-line header with "Fixture purpose:" on its first line kept firing until "This fixture covers ..." moved to the final line.

Resolved 2026-08-04: `hasFixturePurposeComment` now evaluates the joined contiguous `//` run (shared `src/comment-scanner.ts`, search: `combinedContextLineComment`), and a leading or same-line comment of eight or more words clears the rule even without the vocabulary list (search: `FIXTURE_PURPOSE_MIN_WORDS`). Keyword placement games are no longer needed; short comments still need a vocabulary word.

## Footgun: context-doc markers were checked against only the last line of a leading line-comment run

**Status:** resolved | **Created:** 2026-07-12 | **Evidence:** OBSERVED
**Evidence context:** 0.5.0 self-scan fix-forward across six reword iterations.

The context-doc rules previously tested only the comment record adjacent to a declaration, so marker wording on earlier lines of a contiguous `//` run was invisible. Resolved 2026-07-13: `src/comment-scanner.ts` (search: `function combinedContextLineComment`, moved there 2026-08-04) joins contiguous line-comment text for context-doc evaluation while retaining the final record's anchor. Extended 2026-08-04: magic-threshold and fixture-purpose leading-comment checks now read the joined run too. Stale-reference and restatement checks deliberately keep the final record only, so examples in earlier prose do not become symbols.

## Footgun: rule-group pass gates silently disable rules missing from the id list

**Status:** resolved | **Created:** 2026-06-11 | **Evidence:** ACTUAL_MEASURED
**Evidence context:** runtime reproduction plus regression test.

The analyser's pass gates (`src/analyser.ts`, search: `runRuleGroupPass`) skip a whole scanner pass when no rule in the gate's id list is enabled. The contract is implicit: the list must contain EVERY rule id the pass can emit, including rules pushed by helpers the pass calls (`analyseCommentQualityRules` calls `pushFixturePurposeFindings`, which emits `docs.fixture-purpose-missing`). `COMMENT_QUALITY_RULE_IDS` omitted that id, so a config disabling the nine listed docs rules silently disabled the still-enabled fixture-purpose rule: zero findings, no diagnostic, catalogue still advertising the rule. Resolved 2026-06-11 by adding the id to the gate list and pinning `src/docs-comment-rules.test.ts` (search: `fixture purpose rule still runs`). When adding a rule to a shared pass, extend the matching gate list in `src/analyser.ts` and prefer an enabled-solo or disabled-siblings regression test for any rule that rides a group gate. Over-inclusive gates only waste cycles; under-inclusive gates silently kill enabled rules - bias toward over-inclusion.

## Footgun: declaration anchors keyed to the name line hide decorators and split modifiers

**Status:** resolved | **Created:** 2026-08-12 | **Evidence:** ACTUAL_MEASURED
**Resolved:** 2026-08-12

`CallableMatchPoint.lineIndex` deliberately anchors on the callable's NAME line, because that is where the legacy regex scanner fired and the finding anchor must not move. `src/blocks.ts` then used that same index to ask whether the declaration had a leading comment, which is a different question: the name line is not the start of the declaration when modifiers or decorators precede it.

Two shapes broke. A decorated method (`// comment` then `@Post(...)` then `@HttpCode(200)` then the name) looked undocumented because the line above the name is a decorator. A split-line signature (`export async function` then `publicApi()`) looked undocumented because the line above the name is the modifier run. Measured on the `nest` corpus: 15 false `docs.missing-internal-function-doc` findings, every one a controller method carrying real documentation above its decorators.

Resolved 2026-08-12 by adding `declarationLineIndex` (`src/parsed-script.ts`, search: `declarationLineIndex`), derived from the visibility node's `getStart`, which skips leading documentation but includes modifiers and decorators. It is clamped with `Math.min` against `lineIndex` so the anchor can only move earlier, never later, and `startLine` is untouched so no fingerprint churns. Tests: `src/false-positive-fixes.test.ts`, search: `FP-#49`.

When a rule asks a question about the DECLARATION (does it have docs, is it exported, what modifiers does it carry), use the declaration anchor. Reserve the name-line index for the reported finding location, where the legacy contract requires it.

## Footgun: "contains a literal" is not "is a literal" when grading command vectors

**Status:** resolved | **Created:** 2026-08-12 | **Evidence:** ACTUAL_MEASURED
**Resolved:** 2026-08-12

`hasConstLiteralCommandDeclaration` (`src/process-exec-metadata.ts`) classified a `const` command as a fixed vector when its initializer matched `/["'][^"']+["']/` and contained none of `` `$()[]{} ``. `const command = "echo " + input` satisfies both: it contains a quoted fragment, and `+` was not in the rejection set. ADR-018 grades shell-enabled DYNAMIC commands as warning and fixed vectors as advisory, so a genuine command-injection candidate emitted at advisory and a `--fail-on=warning` gate passed it.

**Evidence:** a probe with `const command = "echo " + input; exec(command)` produced `security.process-exec` at advisory with `argumentSource: "local-const"`, `shellEnabled: true`.

Resolved 2026-08-12 by requiring the whole trimmed initializer to be one quoted literal (search: `hasConstLiteralCommandDeclaration`). Tests: `src/process-exec-rules.test.ts`, search: `a concatenated const command stays dynamic`.

Generalise this: any predicate that downgrades severity on "evidence of safety" must match the WHOLE expression, never a substring of it. A blacklist of dangerous characters will always miss an operator someone did not think of; an allowlist of the exact safe shape will not.
