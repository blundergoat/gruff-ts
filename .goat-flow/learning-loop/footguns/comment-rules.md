---
category: comment-rules
last_reviewed: 2026-10-03
---

# Comment and doc rule footguns

**Scope:** traps in the rules that read comments (context-doc, stale-comment, fixture-purpose, TODO, and commented-out-code checks); every other scanner footgun stays in `rule-scanners.md`.
Split out of `rule-scanners.md` on 2026-10-03 when that bucket came within 406 bytes of the 40000-byte threshold.

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

## Footgun: a removed rule id left in a comment trips `docs.stale-comment` unless the SAME line carries a historical marker

**Status:** active | **Created:** 2026-05-31 | **Evidence:** OBSERVED
**Evidence context:** design.god-function removal self-scan.

After removing a rule from the catalogue, any committed comment that still names the dotted id (`pillar.name`) becomes an "unknown rule id" to `pushStaleRuleReferenceFindings` (`src/comment-rules.ts`, search: `function pushStaleRuleReferenceFindings`), which checks each id against `DESCRIPTOR_IDS`. The escape hatch is `isHistoricalContextComment` (`src/comment-rules.ts`, search: `function isHistoricalContextComment`): it matches `previously|legacy|compat|migration|ADR` and is checked PER comment line, because the scanner emits one record per `//` line. So the historical marker MUST sit on the SAME `//` line as the removed id - "retired"/"removed" are NOT in the vocabulary, and an `ADR-NNN` reference on the next line does not count.

When a comment explains a retired rule (e.g. an ADR cross-reference about `design.god-function`), keep the id and an `ADR-NNN` (or `legacy`/`migration`) token on one line: `// ... the retired design.god-function (ADR-011) composite ...`. This compounds with the context-doc footgun above (the invariant/why marker must be on the LAST `//` line above the declaration), so one explanatory comment near a contract-owning declaration must satisfy both per-line constraints at once.

## Footgun: a test comment that quotes a relative fixture path fails the self-scan as a stale reference

**Status:** active | **Created:** 2026-09-26 | **Evidence:** OBSERVED
**Decision changed:** In a test comment, describe a path a test creates at runtime in words ("a config named two levels
up"), or keep it unquoted. Do not quote it in backticks.
**Trigger phase:** VERIFY

`pushStaleFileReferenceFindings` (`src/comment-rules.ts`, search: `function pushStaleFileReferenceFindings`) reads any
quoted token that opens with `./`, `../` or a source directory and ends in a known extension as a path, and reports
`docs.stale-comment` when that path resolves to nothing from the project root or the comment's own directory. A
path that a test writes into a temporary directory never exists there. M10's D25 test in `src/cli-surfaces.test.ts`
(search: `an explicit relative config is read from the launch directory`) first quoted its nested `--config` operand
in a comment. `npm run check` passed, and the preflight's full-project scan then failed on one advisory finding.

## Resolved Entries

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
