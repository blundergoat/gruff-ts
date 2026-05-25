---
category: rule-scanners
last_reviewed: 2026-05-25
---

# Rule scanner footguns

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
