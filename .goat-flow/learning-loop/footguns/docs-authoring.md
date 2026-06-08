---
category: docs-authoring
last_reviewed: 2026-06-09
---

# Docs-authoring footguns

## Footgun: escaped backticks inside a single-backtick code span silently mangle markdown (and trip MD038)

**Status:** active | **Created:** 2026-06-04 | **Evidence:** MEASURED (markdown-it render of a rule-scanners.md line emitted five prose fragments inside inline code)

The learning-loop docs are dense with backtick anchors, so authors reach for backslash-escaped backticks when an anchor must show a literal backtick or a template-literal snippet. CommonMark has NO backslash escaping inside a code span, so the escape silently corrupts the line:

```text
BAD  (single-backtick span, \` escapes):   `const FIXTURE = \`...\`` template literal
GOOD (double-backtick delimiters):         ``const FIXTURE = `...` `` template literal
```

In the BAD form the first escaped backtick closes the span early (the backslash is kept as literal content), then the trailing backticks open a NEW span that swallows the following prose. The source looks correct in a monospace editor, but the line renders with whole sentences wrapped in code tags, and markdownlint reports MD038 (spaces inside a code span) on the accidental prose span. CodeRabbit runs markdownlint-cli2 on PRs, so it surfaces as a review comment - but its autofix is misdirected: it tightens an already-correct nearby anchor instead of the escaped-backtick source.

Defences:

1. To show a backtick inside inline code, switch to double-backtick delimiters and stop escaping (see GOOD above). When the content ends in a backtick, a single trailing pad space before the closing pair is the CommonMark-required, MD038-allowed form.
2. For a lone literal backtick in prose, write the word "backtick" instead of trying to typeset one.
3. Verify by rendering the line (markdown-it `renderInline`), not by eyeballing the source - the corruption is invisible in a plain editor.

Instance: `.goat-flow/learning-loop/footguns/rule-scanners.md` (search: `docs.fixture-purpose-missing`) carried three such spans on one line until 2026-06-04; a markdown-it render of that line emitted 24 inline code spans, five of them prose fragments (for example "on the" and "is not a candidate -") rather than code. Fixed by switching to double-backtick delimiters and rewording the lone backtick.

## Footgun: moving a `.goat-flow/` doc strands source comments that cite its old path

**Status:** active | **Created:** 2026-06-09 | **Evidence:** OBSERVED (preflight gruff scan flagged two `docs.stale-comment` findings)

Source comments cite learning-loop docs by relative path. A reorg that relocates a doc does not update those comments, so they go stale, and gruff's `docs.stale-comment` rule resolves the cited path and fails the run. Only the full-project scan in `scripts/preflight-checks.sh` covers a commenting file the agent did not just edit, so the straggler surfaces at preflight, not at edit time - the PostToolUse changed-lines hook only scans the edited file, never the one whose comment went stale.

Defence: when moving any doc under `.goat-flow/`, grep all source for the old relative path before committing the move (for example `grep -rn "goat-flow/lessons/" --include='*.ts' src`) and update every hit in the same change.

Instance: the learning-loop reorg in commit `cddf7f9` left `src/cli-program.ts` (search: `buildProgram`) and `src/dashboard.ts` (search: `startDashboard`) citing `.goat-flow/lessons/verification.md` after it moved under `.goat-flow/learning-loop/lessons/`; both tripped `docs.stale-comment` until repointed.
