---
category: docs-authoring
last_reviewed: 2026-08-08
---

# Docs-authoring footguns

## Footgun: escaped backticks inside a single-backtick code span silently mangle markdown (and trip MD038)

**Status:** active | **Created:** 2026-06-04 | **Evidence:** ACTUAL_MEASURED
**Evidence context:** markdown-it render of a rule-scanners.md line emitted five prose fragments inside inline code.

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

**Status:** active | **Created:** 2026-06-09 | **Evidence:** OBSERVED
**Evidence context:** preflight gruff scan flagged two `docs.stale-comment` findings.

Source comments cite learning-loop docs by relative path. A reorg that relocates a doc does not update those comments, so they go stale, and gruff's `docs.stale-comment` rule resolves the cited path and fails the run. Only the full-project scan in `scripts/preflight-checks.sh` covers a commenting file the agent did not just edit, so the straggler surfaces at preflight, not at edit time - the PostToolUse changed-lines hook only scans the edited file, never the one whose comment went stale.

Defence: when moving any doc under `.goat-flow/`, grep all source for the old relative path before committing the move (for example `grep -rn "goat-flow/lessons/" --include='*.ts' src`) and update every hit in the same change.

Instance: the learning-loop reorg in commit `cddf7f9` left `src/cli-program.ts` (search: `buildProgram`) and `src/dashboard.ts` (search: `startDashboard`) citing `.goat-flow/lessons/verification.md` after it moved under `.goat-flow/learning-loop/lessons/`; both tripped `docs.stale-comment` until repointed.

## Footgun: generic Codex skill validation rejects required goat-flow version metadata

**Status:** active | **Created:** 2026-07-16 | **Evidence:** OBSERVED
**Evidence context:** `quick_validate.py` rejected `goat-flow-skill-version`; goat-flow audit still reported `agent-skills` pass.

The system `skill-creator/scripts/quick_validate.py` validator and goat-flow use different frontmatter contracts. The generic validator rejects `goat-flow-skill-version` as an unexpected key, while `.goat-flow/skill-docs/skill-quality-testing/deployment.md` (search: `Frontmatter has`) requires that exact key on installed goat-flow skills. Treating the generic failure as a skill defect and deleting the version field would make the file pass the wrong validator while violating the repository's real deployment contract.

Defence: keep `goat-flow-skill-version`, use goat-flow's own `audit . --agent codex` `agent-skills` result for installed-skill structure, and report template drift separately. Deliberately edited installed skills and hooks are expected to appear in the audit's drift section until their upstream goat-flow templates receive the same fix; never run `install` merely to erase that evidence because it overwrites the local corrections under review.

Smoke evidence: `.goat-flow/logs/sessions/2026-07-16-goat-{critique,plan,qa,security}-tdd.md` records the project-native application checks used instead of claiming generic-validator success or bulletproof coverage.

## Footgun: goat-flow upgrades can expose project-owned cold-path drift

**Status:** active | **Created:** 2026-08-07 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After a goat-flow upgrade, run stats and all three audit modes, then budget time to reconcile project-owned metadata, anchors, and inventories that the installer deliberately preserves.
**Trigger phase:** VERIFY
**Incident count:** 2
**Latest occurrence:** 2026-08-07

The 1.14.0 setup audit passed while `audit . --agent codex --harness` failed because existing entries used older evidence labels such as `MEASURED`, appended evidence context inside the label field, encoded resolution dates inside `Status`, and cited a gitignored milestone as durable evidence. The install correctly refreshed system-owned README contracts but did not rewrite project-owned learning entries, so a structurally current install can still fail its feedback-loop gate.

The 1.15.0 `audit . --agent codex --check-content` gate then found the same preservation boundary in cold-path docs: managed log and plan READMEs cited the `Local Data and Evidence Budget` architecture anchor, while the preserved `.goat-flow/architecture.md` lacked that heading; the preserved code map also omitted the newly installed playbook inventory. These are setup-content failures even when base structure, skill versions, and hook registration pass.

Evidence: `.goat-flow/learning-loop/footguns/README.md` (search: `Evidence labels are mutually exclusive`) defines the current label/status contract; `.goat-flow/learning-loop/lessons/README.md` (search: `Automatic Capture Policy`) confirms project-owned entries are manually consolidated rather than auto-rewritten; `.goat-flow/logs/sessions/README.md` (search: `Local Data and Evidence Budget`) demonstrates the managed-to-project-owned anchor contract.

Prevention: immediately run `stats . --check`, the base audit, the harness audit, and the content audit after installation. Normalize only reported project-owned entries, replace gitignored task paths with committed semantic anchors, reconcile architecture and code-map inventories against live files, regenerate indexes, and rerun each original failing command.

## Footgun: `audit --agent <one>` never inspects the sibling agents' instruction files

**Status:** active | **Created:** 2026-08-08 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** After renaming or moving any doc an instruction file cites, grep every agent surface for the old path instead of trusting a passing single-agent audit.
**Trigger phase:** VERIFY
**Incident count:** 1
**Latest occurrence:** 2026-08-08

This workspace keeps four near-identical agent instruction files (`CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, plus the `.agents/` surface). `audit . --agent claude` reads only the Claude surface, and its path-resolution finding ("All 64 referenced paths resolve across router tables, architecture.md, and core docs") covers router tables and core docs - not inline prose in the body. Two blind spots stack: a stale path in a Commit Messages sentence is invisible even in the audited file, and a stale path in a *sibling* file's router table is invisible because that file was never opened. gruff's own `docs.stale-comment` rule does not close the gap either - it resolves paths cited in source comments, not in markdown prose.

Defence: after renaming a doc, run one repo-wide grep for the old basename across all extensions (`grep -rn "old-name\.md" . | grep -v node_modules`) and fix every agent surface in the same change. A green `--agent claude` audit is not evidence that the other three surfaces are consistent.

Instance: `docs/coding-standards/git-commit.md` was renamed to `git-commit-message.md`, but six references survived - inline prose in all three of `CLAUDE.md`, `AGENTS.md`, `.github/copilot-instructions.md`, the router-table `Commit policy` row in the latter two, and the Copilot Workspace Boundary owned-surfaces list. Both `audit . --agent claude --harness` and `--check-content` reported pass (all five concerns at 100, drift 0/53 findings, 177 files scanned) while every one of those pointers was broken. The audit's own verification concern named the real file (`Commit guidance found at docs/coding-standards/git-commit-message.md`), so the mismatch was only visible by reading that finding against the instruction file.

## Footgun: gitignore-aware search finds nothing when recursion starts at `.goat-flow/`

**Status:** active | **Created:** 2026-08-08 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Scope learning-loop greps at the bucket directory or deeper, and treat a zero-hit result rooted at `.goat-flow/` as a tooling artifact rather than a genuine retrieval miss.
**Trigger phase:** READ
**hallucination-risk:** high

`.goat-flow/.gitignore` (search: `# Ignore everything by default`) opens with a blanket `*` and re-admits content through negations such as `!learning-loop/**`. Git resolves that correctly - `git ls-files .goat-flow/learning-loop/` lists 44 tracked files and `git check-ignore` exits 1 for `footguns/README.md`. Gitignore-aware search tools do not. Claude Code replaces `grep` with a shell function that execs `ugrep --ignore-files`, which honours the leading `*` and prunes the whole tree before the negations apply.

Measured on 2026-08-08: `grep -rl Footgun .goat-flow/` returned 0 files while `command grep -rl Footgun .goat-flow/` returned 23. Searching `ADR-024` under `.goat-flow/` returned 0 hits; the identical pattern under `.goat-flow/learning-loop/` returned 1. The failure is silent - no error, no warning, just an empty result that reads exactly like "no prior learnings exist".

This matters because the instruction file's READ step mandates grep-first retrieval over the learning loop and `.goat-flow/skill-docs/skill-preamble.md` (search: `Relevant prior learnings`) requires every functional skill to report the outcome. An agent that scopes one directory too high records a fabricated `none found` as evidence, which is the exact failure the evidence standard exists to prevent. It is also self-concealing: a footgun about retrieval failure cannot be retrieved by the failing search.

Defence: root learning-loop searches at `.goat-flow/learning-loop/<bucket>/` or deeper, which works, or repo root, which also works. When a search must span `.goat-flow/`, use `command grep` to bypass the wrapper. The `.gitignore` is byte-identical to the shipped template at `workflow/setup/reference/goat-flow-gitignore`, so this is framework-owned; editing it locally would trade this trap for permanent audit drift.
