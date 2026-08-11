# AGENTS.md

`gruff-ts` governs AI-generated code: wired in as a coding-agent hook, it forces an agent to produce changes a human who did not write them can sign off on - legible enough to verify, secure where the reviewer's eye slips, and tested for real behavior rather than low-signal ceremony. Mechanically it is a TypeScript project quality analyzer: a dependency-light Node.js/ESM CLI with a thin `src/cli.ts` bootstrap and focused runtime modules under `src/`. It scans TypeScript, JavaScript, CSS, and common config/text files (json, yaml, toml, env, ini, xml, npmrc-style secret files) and emits findings across 11 pillars (complexity, dead-code, design, documentation, maintainability, modernisation, naming, security, sensitive-data, size, test-quality). Core invariant: every finding carries a stable `fingerprint` so baselines (`gruff.baseline.v1`) and report snapshots (`gruff.analysis.v2`) round-trip without churn.

goat-flow version: 1.15.1

## Workspace Boundary

This repo is the **selected target project**. If the controlling goat-flow workspace differs from the target, treat its workflow, dist, and manifest as read-only context, not paths to edit. Inside this target project, only Codex-owned surfaces (`AGENTS.md`, `.codex/`, shared `.agents/skills/`, shared `.goat-flow/`) are in scope unless the user widens it. Do not modify `CLAUDE.md` or `.claude/` during Codex turns.

## Truth Order

1. User's explicit instruction for this session.
2. This file.
3. `.goat-flow/architecture.md` and `.goat-flow/code-map.md`.
4. Skills loaded on demand from `.agents/skills/`.
5. Existing source under `src/`, `bin/`, `scripts/`.

The Never tier and accepted ADR safety constraints are non-overridable. Approval may release an Ask First boundary or provide the explicit commit/push authorization required below, but it cannot waive safety enforcement.

## Autonomy Tiers

- **Always:** Read source before changing it; run `npm run check` on changed `.ts`; edit within declared scope; append progress lines to the active session log when one exists.
- **Ask First:** Before touching any of: schema strings (`gruff.analysis.v2`, `gruff.baseline.v1`, `gruff.hotspot.v1`), the `Finding` shape, the default-ignored directory list, baseline file format, dashboard wire format, or `package.json`/`tsconfig.json`. State boundary touched, related code read (file:symbol), footgun checked, local instruction checked, rollback command.
- **Never:** Freeze writes if interrupted; commit/push without explicit ask; relax `tsconfig.json` strict flags; introduce runtime dependencies beyond `commander`, `tsx`, and `typescript` (syntax-only parsing per ADR-012); bypass `.goat-flow/hooks/deny-dangerous.sh`; edit `CLAUDE.md` or `.claude/` (peer agent surfaces).

## Hard Rules

- Modify files in place via `apply_patch`. Never create `_v2`, `_new`, `_backup`, `cli.modified.ts`.
- Severity order: SECURITY > CORRECTNESS > INTEGRATION > PERFORMANCE > STYLE.
- `tsconfig.json` runs with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`. New code must compile without weakening these.
- Schema versions are public contract - bump only when the user explicitly asks.
- Use semantic anchors (file:`symbolName`) in references, not bare line numbers.
- Sub-agents get one objective, structured return, ≤5 calls.
- No new abstractions or error handling beyond what was asked.
- Ambiguous requirements: present interpretations, do not pick silently.

## Commit Messages

Conventional commits (`type(scope): subject`); observed types: feat, refactor, chore, docs, fix, perf, test. Name the concrete behavior, file family, or command that changed - no bare weak verbs (`update`, `change`, `tweak`) as the whole subject. Full reference: `docs/coding-standards/git-commit-message.md`.

## Key Resources

- **Learning loop** (INDEX-first before every change): `.goat-flow/learning-loop/footguns/`, `.goat-flow/learning-loop/lessons/`, `.goat-flow/learning-loop/patterns/`, `.goat-flow/learning-loop/decisions/`.
- **Tool playbooks**: `.goat-flow/skill-docs/playbooks/README.md` is the full index (e.g. `.goat-flow/skill-docs/playbooks/browser-use.md`, `.goat-flow/skill-docs/playbooks/page-capture.md`) - read BEFORE declaring a tool unavailable.
- Orientation: `.goat-flow/code-map.md`, `.goat-flow/architecture.md`, `.goat-flow/glossary.md`.

## Essential Commands

```bash
npm run check        # tsc --noEmit && npm test
npm test             # node --import tsx --test src/**/*.test.ts
npm run start-dev    # tsx src/cli.ts dashboard (binds 127.0.0.1:8767)
./bin/gruff-ts analyse . --fail-on=advisory   # the self-scan gate CI enforces
bash scripts/preflight-checks.sh              # full local gate: version, npm audit, check, self-scan, shellcheck
bash .goat-flow/hooks/deny-dangerous.sh --self-test   # verify deny hook
```

## Execution Loop: READ → SCOPE → ACT → VERIFY

When a `goat-*` skill is active, its Step 0 replaces READ and selects the skill's mode/depth. SCOPE still applies before writes: a skill may write when its selected mode permits writes or the user explicitly approves them. `/goat-plan` File-Write may create gitignored milestone files without a separate approval gate; `/goat-debug` D3 still requires approval before fixes. Resume at ACT after Step 0 output or when a blocking gate releases.

### READ
MUST read relevant files before changes. Never fabricate codebase facts (rule counts, pillar names, schema strings - read the live source first, especially `src/types.ts`, `src/rules.ts`, `src/constants.ts`, and the touched module). For URL, local HTML, localhost, screenshot, rendered UI, or browser-visible behaviour (the `dashboard` subcommand on `127.0.0.1:8767`), check browser evidence first. Search the generated `INDEX.md` files in `.goat-flow/learning-loop/{footguns,lessons,patterns}/` before opening source entries; include `.goat-flow/learning-loop/decisions/INDEX.md` for architecture, schema, or setup work. When a follow-up grep is needed, root it at the bucket directory or deeper - a recursive search started at `.goat-flow/` silently returns zero hits because its `.gitignore` opens with `*`. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-docs/playbooks/` (e.g. `browser-use.md`, `page-capture.md`) and run that doc's "Availability Check" section verbatim - project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool". Before editing human-read prose, load its playbook: `changelog.md` for `CHANGELOG.md`, `release-notes.md` for release notes, and `writing-style.md` for README, docs, plan narrative, PR/issue text, or learning-loop bodies.

### SCOPE
Three signals before acting: (1) Intent - question vs directive. (2) Complexity tier + budget. (3) Mode - Plan / Implement / Explain / Debug / Review. MUST declare files allowed to change, non-goals, max blast radius. Expanding beyond scope = stop and re-scope.

| Complexity | Reads | Turns |
|---|---|---|
| Hotfix | 2 | 3 |
| Standard | 4 | 10 |
| System | 6 | 20 |
| Infra | 8 | 25 |

### ACT
Declare `State: [MODE] | Goal: [one line] | Exit: [condition]`.

| Mode | Behaviour |
|---|---|
| Plan | Produce planning artefacts. `/goat-plan` File-Write may create gitignored milestone files when selected. Exit on LGTM |
| Implement | Edit in 2-3 turns via `apply_patch`. 4th read without writing = checkpoint or re-scope |
| Explain | Walkthrough only. No changes unless asked |
| Debug | Diagnosis with file + semantic anchor first. Fixes after human reviews |
| Review | Investigate first. Never blindly apply suggestions |

### VERIFY
MUST run `npm run check` after touching `src/**/*.ts`, then the CI self-scan `./bin/gruff-ts analyse . --fail-on=advisory` (or `bash scripts/preflight-checks.sh` for the full sweep). MUST run `shellcheck` on `.sh` changes (including `.goat-flow/hooks/*.sh`). Cross-reference grep after renames (`grep -r symbol src/`). Tick milestone `- [x]` immediately when working from a plan.

**Hallucination red-flags:**
1. **Checks passed.** Quote the literal `tsc`/`node --test` pass line from this session - not paraphrase, not cached output.
2. **Completion.** List the specific files changed this turn or say none changed.
3. **Fix verification.** Run the original repro before claiming a bug is fixed.
4. **Hedged claims.** "Should work", "probably fine", "looks good" are not verification.

Before reporting done, reject the rationalisations catalogued in `.goat-flow/skill-docs/skill-preamble.md` (Rationalisations to reject): an excuse that trades a quoted result for hope is not verification.

Stop-the-line on broken tests, failed `tsc`, or behaviour regression. Two corrections on the same approach = rewind.

If VERIFY caught a failure or you corrected course, log behavioural mistakes in `.goat-flow/learning-loop/lessons/`, cross-doc traps in `.goat-flow/learning-loop/footguns/` (`Status:` / `Created:` / `Evidence:`), and significant decisions in `.goat-flow/learning-loop/decisions/`.

## Definition of Done

- `npm run check` AND the CI self-scan `./bin/gruff-ts analyse . --fail-on=advisory` pass (paste the literal pass lines). `bash scripts/preflight-checks.sh` covers both.
- No broken cross-references; renames grepped.
- No unapproved boundary changes (peer-agent files untouched).
- Learning loop updated if VERIFY tripped.
- Session log line appended if one is active.

## Artifact Routing

- "Add a footgun" → `.goat-flow/learning-loop/footguns/<category>.md` (read its README first).
- "Add a lesson" → `.goat-flow/learning-loop/lessons/<category>.md`.
- "Add a decision/ADR" → `.goat-flow/learning-loop/decisions/`.
- "Add a pattern" → `.goat-flow/learning-loop/patterns/`.

Runtime code, hooks, and agent config are out of scope unless the user explicitly asks.

## Router Table

| Resource | Path |
|----------|------|
| Instruction file | `AGENTS.md` |
| Architecture | `.goat-flow/architecture.md` |
| Code map / glossary | `.goat-flow/code-map.md`, `.goat-flow/glossary.md` |
| Learning loop | `.goat-flow/learning-loop/footguns/`, `.goat-flow/learning-loop/lessons/`, `.goat-flow/learning-loop/patterns/`, `.goat-flow/learning-loop/decisions/` |
| Skill reference (meta) | `.goat-flow/skill-docs/` |
| Tool playbooks (README index; tools e.g. browser-use, page-capture; disciplines e.g. changelog, release notes, prose style) | `.goat-flow/skill-docs/playbooks/` - read when a request names one, and BEFORE declaring a tool unavailable |
| Skill-authoring methodology | `.goat-flow/skill-docs/skill-quality-testing/` - load the README, then the topical authoring guide |
| Codex skills/config | `.agents/skills/`, `.codex/config.toml`, `.codex/hooks.json`, `.goat-flow/hooks/` (shared) |
| Source | `src/analyser.ts` (pipeline), `src/rules.ts` (catalogue), `src/cli-program.ts` (commands); `src/cli.ts` is a 24-line entrypoint |
| Entry point / scripts | `bin/gruff-ts`, `scripts/preflight-checks.sh`, `scripts/check.sh`, `scripts/start-dev.sh` |
| Fixtures | `fixtures/sample.ts` |
| Build / config | `package.json`, `tsconfig.json` |
| Commit policy | `docs/coding-standards/git-commit-message.md` |
| Workspace notes | `.goat-flow/logs/sessions/`, `.goat-flow/plans/`, `.goat-flow/scratchpad/` |
| Peer instructions | `CLAUDE.md` |
