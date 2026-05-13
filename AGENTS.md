# AGENTS.md

`gruff-ts` — TypeScript project quality analyzer. Single-file Node.js/ESM CLI (`src/cli.ts`, ~1.2k lines) that scans TypeScript, JavaScript, and common config (json, yaml, toml, env) files and emits findings across 11 pillars (size, complexity, dead-code, waste, naming, documentation, modernisation, security, sensitive-data, test-quality, design). Core invariant: every finding carries a stable `fingerprint` so baselines (`gruff.baseline.v1`) and report snapshots (`gruff.analysis.v1`) round-trip without churn.

goat-flow version: 1.6.4

## Workspace Boundary

This repo is the **selected target project**. The controlling goat-flow workspace lives elsewhere on the operator's machine; treat its workflow, dist, and manifest as read-only context, not paths to edit. Inside this target project, only Codex-owned surfaces (`AGENTS.md`, `.codex/`, shared `.agents/skills/`, shared `.goat-flow/`) are in scope unless the user widens it. Do not modify `CLAUDE.md` or `.claude/` during Codex turns.

## Truth Order

1. User's explicit instruction for this session.
2. This file.
3. `.goat-flow/architecture.md` and `.goat-flow/code-map.md`.
4. Skills loaded on demand from `.agents/skills/`.
5. Existing source under `src/`, `bin/`, `scripts/`.

## Autonomy Tiers

- **Always:** Read source before changing it; run `npm run check` on changed `.ts`; edit within declared scope; append progress lines to the active session log when one exists.
- **Ask First:** Before touching any of: schema strings (`gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`), the `Finding` shape, the default-ignored directory list, baseline file format, dashboard wire format, or `package.json`/`tsconfig.json`. State boundary touched, related code read (file:symbol), footgun checked, local instruction checked, rollback command.
- **Never:** Freeze writes if interrupted; commit/push without explicit ask; relax `tsconfig.json` strict flags; introduce runtime dependencies beyond `commander` + `tsx`; bypass `.codex/hooks/deny-dangerous.sh`; edit `CLAUDE.md` or `.claude/` (peer agent surfaces).

## Hard Rules

- Modify files in place via `apply_patch`. Never create `_v2`, `_new`, `_backup`, `cli.modified.ts`.
- Severity order: SECURITY > CORRECTNESS > INTEGRATION > PERFORMANCE > STYLE.
- `tsconfig.json` runs with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`. New code must compile without weakening these.
- Schema versions are public contract — bump only when the user explicitly asks.
- Use semantic anchors (file:`symbolName`) in references, not bare line numbers.
- Sub-agents get one objective, structured return, ≤5 calls.
- No new abstractions or error handling beyond what was asked.
- Ambiguous requirements: present interpretations, do not pick silently.

## Key Resources

- **Learning loop** (grep before every change): `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/`.
- **Tool playbooks**: `.goat-flow/skill-playbooks/browser-use.md`, `.goat-flow/skill-playbooks/page-capture.md` — read BEFORE declaring a tool unavailable.
- Orientation: `.goat-flow/code-map.md`, `.goat-flow/architecture.md`, `.goat-flow/glossary.md`.

## Essential Commands

```bash
npm run check        # tsc --noEmit && npm test
npm test             # node --import tsx --test src/**/*.test.ts
npm run start-dev    # tsx src/cli.ts dashboard (binds 127.0.0.1:8767)
./bin/gruff-ts analyse .   # local CLI invocation
bash .codex/hooks/deny-dangerous.self-test.sh   # verify deny hook
```

## Execution Loop: READ → SCOPE → ACT → VERIFY

When a `goat-*` skill is active, its Step 0 replaces READ and selects the skill's mode/depth. SCOPE still applies before writes: a skill may write when its selected mode permits writes or the user explicitly approves them. `/goat-plan` File-Write may create gitignored milestone files without a separate approval gate; `/goat-debug` D3 still requires approval before fixes. Resume at ACT after Step 0 output or when a blocking gate releases.

### READ
MUST read relevant files before changes. Never fabricate codebase facts (rule counts, pillar names, schema strings — read `src/cli.ts` first). For URL, local HTML, localhost, screenshot, rendered UI, or browser-visible behaviour (the `dashboard` subcommand on `127.0.0.1:8767`), check browser evidence first. Use grep-first retrieval across `.goat-flow/footguns/`, `.goat-flow/lessons/`, and `.goat-flow/patterns/`; include `.goat-flow/decisions/` for architecture, schema, or setup work. Before declaring any tool or capability unavailable, read the matching playbook in `.goat-flow/skill-playbooks/` (e.g. `browser-use.md`, `page-capture.md`) and run that doc's "Availability Check" section verbatim - project-local CLI tools at `~/.local/bin/` are valid; do not conflate "no harness/MCP tool" with "no tool".

### SCOPE
Three signals before acting: (1) Intent — question vs directive. (2) Complexity tier + budget. (3) Mode — Plan / Implement / Explain / Debug / Review. MUST declare files allowed to change, non-goals, max blast radius. Expanding beyond scope = stop and re-scope.

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
MUST run `npm run check` after touching `src/**/*.ts`. MUST run `shellcheck` on `.sh` changes (including `.codex/hooks/*.sh`). Cross-reference grep after renames (`grep -r symbol src/`). Tick milestone `- [x]` immediately when working from a plan.

**Hallucination red-flags:**
1. **Checks passed.** Quote the literal `tsc`/`node --test` pass line from this session — not paraphrase, not cached output.
2. **Completion.** List the specific files changed this turn or say none changed.
3. **Fix verification.** Run the original repro before claiming a bug is fixed.
4. **Hedged claims.** "Should work", "probably fine", "looks good" are not verification.

Stop-the-line on broken tests, failed `tsc`, or behaviour regression. Two corrections on the same approach = rewind.

If VERIFY caught a failure or you corrected course, log behavioural mistakes in `.goat-flow/lessons/`, cross-doc traps in `.goat-flow/footguns/` (`Status:` / `Created:` / `Evidence:`), and significant decisions in `.goat-flow/decisions/`.

## Definition of Done

- `npm run check` passes (paste the literal pass line).
- No broken cross-references; renames grepped.
- No unapproved boundary changes (peer-agent files untouched).
- Learning loop updated if VERIFY tripped.
- Session log line appended if one is active.

## Artifact Routing

- "Add a footgun" → `.goat-flow/footguns/<category>.md` (read its README first).
- "Add a lesson" → `.goat-flow/lessons/<category>.md`.
- "Add a decision/ADR" → `.goat-flow/decisions/`.
- "Add a pattern" → `.goat-flow/patterns/`.

Runtime code, hooks, and agent config are out of scope unless the user explicitly asks.

## Router Table

| Resource | Path |
|----------|------|
| Instruction file | `AGENTS.md` |
| Architecture | `.goat-flow/architecture.md` |
| Code map / glossary | `.goat-flow/code-map.md`, `.goat-flow/glossary.md` |
| Learning loop | `.goat-flow/footguns/`, `.goat-flow/lessons/`, `.goat-flow/patterns/`, `.goat-flow/decisions/` |
| Skill reference (meta) | `.goat-flow/skill-reference/` |
| Tool playbooks (CLI/MCP availability checks: browser-use, page-capture, skill-quality-testing) | `.goat-flow/skill-playbooks/` - read BEFORE declaring a tool unavailable |
| Codex skills/config | `.agents/skills/`, `.codex/config.toml`, `.codex/hooks.json`, `.codex/hooks/deny-dangerous.sh` |
| Source | `src/cli.ts`, `src/cli.test.ts` |
| Entry point / scripts | `bin/gruff-ts`, `scripts/check.sh`, `scripts/start-dev.sh` |
| Fixtures | `fixtures/sample.ts` |
| Build / config | `package.json`, `tsconfig.json` |
| Commit policy | `.github/git-commit-instructions.md` |
| Workspace notes | `.goat-flow/logs/sessions/`, `.goat-flow/tasks/`, `.goat-flow/scratchpad/` |
| Peer instructions | `CLAUDE.md` |
