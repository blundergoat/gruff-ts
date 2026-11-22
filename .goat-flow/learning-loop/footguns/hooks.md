---
category: hooks
last_reviewed: 2026-11-23
---

# Hooks footguns

## Footgun: a locally patched managed hook is reverted by `install` and reported as an audit failure

**Status:** active | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Treat any local edit to `.goat-flow/hooks/**` as temporary. Before running `goat-flow install` or `hooks sync`, preview the managed diff. Authorize a conflicted path only after proving the new template preserves the intended behaviour; otherwise retain and re-apply the local patch.
**Trigger phase:** VERIFY

goat-flow owns the hook files it installs and compares them byte-wise against its template. Under 1.15.1, `goat-flow audit . --agent claude` reported `agent-guardrails` as **fail** with `deny-dangerous/patterns-shell.sh for claude differs from the current goat-flow template (v1.15.1)`, and the repair it printed was `install . --agent claude`. Following that advice without reviewing the conflict would have reverted the patch.

Version 1.15.1 had no supported local-override seam: `--force` overwrote every conflicted managed seed, and `.goat-flow/config.yaml` had no per-hook customization key. Version 1.16.0 adds `--force-path`, which narrows the replacement authority but still replaces the current bytes at that path.

This bit during the 0.5.0 review. The secret-guard bypass documented below was fixed locally in the bash policy modules patterns-shell.sh and patterns-paths.sh, then reproduced against the pristine 1.15.1 template. Goat-flow 1.16.0 incorporated equivalent protections: `find_has_destructive_action` saves and restores the shared command context, and the shared splitter handles stderr pipelines. Direct checks also confirmed that `npm run secrets` and `make secrets` remain allowed. The exact-path refresh therefore removed this repository's deliberate three-file divergence. Since 1.19.0 the hooks are Node modules, and `.goat-flow/hooks/deny-dangerous/corpus.json` (search: `stderr pipeline cannot hide protected read`) pins the stderr-pipeline protection.

Detection: a managed dry run that reports `both-changed` is a divergence requiring review, not corruption. Before authorizing a conflicted path, run `node .goat-flow/hooks/deny-dangerous.mjs --self-test=full` and confirm it prints `PASS`. The corpus case `.goat-flow/hooks/deny-dangerous/corpus.json` (search: `find exec preserves protected search root`) covers the bypass this repository once patched locally.

## Footgun: an upgrade that retires hook files fails each install until the last provider migrates

**Status:** active | **Created:** 2026-11-23 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** When a goat-flow upgrade retires hook files, run `install . --agent <id>` for every installed agent, re-run each install that exited 1, and only then run `hooks sync .`. Afterwards grep tracked files outside `.goat-flow/hooks/` for the retired paths, because install does not report references in CI, scripts, or instruction files.
**Trigger phase:** ACT

On the 1.18.0 to 1.19.0 upgrade the `.sh` hooks were replaced by `.mjs` hooks. Four provider configs register them, for example `.codex/hooks.json` (search: `run-hook.mjs`), alongside `.claude/settings.json`, `.agents/hooks.json` and `.github/hooks/hooks.json`. The claude, codex and antigravity installs wrote their files and then exited 1 with `Runtime migration is incomplete: a provider still references the retired runtime.` After the claude install, only `.claude/settings.json` had stopped referencing the retired runtime. The copilot install, run last, removed the ten retired files, and re-running the first three installs then printed `Install verified for <agent> (1.19.0)`.

The same rename stranded the self-test gates. Three CI steps in `.github/workflows/ci.yml` named the deleted `.sh` files and would have failed. `scripts/preflight-checks.sh` (search: `hook_policy_check()`) ran each hook self-test only when its file existed, so with the old paths it would have reported success while running nothing; it now runs the `.mjs` self-tests unconditionally, so a missing hook file fails the step.

## Resolved Entries

## Footgun: policy modules read shared `CMD_*` globals that any nested walk overwrites

**Status:** resolved | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before adding a recursive `check_command_segments` call inside any policy module, save the `CMD_*` and `HAS_*` globals and restore them once the nested walk returns. Adding a new recursion site without that save is a silent policy bypass, not a style issue.
**Trigger phase:** ACT

This trap belongs to the bash policy runtime that goat-flow shipped through 1.18.0. There, `check_segment` in guard-runtime.sh parses each segment once and then runs three modules in sequence. `prepare_segment_context` assigns `CMD_TRIMMED`, `CMD_NORMALIZED`, `CMD_VERB`, `CMD_UNQUOTED`, `CMD_LOWER`, `HAS_REDIRECT`, and `HAS_PIPE` without `local`, so they are globals. Both later modules, patterns-paths.sh and patterns-writes.sh, discard their own argument and read `CMD_TRIMMED` and its siblings instead.

Any module that recurses after the parse therefore rewrites the context the remaining modules depend on. `find_has_destructive_action` in patterns-shell.sh does exactly this for `-exec` and `-execdir` payloads, so the outer command was judged using the inner payload's context.

Measured: `find .env -exec cat {} \;` was ALLOWED while the control `find .env -name x` was BLOCKED, and `.env.local`, `.aws/credentials`, `.npmrc`, `deploy.pem`, and `secrets/prod.pfx` were all reachable the same way. `-ok` and `-okdir` were unaffected because they do not recurse.

The trap is structural: `prepare_segment_context` already carries a save/restore around its own `bash -c` recursion, which reads as though the hazard is handled everywhere. It is not, and nothing in the suite covered the shape, because a nested payload that is itself dangerous still blocks correctly. Only an outer-dangerous plus inner-safe command exposes it.

Regression coverage now lives in `.goat-flow/hooks/deny-dangerous/corpus.json` (search: `find exec preserves protected search root`).

Upstream status: goat-flow 1.16.0 carries the fix. Its `find_has_destructive_action` saves the shared command context immediately before each nested walk and restores it afterwards, while the regression suite covers a protected outer search root with a safe nested action.

Resolved 2026-11-23 by goat-flow 1.19.0, which replaced the bash runtime with Node modules. The policy modules declare no module-level `let` or `var` bindings, each segment's context comes from its own `segmentFacts` call, and `.goat-flow/hooks/deny-dangerous/patterns-shell.mjs` (search: `export async function findHasDestructiveAction`) hands each `-exec` payload to an `evaluate` callback at `depth + 1` instead of rewriting shared state. Through `node .goat-flow/hooks/deny-dangerous.mjs --check`, `find .env -exec cat {} \;`, its control `find .env -name x`, and the `.env.local`, `.aws/credentials`, `.npmrc`, `deploy.pem`, and `secrets/prod.pfx` variants all exited 2.

## Footgun: a leading variable assignment makes deny-dangerous read quoted-heredoc backticks as command substitution

**Status:** resolved | **Created:** 2026-10-03 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Write multi-line file bodies with the Write tool. When a shell heredoc is unavoidable and its body holds backticks, do not open the command with a bare `NAME=value;` segment, and treat a block as "not run" rather than rewording the body to slip past the guard.
**Trigger phase:** ACT

**Prevention:** Prefer the Write tool for file bodies; otherwise drop the leading assignment, which the guard accepts without it.

Under goat-flow 1.17.0 the bash guard in guard-runtime.sh blocked a scratch-file write with `Backtick command substitution hides nested execution`. The command began `S=<dir>;` and then fed a quoted heredoc with backticks in its body. Quoted-delimiter heredoc bodies never undergo substitution, so the block is a false positive. Check mode reproduced it: `bash deny-dangerous.sh --check="$cmd"` exited 2 when `cmd` was `S=/tmp/x; cat > /tmp/a.json <<'JSON'`, a body line holding a backticked word, and `JSON`; the same heredoc with no prefix, or after `echo start;`, exited 0.

The block fails closed, so it costs time, not safety. The managed self-test pins only the bounded-saver shape, now in `.goat-flow/hooks/deny-dangerous/corpus.json` (search: `bounded quality saver treats Markdown report JSON as data`). Because install reverts local hook patches (first entry above), the fix belonged upstream, and this entry was to be resolved when a goat-flow release passed the reproduction.

Resolved 2026-11-23 by goat-flow 1.19.0. Through `node .goat-flow/hooks/deny-dangerous.mjs --check`, the reproduction exits 0 with the `S=/tmp/x;` prefix, without it, and after `echo start;`. As a control, the same three commands against the 1.18.0 bash hook from commit `56a4b53` exited 2, 0, and 0, the first with `Backtick command substitution hides nested execution`.

## Footgun: `install` and `hooks sync` disagree about a disabled hook's script

**Status:** resolved | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** On a goat-flow upgrade, run every `install . --agent <id>` first and `hooks sync .` last, then restore the disabled hook's script from the package template instead of re-running `install`.
**Trigger phase:** VERIFY

`gruff-code-quality` is disabled in `.goat-flow/config.yaml` (search: `gruff-code-quality`). Under goat-flow 1.15.1 the two managed-write commands hold opposite beliefs about its script:

- `install . --agent <id>` writes `.goat-flow/hooks/gruff-code-quality.sh`, and appends a Stop registration that is already there, leaving two identical blocks.
- `hooks sync .` deletes that script because the hook is disabled, and rewrites agent configs back to one block per event.

Neither order is self-consistent. Ending on `install` leaves `.claude/settings.json` and `.codex/hooks.json` running the post-turn safety scan twice per turn. Ending on `hooks sync` deletes a file the drift check requires, so `audit . --agent <id>` fails with `[missing] .goat-flow/hooks/gruff-code-quality.sh`, and the next `install` refuses to start: `Managed setup blocked before changes: ... The managed file was removed from the target after the last install.`

Measured on the 1.15.0 to 1.15.1 upgrade: a plain `install . --agent claude` took `.claude/settings.json` Stop blocks from 1 to 2; the following `hooks sync .` returned both `.claude/settings.json` and `.codex/hooks.json` to 1 and removed the script.

Prevention: finish with `hooks sync .`, then copy the template back with `cp node_modules/@blundergoat/goat-flow/workflow/hooks/gruff-code-quality.sh .goat-flow/hooks/gruff-code-quality.sh` and `chmod 755` it. The copy is byte-identical to what `install` writes (sha256 `c37b2ea34e438f40e6238a5b9b73ce69c9ee967e0a8dc64ac5c577ea3d8c22eb`), so install-state stays valid and `--force` is never needed. Count Stop blocks per agent config and confirm one each before reporting done.

Resolved 2026-10-03 by goat-flow 1.17.0. On the 1.16.0 to 1.17.0 upgrade, `install . --agent <id>` for claude, codex, and copilot followed by `hooks sync .` kept `.goat-flow/hooks/gruff-code-quality.sh` byte-identical to the package template and left one Stop block each in `.claude/settings.json` and `.codex/hooks.json`. A later `install . --agent <id> --dry-run` reported both configs `user-preserved` and the script `unchanged`, so neither command undoes the other and the template copy step is no longer needed.
