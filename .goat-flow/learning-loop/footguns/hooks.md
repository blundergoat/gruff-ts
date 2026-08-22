---
category: hooks
last_reviewed: 2026-08-21
---

# Hooks footguns

## Footgun: a locally patched managed hook is reverted by `install` and reported as an audit failure

**Status:** active | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Treat any local edit to `.goat-flow/hooks/**` as temporary. Before running `goat-flow install` or `hooks sync`, preview the managed diff. Authorize a conflicted path only after proving the new template preserves the intended behaviour; otherwise retain and re-apply the local patch.
**Trigger phase:** VERIFY

goat-flow owns the hook files it installs and compares them byte-wise against its template. Under 1.15.1, `goat-flow audit . --agent claude` reported `agent-guardrails` as **fail** with `deny-dangerous/patterns-shell.sh for claude differs from the current goat-flow template (v1.15.1)`, and the repair it printed was `install . --agent claude`. Following that advice without reviewing the conflict would have reverted the patch.

Version 1.15.1 had no supported local-override seam: `--force` overwrote every conflicted managed seed, and `.goat-flow/config.yaml` had no per-hook customization key. Version 1.16.0 adds `--force-path`, which narrows the replacement authority but still replaces the current bytes at that path.

This bit during the 0.5.0 review. The secret-guard bypass documented below was fixed locally in `.goat-flow/hooks/deny-dangerous/patterns-shell.sh` and `.goat-flow/hooks/deny-dangerous/patterns-paths.sh`, then reproduced against the pristine 1.15.1 template. Goat-flow 1.16.0 incorporated equivalent protections: `find_has_destructive_action` saves and restores the shared command context, and `.goat-flow/hooks/deny-dangerous.sh` (search: `Bash's |& operator pipes stderr too`) handles stderr pipelines in the shared splitter. Direct checks also confirmed that `npm run secrets` and `make secrets` remain allowed. The exact-path refresh therefore removed this repository's deliberate three-file divergence.

Detection: a managed dry run that reports `both-changed` is a divergence requiring review, not corruption. Confirm `.goat-flow/hooks/deny-dangerous/patterns-shell.sh` still contains `saved_cmd_trimmed` in `find_has_destructive_action`, then run the full deny-hook self-test before authorizing a conflicted path.

## Footgun: policy modules read shared `CMD_*` globals that any nested walk overwrites

**Status:** active | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before adding a recursive `check_command_segments` call inside any policy module, save the `CMD_*` and `HAS_*` globals and restore them once the nested walk returns. Adding a new recursion site without that save is a silent policy bypass, not a style issue.
**Trigger phase:** ACT

`check_segment` (`.goat-flow/hooks/deny-dangerous.sh`, search: `prepare_segment_context "$cmd" "$depth" || return $?`) parses each segment once and then runs three modules in sequence. `prepare_segment_context` assigns `CMD_TRIMMED`, `CMD_NORMALIZED`, `CMD_VERB`, `CMD_UNQUOTED`, `CMD_LOWER`, `HAS_REDIRECT`, and `HAS_PIPE` without `local`, so they are globals. Both later modules discard their own argument and read those globals instead (search: `CMD_TRIMMED` in `patterns-paths.sh` and `patterns-writes.sh`).

Any module that recurses after the parse therefore rewrites the context the remaining modules depend on. `find_has_destructive_action` (`.goat-flow/hooks/deny-dangerous/patterns-shell.sh`, search: `check_command_segments "$exec_cmd"`) does exactly this for `-exec` and `-execdir` payloads, so the outer command was judged using the inner payload's context.

Measured: `find .env -exec cat {} \;` was ALLOWED while the control `find .env -name x` was BLOCKED, and `.env.local`, `.aws/credentials`, `.npmrc`, `deploy.pem`, and `secrets/prod.pfx` were all reachable the same way. `-ok` and `-okdir` were unaffected because they do not recurse.

The trap is structural: `prepare_segment_context` already carries a save/restore around its own `bash -c` recursion, which reads as though the hazard is handled everywhere. It is not, and nothing in the suite covered the shape, because a nested payload that is itself dangerous still blocks correctly. Only an outer-dangerous plus inner-safe command exposes it.

Regression coverage now lives in `.goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh` (search: `find exec preserves protected search root`).

Upstream status: goat-flow 1.16.0 carries the fix. The current `find_has_destructive_action` saves the shared command context immediately before each nested walk and restores it afterwards, while the regression suite covers a protected outer search root with a safe nested action. The structural warning remains active because any future recursion site that omits the same save and restore can recreate the bypass.

## Footgun: `install` and `hooks sync` disagree about a disabled hook's script

**Status:** active | **Created:** 2026-08-11 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** On a goat-flow upgrade, run every `install . --agent <id>` first and `hooks sync .` last, then restore the disabled hook's script from the package template instead of re-running `install`.
**Trigger phase:** VERIFY

`gruff-code-quality` is disabled in `.goat-flow/config.yaml` (search: `gruff-code-quality`). Under goat-flow 1.15.1 the two managed-write commands hold opposite beliefs about its script:

- `install . --agent <id>` writes `.goat-flow/hooks/gruff-code-quality.sh`, and appends a Stop registration that is already there, leaving two identical blocks.
- `hooks sync .` deletes that script because the hook is disabled, and rewrites agent configs back to one block per event.

Neither order is self-consistent. Ending on `install` leaves `.claude/settings.json` and `.codex/hooks.json` running the post-turn safety scan twice per turn. Ending on `hooks sync` deletes a file the drift check requires, so `audit . --agent <id>` fails with `[missing] .goat-flow/hooks/gruff-code-quality.sh`, and the next `install` refuses to start: `Managed setup blocked before changes: ... The managed file was removed from the target after the last install.`

Measured on the 1.15.0 to 1.15.1 upgrade: a plain `install . --agent claude` took `.claude/settings.json` Stop blocks from 1 to 2; the following `hooks sync .` returned both `.claude/settings.json` and `.codex/hooks.json` to 1 and removed the script.

Prevention: finish with `hooks sync .`, then copy the template back with `cp node_modules/@blundergoat/goat-flow/workflow/hooks/gruff-code-quality.sh .goat-flow/hooks/gruff-code-quality.sh` and `chmod 755` it. The copy is byte-identical to what `install` writes (sha256 `c37b2ea34e438f40e6238a5b9b73ce69c9ee967e0a8dc64ac5c577ea3d8c22eb`), so install-state stays valid and `--force` is never needed. Count Stop blocks per agent config and confirm one each before reporting done.
