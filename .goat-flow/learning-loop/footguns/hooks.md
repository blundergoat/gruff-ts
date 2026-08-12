---
category: hooks
last_reviewed: 2026-08-13
---

# Hooks footguns

## Footgun: a locally patched managed hook is reverted by `install` and reported as an audit failure

**Status:** active | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Treat any local edit to `.goat-flow/hooks/**` as temporary. Before running `goat-flow install` or `hooks sync`, diff the managed hooks against the template and re-apply local patches afterwards, or the change disappears with no error at the moment it is lost.
**Trigger phase:** VERIFY

goat-flow owns the hook files it installs and compares them byte-wise against its template. `goat-flow audit . --agent claude` reports `agent-guardrails` as **fail** with `deny-dangerous/patterns-shell.sh for claude differs from the current goat-flow template (v1.15.1)`, and the repair it prints is `install . --agent claude`, which overwrites the local file. Following the audit's own advice therefore reverts the patch.

There is no supported local-override seam in 1.15.1: `--force` overwrites managed seeds, and `.goat-flow/config.yaml` has no per-hook customization key. Confirmed with `goat-flow install --help` and by reading the config.

This bit during the 0.5.0 review. The secret-guard bypass documented below was fixed in `.goat-flow/hooks/deny-dangerous/patterns-shell.sh` and `.goat-flow/hooks/deny-dangerous/patterns-paths.sh`. Both defects were then reproduced against the pristine upstream template at `/home/devgoat/projects/goat-flow/workflow/hooks/`, so the vulnerable code ships to every project on goat-flow 1.15.1, not just this one. Until an upstream release carries the same change, this repository is deliberately divergent and `agent-guardrails` stays red for that reason alone; the other three agent-scope checks pass and `drift` passes across 58 checked files.

Detection: `goat-flow audit . --agent claude` naming a `differs from the current goat-flow template` message is the divergence, not a corruption. Confirm the local file still contains `saved_cmd_trimmed` in `find_has_destructive_action` before assuming the fix survived an upgrade.

## Footgun: policy modules read shared `CMD_*` globals that any nested walk overwrites

**Status:** active | **Created:** 2026-08-13 | **Evidence:** ACTUAL_MEASURED
**Decision changed:** Before adding a recursive `check_command_segments` call inside any policy module, save the `CMD_*` and `HAS_*` globals and restore them once the nested walk returns. Adding a new recursion site without that save is a silent policy bypass, not a style issue.
**Trigger phase:** ACT

`check_segment` (`.goat-flow/hooks/deny-dangerous.sh`, search: `prepare_segment_context "$cmd" "$depth" || return $?`) parses each segment once and then runs three modules in sequence. `prepare_segment_context` assigns `CMD_TRIMMED`, `CMD_NORMALIZED`, `CMD_VERB`, `CMD_UNQUOTED`, `CMD_LOWER`, `HAS_REDIRECT`, and `HAS_PIPE` without `local`, so they are globals. Both later modules discard their own argument and read those globals instead (search: `CMD_TRIMMED` in `patterns-paths.sh` and `patterns-writes.sh`).

Any module that recurses after the parse therefore rewrites the context the remaining modules depend on. `find_has_destructive_action` (`.goat-flow/hooks/deny-dangerous/patterns-shell.sh`, search: `check_command_segments "$exec_cmd"`) does exactly this for `-exec` and `-execdir` payloads, so the outer command was judged using the inner payload's context.

Measured: `find .env -exec cat {} \;` was ALLOWED while the control `find .env -name x` was BLOCKED, and `.env.local`, `.aws/credentials`, `.npmrc`, `deploy.pem`, and `secrets/prod.pfx` were all reachable the same way. `-ok` and `-okdir` were unaffected because they do not recurse.

The trap is structural: `prepare_segment_context` already carries a save/restore around its own `bash -c` recursion, which reads as though the hazard is handled everywhere. It is not, and nothing in the suite covered the shape, because a nested payload that is itself dangerous still blocks correctly. Only an outer-dangerous plus inner-safe command exposes it.

Regression coverage now lives in `.goat-flow/hooks/deny-dangerous/deny-dangerous-self-test.sh` (search: `find exec keeps outer secret operand in scope`).

Upstream status: the same bypass reproduces against the pristine goat-flow 1.15.1 template at `/home/devgoat/projects/goat-flow/workflow/hooks/`, so every port and every consumer of that release carries it. The local fix diverges from the template on purpose; see the managed-hook divergence footgun above before running `install` or `hooks sync`.

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
