---
category: hooks
last_reviewed: 2026-08-11
---

# Hooks footguns

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
