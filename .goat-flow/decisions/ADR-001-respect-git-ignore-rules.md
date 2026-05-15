# ADR-001: Respect Git Ignore Rules During Discovery

**Status:** Accepted
**Date:** 2026-05-15
**Author(s):** Codex, user
**Ticket/Context:** `.goat-flow/tasks/0.1/M14-respect-gitignore-scan-scope.md`

## Decision

`gruff-ts` recursive discovery will respect repository Git ignore rules before adding supported source and config inputs to an analysis run.

Project `paths.ignore` configuration remains an additional policy layer for deliberately excluded scan surfaces. It does not replace repository ignore semantics.

The scanner must keep deterministic ordering and stable finding fingerprints for the discovered input set. The decision does not require changing report schemas, baseline schemas, the `Finding` shape, dashboard wire format, `package.json`, or `tsconfig.json`.

## Context

Current discovery is implemented in `src/cli.ts` (`function discoverSources`, `function walk`) using a hardcoded default directory list plus `.gruff.yaml` `paths.ignore`. It does not currently apply repository ignore rules while walking directories.

That creates a mismatch between the desired repository-level scan and the actual scan surface. Security and configuration rubrics should be able to inspect committed repository surfaces broadly, but generated or local-only material should not have to be excluded by broad project config rules that also hide useful committed config from those rubrics.

M14 records the implementation plan for this discovery change. The durable policy is captured here so future cleanup does not reintroduce broad path exclusions as a substitute for repository ignore handling.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Keep only hardcoded default ignores and `paths.ignore` | Broad config exclusions become the only way to avoid local/generated noise, which can hide useful repository config from security and configuration checks. | Rejected. It makes project config carry a responsibility that belongs in discovery. |
| Shell out to Git for every discovery run | Runtime behaviour depends on Git availability and repository state, and scanning non-Git directories becomes less predictable. | Rejected for normal scanning. A Git-based comparison can still be used in tests or smoke checks. |
| Parse repository ignore rules during discovery | Local/generated noise is skipped while useful committed surfaces remain discoverable. | Accepted. This keeps scan scope aligned with repository intent without adding a runtime dependency. |
| Add rule- or pillar-specific path scopes first | It would solve a broader product problem but delays the simpler discovery invariant. | Deferred. It can build on this decision later. |

## Reversibility

This is a two-way door if implemented behind the existing discovery path with focused tests. It can be revisited if local parser behaviour proves too divergent from Git semantics, if users need a profile that scans ignored material by default, or if a future dependency policy allows a proven ignore-matching library.

Rollback is to remove the repository-ignore layer from discovery and restore explicit project config exclusions for any affected paths. Any rollback must preserve schema versions and baseline matching semantics.
