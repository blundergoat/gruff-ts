# ADR-003: Single File Scan Inputs

**Status:** Implemented
**Date:** 2026-05-19
**Author(s):** Codex, user
**Ticket/Context:** User request to make single-file scanning explicit

## Decision

`gruff-ts` treats a supported file path passed to `analyse [paths...]`, `summary [paths...]`, or `report [paths...]` as a first-class scan input.

Single-file scans use the same analysis pipeline, finding shape, fingerprint generation, baseline matching, output formats, and `--fail-on` semantics as directory scans. They do not require a separate `--file` flag or a separate command.

Explicit file operands are resolved by discovery before recursive directory walking. If the file exists and has a supported script or config/text extension, it is added directly to the scan set. Directory ignore rules are still applied while walking directories, but they must not prevent an explicitly supplied supported file from being scanned.

This decision does not change `Finding`, `gruff.analysis.v1`, `gruff.baseline.v1`, `gruff.hotspot.v1`, dashboard wire format, `package.json`, or `tsconfig.json`.

## Context

The CLI already exposes variadic path operands through `src/cli-program.ts` (`registerAnalyseCommand`, `registerReportCommand`, `registerSummaryCommand`) with the help text "Files or directories to analyse."

Discovery already routes each operand through `src/discovery.ts` (`discoverSources`, `discoverSourceInput`). `discoverSourceInput` checks `stats.isFile()` before directory walking and calls `pushSourceFile` directly for supported files.

The user asked to add single-file scan support after switching branches, then asked for this ADR. Recording the policy prevents future refactors from treating file operands as incidental directory-discovery behavior or replacing them with a new command shape that would fragment the CLI contract.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Require users to scan a parent directory and filter findings externally | Small editor, hook, and CI workflows must over-scan, then post-process results. This adds noise and makes exit codes harder to reason about. | Rejected. A direct file operand is simpler and deterministic. |
| Add a separate `--file <path>` option | The same path can be supplied through two public surfaces, which creates precedence and validation questions without improving behaviour. | Rejected. `paths...` already models files and directories. |
| Add a dedicated `analyse-file` command | Output formats, baseline handling, summary/report parity, and dashboard routing would need duplicate command policy. | Rejected. Single-file scans should stay inside the normal analysis pipeline. |
| Treat supported file operands as first-class scan roots | The existing CLI stays compact, file and directory scans share one implementation, and users can scan one file or many paths with the same command. | Accepted. This preserves deterministic reports and stable fingerprints without schema churn. |

## Consequences

Discovery refactors must keep the `stats.isFile()` path before directory walking and must preserve direct `pushSourceFile` handling for explicit file operands.

Tests should keep at least one explicit-file regression at the analysis or CLI boundary. Useful assertions include `paths.analysedFiles === 1`, the finding `filePath` matching the explicit operand, and ignored-path reporting staying empty for a directly supplied file.

Documentation and help text should continue to describe path operands as files or directories. Examples may show a single file, multiple files, directories, or mixed path lists, but should not imply directory-only scanning.

## Reversibility

This is technically reversible but should be treated as a public CLI contract. Removing direct file operands would break editor integrations, pre-commit hooks, targeted CI scans, and scripts that rely on one-file exit codes.

Revisit only if the CLI path model is redesigned with an explicit migration plan. Any revisit must preserve report schema versions and stable finding fingerprints unless the user separately approves schema or fingerprint churn.
