---
category: performance
last_reviewed: 2026-08-22
---

# Performance patterns

## Pattern: pair the perf harness with a warmed in-process profile

**Context:** CLI-level runs include Node/tsx startup, which can hide scanner hot paths when the workload is small.

**Approach:** Use `scripts/test-performance.sh --matrix --runs 5` for the public before/after proof, then isolate scanner CPU with a warmed import loop such as `node --import tsx --input-type=module -e 'import { analyse } from "./src/cli.ts"; for (let i = 0; i < 100; i += 1) analyse({ paths: ["src"], format: "json", failOn: "none", noConfig: true, noBaseline: true });'`. If the CLI harness improves but the import loop does not, the change probably only affects startup or output noise. If both improve, the scanner path changed.

## Pattern: Degrade deep source analysis and bind its performance baseline

**Created:** 2026-08-22

**Evidence:** ACTUAL_MEASURED

**Context:** TypeScript was the reference port for bounded analysis, but its contract had to be explicit: either the 20,000-line or 2,000,000-byte limit drops masking, block, AST, and flow work without excluding the script from raw-text checks or analysed-file counts.

**Approach:** `src/analyser.ts` (search: `deepScanBudgetDiagnostic`) classifies scripts before applying the paired limits, emits `bounded-deep-scan`, and passes `isWithinDeepScanBudget` to `analyseSource`. Keep text-level rules outside the guarded script block and allow project-source retention only when the same budget diagnostic is absent. `src/config.ts` (search: `applyDeepScanBudgetOverride`) applies the CLI value after config so the override is atomic and may disable the budget.

**Measurement integrity:** `scripts/test-performance.sh` records host, Node, Git, runtime-source, live-wrapper, and harness identities in `scripts/performance-baselines/linux-x86_64.json`. The 12-cell baseline's runtime-source and wrapper digests match the source-bound M11 cohort run.

**Verification:** `src/scan-surface.test.ts` (search: `bounded deep-scan diagnostics are visible in every supported report surface`) protects boundary, retention, non-code, precedence, disable, and visibility behavior; `src/hook-contract.test.ts` (search: `hook projects bounded deep-scan diagnostics`) protects non-fatal hook projection.
