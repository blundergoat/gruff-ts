---
category: performance
last_reviewed: 2026-05-17
---

# Performance patterns

## Pattern: pair the perf harness with a warmed in-process profile

**Context:** CLI-level runs include Node/tsx startup, which can hide scanner hot paths when the workload is small.

**Approach:** Use `scripts/test-performance.sh --matrix --runs 5` for the public before/after proof, then isolate scanner CPU with a warmed import loop such as `node --import tsx --input-type=module -e 'import { analyse } from "./src/cli.ts"; for (let i = 0; i < 100; i += 1) analyse({ paths: ["src"], format: "json", failOn: "none", noConfig: true, noBaseline: true });'`. If the CLI harness improves but the import loop does not, the change probably only affects startup or output noise. If both improve, the scanner path changed.
