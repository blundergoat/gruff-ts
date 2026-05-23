---
category: rule-scanners
last_reviewed: 2026-05-17
---

# Rule scanner footguns

## Footgun: `process-exec` matches `RegExp.exec` source text

**Status:** active | **Created:** 2026-05-17 | **Evidence:** OBSERVED

`processExecCandidate` (`src/cli.ts`, search: `function processExecCandidate`) matches bare `exec(`, `spawn(`, or `execFile(` in masked code. That intentionally catches child-process helpers, but it also catches ordinary `RegExp.exec(...)` calls because the current regex does not require a child-process receiver or import context.

When adding hot-path regex loops, avoid writing `.exec(` in scanner source unless you also refine the rule. This performance pass used bracket dispatch (`src/text-scans.ts`, search: `globalPattern["exec"]`) to keep the source self-scan from adding `security.process-exec` noise.
