---
category: sensitive-data
last_reviewed: 2026-05-13
hallucination-risk: high
---

# Sensitive-data footguns (`src/cli.ts`)

## Footgun: secret scanners scan analyzer source and fixtures too

**Status:** active | **Created:** 2026-05-13 | **Evidence:** OBSERVED

`analyseSensitiveData` (`src/cli.ts`, search: `function analyseSensitiveData`) runs against every discovered text/config/TypeScript file, including `src/cli.ts`, `src/cli.test.ts`, fixtures, and lockfiles. New literal detectors can therefore flag their own regex text, test fixture values, or package integrity hashes unless they include explicit non-candidates.

When adding or expanding secret-like rules, include non-candidate coverage for detector names, documentation strings, and standard package integrity formats such as `sha512-...`; then inspect `./bin/gruff-ts analyse . --format=html --fail-on=none --no-config` for obvious redacted false positives before ticking the milestone.
