---
category: sensitive-data
last_reviewed: 2026-08-11
hallucination-risk: high
---

# Sensitive-data footguns (`src/sensitive-data-rules.ts`)

## Footgun: secret scanners scan analyzer source and fixtures too

**Status:** active | **Created:** 2026-05-13 | **Evidence:** OBSERVED

`analyseSensitiveData` (`src/sensitive-data-rules.ts`, search: `function analyseSensitiveData`) runs against every discovered text/config/TypeScript file, including the analyser's own sources, `src/cli.test.ts`, fixtures, and lockfiles. New literal detectors can therefore flag their own regex text, test fixture values, or package integrity hashes unless they include explicit non-candidates.

When adding or expanding secret-like rules, include non-candidate coverage for detector names, documentation strings, and standard package integrity formats such as `sha512-...`; then inspect `./bin/gruff-ts analyse . --format=html --fail-on=none --no-config` for obvious redacted false positives before ticking the milestone.

## Footgun: redaction policy silently rewrites hook finding identity

**Status:** active | **Created:** 2026-08-10 | **Evidence:** OBSERVED
**Decision changed:** Treat any change to `redact()` output as a change to hook identity, and check same-line discrimination before shipping it.
**Trigger phase:** ACT

`stableIdentityComponent` (`src/hook-contract.ts`, search: `function stableIdentityComponent`) keys symbol-less line findings on the finding message, and `pushSensitiveFinding` (`src/sensitive-data-rules.ts`, search: `function pushSensitiveFinding`) builds that message from `redact()` output. Finding identity therefore depends on the redaction format, and nothing in either file states the coupling.

Raising the full-mask threshold to 24 characters made every secret shorter than that render as mask-plus-length. AWS access key ids are always 20 characters, so two of them on one line produced the same preview, the same message, and the same identity. The two findings became byte-identical on the `gruff.hook.v1` wire, and a consumer following the contract's own "track by stable identity" guidance collapsed a second real credential into the first.

The coupling crosses milestone boundaries, so the assumption that justified the same-line work was already false by the time the release shipped. When a redaction, preview, or message format changes, scan a fixture with two short same-line secrets and confirm the hook still reports two distinct `stableIdentity` values.
