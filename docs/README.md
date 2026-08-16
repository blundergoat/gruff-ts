# gruff-ts docs

Use these docs with the top-level README for the stable user-facing surface.

## Core Docs

- [Philosophy](philosophy.md) - what gruff-ts optimises for and why it governs AI-generated code for human sign-off.
- [Coding-agent hook](agent-hook.md) - wiring gruff-ts as a forcing function on agent output: changed-region scans, gate levels, and CI.
- [Configuration](configuration.md) - config discovery, schema, allowlists, and rule overrides.
- [Rules](rules.md) - rule IDs, severities, thresholds, and remediation guidance.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [CI Integration](ci-integration.md) - GitHub Actions, SARIF upload, baselines, and diff scans.
- [Dashboard](dashboard.md) - local dashboard flags and safety model.

## Extra Docs

- [Reports And CI](reports-and-ci.md) - combined reporting and CI details retained for existing links.

## Shared Contract

`gruff-ts` follows the cross-language naming and CLI expectations shared across the gruff family (`gruff-go`, `gruff-php`, `gruff-py`, `gruff-rs`). It keeps its `summary` analysis flags as documented extensions while also supporting the common `--format` and `--top` summary surface.
