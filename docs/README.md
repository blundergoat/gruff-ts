# gruff-ts docs

Reference guides for the `gruff-ts` CLI, configuration, rules, and reports.

## Core Docs

- [Philosophy](philosophy.md) - why `gruff-ts` optimises for the human reviewing AI-generated code.
- [Coding-agent hook](agent-hook.md) - wiring `gruff-ts` onto agent edits with changed-region scans, gate levels, and CI.
- [Configuration](configuration.md) - config discovery, schema, profiles, ignore rules, allowlists, and `sensitiveExclusions`.
- [Rules](rules.md) - the full rule catalogue grouped by pillar, with defaults, thresholds, and confidence evidence.
- [Output Formats](output-formats.md) - text, JSON, HTML, Markdown, GitHub annotations, hotspot, and SARIF.
- [CI Integration](ci-integration.md) - GitHub Actions workflows, SARIF upload, baselines, and diff scans.
- [Dashboard](dashboard.md) - local browser dashboard options and loopback safety model.
- [Upgrading](../UPGRADING.md) - `0.6.0` breaking changes, migration commands, and rollback steps.

## Extra Docs

- [Reports And CI](reports-and-ci.md) - combined reporting and CI page retained for older links; the core pages above own each topic.

## Maintainer Docs

- [Releasing](releasing.md) - maintainer release checklist (excluded from the npm package; also readable on [GitHub](https://github.com/blundergoat/gruff-ts/blob/main/docs/releasing.md)).

## Shared Contract

`gruff-ts` shares rule naming, JSON schemas, and CLI conventions with the sibling gruff ports (`gruff-go`, `gruff-php`, `gruff-py`, `gruff-rs`). It keeps `summary`'s analysis flags as documented extensions alongside the shared `--format` and `--top` surface.
