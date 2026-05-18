# Changelog

All notable changes to `gruff-ts` are documented here.

This project follows semantic versioning once public releases begin.

## [0.1.0] - 2026-05-15

### Added

- Initial public release of the `gruff-ts` CLI.
- Static analysis for TypeScript, JavaScript, package metadata, and common
  config files.
- 86 rule descriptors across 11 public pillars: size, complexity, dead-code,
  waste, naming, documentation, modernisation, security, sensitive-data,
  test-quality, and design.
- Stable finding fingerprints for dedupe, baselines, and repeatable reports.
- Output formats: text, JSON, HTML, Markdown, GitHub annotations, and hotspot
  JSON.
- `report` command for static HTML and JSON reports.
- `list-rules` command for rule catalogue metadata in text or JSON form.
- Symfony-style command menu with ANSI-coloured section headers, options, and
  command names.
- Local dashboard with a dark iframe report shell and controls panel.
- Config loading from `.gruff-ts.yaml`.
- Baseline generation/application using `gruff.baseline.v1`.
- Changed-file filtering with `--diff`.
- Local score history with `--history-file`.

### Security

- Sensitive-data findings use redacted previews.
- Dashboard binds to `127.0.0.1` by default.

### Notes

- Public schema strings are `gruff.analysis.v1`, `gruff.baseline.v1`, and
  `gruff.hotspot.v1`.
