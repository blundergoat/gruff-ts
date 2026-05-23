# Changelog

## [0.1.0] - 2026-05-23

Initial public release of the `@blundergoat/gruff-ts` npm package.

- TypeScript/JavaScript code quality scanner: 121 rules across 11 pillars
  (complexity, dead-code, design, documentation, modernisation, naming,
  security, sensitive-data, size, test-quality, waste).
- CLI commands: `analyse`, `summary`, `report`, `list-rules`, `dashboard`,
  `completion`.
- Output formats: `text`, `json`, `html`, `markdown`, `github`, `hotspot`,
  `sarif`. Stable schemas: `gruff.analysis.v1`, `gruff.baseline.v1`,
  `gruff.hotspot.v1`.
- Baselines via stable per-finding fingerprints, `--diff` for changed-file
  scans, local dashboard on `127.0.0.1:8767`. Released under MIT.
