# Security Policy

This repo defines the local security boundaries for `gruff-ts` release work.
`goat-security` may read this file as the canonical repo-local policy hook.
Nothing here suppresses observed exploit paths or downgrades verified findings.

## Optional Inputs

- Approved crypto choices: no project-specific crypto allowlist.
- Auth model assumptions: CLI has no authentication model; dashboard is a
  local developer tool only.
- Secret classes and handling rules: sensitive-data matches must be redacted in
  findings, reports, dashboard HTML, GitHub output, SARIF, and logs.
- Deployment boundaries: dashboard defaults to `127.0.0.1:8767`; binding to
  `0.0.0.0` exposes unauthenticated filesystem scanning and must be treated as
  a user-owned risk.
- Baseline expectations: security-focused CI should prefer
  `gruff-ts analyse . --no-baseline --fail-on=error` so an adoption baseline
  cannot hide error-severity security findings.
- Forbidden third-party services/actions: no network-backed vulnerability
  lookup or telemetry is approved for the 0.1.x line.
