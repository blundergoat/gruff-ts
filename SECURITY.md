# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.6.x | Yes |
| 0.5.x and earlier | No |

## Reporting A Vulnerability

Do not open a public issue containing exploit details, secrets, tokens, private paths, or sensitive scan output.

Use GitHub's private vulnerability reporting on this repository if it is enabled. Otherwise, reach out to the maintainer privately before posting details publicly.

Include what helps reproduce and scope the report:

- A short description of the issue and a minimal reproduction, if you have one.
- The command or output format affected.
- Whether sensitive data leaked into findings, reports, dashboard output, or logs.
- Whether a baseline, SARIF upload, GitHub annotation output, or the dashboard `/scan` endpoint is involved.

## Security Boundaries

- The dashboard is a local tool that binds to `127.0.0.1` by default. Binding it to `0.0.0.0` exposes filesystem scanning to the network without authentication.
- Sensitive-data findings print fixed category markers rather than matched secret characters or secret-derived lengths.
- HTML output is built without a template engine, so every interpolated value must be HTML-escaped.
- `gruff-ts` runs static heuristics; it is not a vulnerability scanner or dependency advisory database.
- Baselines suppress reviewed findings by line-free identity and count, and sensitive-data findings can never be baselined. For a security gate that ignores adoption baselines, run `gruff-ts analyse . --no-baseline --fail-on=warning` (all `sensitive-data.*` rules default to `warning`, so `--fail-on=error` alone will not fail on them).

## Disclosure Process

Valid private reports are acknowledged, triaged for impact, and patched before public disclosure. Public advisories list affected versions, the fixed version, and mitigation steps.
