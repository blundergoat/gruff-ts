# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting A Vulnerability

Do not file a public issue with exploit details, secrets, tokens, private source
paths, or sensitive scan output.

Use the project's private vulnerability reporting channel if one is enabled on
the public repository. If private reporting is not available yet, contact the
maintainer through the preferred private channel before posting details
publicly.

Please include:

- A short description of the issue.
- A minimal reproduction when possible.
- Affected command or output format.
- Whether sensitive data is exposed in findings, reports, dashboard output, or
  logs.

## Security Boundaries

- The dashboard is a local developer tool. It binds to `127.0.0.1` by default.
  Binding it to `0.0.0.0` can expose filesystem scanning to the network.
- Sensitive-data rules should render redacted previews only.
- HTML output is generated without a template engine; new interpolated fields
  must be escaped.
- The scanner is heuristic and is not a vulnerability scanner or dependency
  advisory database.

## Disclosure Expectations

The maintainer should acknowledge valid private reports, assess impact, and
coordinate a fix before public disclosure. Public advisories should include the
affected versions, fixed version, and mitigation.
