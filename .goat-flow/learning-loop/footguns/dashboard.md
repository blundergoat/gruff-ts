---
category: dashboard
last_reviewed: 2026-11-23
hallucination-risk: high
---

# Dashboard footguns (`src/dashboard.ts`, `src/report-html.ts`)

The `dashboard` subcommand boots an HTTP server that re-runs the analyser. Three properties make it look safer than it is.

## Footgun: `/scan` mutates `process.cwd()` via `chdir()`

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-11-23 | **Evidence:** OBSERVED

`renderDashboardScan` (`src/dashboard.ts`, search: `function renderDashboardScan`) serves `/scan` by capturing `cwd()`, calling `chdir(input.root)`, running `analyse({...})`, and restoring the previous cwd in a `finally`. This is process-global state. Two concurrent `/scan` requests interleave their `chdir`/`analyse`/`chdir-back` and produce findings for the wrong project root, with no error.

Node's HTTP server does not concurrently *execute* JS, but `analyse` is synchronous start-to-finish (`DashboardAnalyse` returns an `AnalysisReport`, not a Promise), so today the race is suppressed by the event loop. The trap is: any change that makes `analyse` return a Promise (e.g., switching to async file reads) instantly opens the race. If you go async, also drop `chdir` in favour of passing `projectRoot` through the call chain.

## Footgun: `projectRoot` is read from query string and passed straight to `chdir`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`/scan?projectRoot=...` (`src/dashboard.ts`, search: `function dashboardRouteInput`) accepts any path the operator supplies and `chdir`s to it. This is safe only as "trusted local user": `assertLoopbackHost` (`src/dashboard.ts`, search: `function assertLoopbackHost`) refuses any host other than `127.0.0.1` or `localhost` before the listener opens, so `--host 0.0.0.0` now fails instead of exposing a remote "scan any directory on the host" service. Treat that guard as the only thing standing between this endpoint and arbitrary filesystem traversal; never relax it without first constraining `projectRoot`.

## Footgun: HTML output is concatenated, not templated

**Status:** active | **Created:** 2026-05-10 | **Updated:** 2026-11-23 | **Evidence:** OBSERVED

Every dashboard page is a template-literal string in `src/report-html.ts`: `dashboardHomeHtml` renders `/`, `renderHtml` renders a successful `/scan`, and `dashboardErrorHtml` renders a failed one. `escapeHtml` (`src/report-html.ts`, search: `function escapeHtml`) is applied to user-controlled values (`projectRoot`, scan path, error messages, finding messages, file paths), but every NEW field added to a page MUST be wrapped in `escapeHtml` explicitly - there is no template-engine default. Forgetting `escapeHtml` on a new field is a stored-XSS-shaped bug visible only when the dashboard is rendered.
