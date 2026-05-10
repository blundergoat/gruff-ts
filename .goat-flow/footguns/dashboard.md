---
category: dashboard
last_reviewed: 2026-05-10
hallucination-risk: high
---

# Dashboard footguns (`src/cli.ts:startDashboard`)

The `dashboard` subcommand boots an HTTP server that re-runs the analyser. Three properties make it look safer than it is.

## Footgun: `/scan` mutates `process.cwd()` via `chdir()`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`startDashboard` (`src/cli.ts`, search: `function startDashboard`) handles `/scan` by capturing `cwd()`, calling `chdir(root)`, running `analyse({...})`, and restoring the previous cwd in a `finally`. This is process-global state. Two concurrent `/scan` requests interleave their `chdir`/`analyse`/`chdir-back` and produce findings for the wrong project root, with no error.

Node's HTTP server does not concurrently *execute* JS, but `analyse` is synchronous start-to-finish, so today the race is suppressed by the event loop. The trap is: any change that makes `analyse` return a Promise (e.g., switching to async file reads) instantly opens the race. If you go async, also drop `chdir` in favour of passing `projectRoot` through the call chain.

## Footgun: `projectRoot` is read from query string and passed straight to `chdir`

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

`/scan?projectRoot=...` (in `src/cli.ts`, search: `url.searchParams.get("projectRoot")`) accepts any path the operator supplies and `chdir`s to it. The default bind is `127.0.0.1:8767`, so this is "trusted local user" — but if anyone rebinds via `--host 0.0.0.0`, the dashboard becomes a remote-controlled "scan any directory on the host" service. Treat the bind address as the only thing standing between this endpoint and arbitrary filesystem traversal; document it whenever you touch the `dashboard` command's CLI surface.

## Footgun: HTML output is concatenated, not templated

**Status:** active | **Created:** 2026-05-10 | **Evidence:** OBSERVED

The `/` page and the `/scan` HTML response in `startDashboard` are built by string concatenation. `escapeHtml` is applied to user-controlled values (`projectRoot`, finding messages, file paths), but every NEW field added to the page MUST be wrapped in `escapeHtml` explicitly — there is no template-engine default. The same applies to `renderHtml` (`src/cli.ts`, search: `function renderHtml`). Forgetting `escapeHtml` on a new field is a stored-XSS-shaped bug visible only when the dashboard is rendered.
