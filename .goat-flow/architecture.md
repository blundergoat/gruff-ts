# Architecture

## System Overview

`gruff-ts` is a single-binary Node.js CLI that statically analyses TypeScript/JavaScript projects and emits findings, reports, baselines, and rule catalogue metadata. The whole runtime lives in one file — `src/cli.ts` (~3.4k lines) — so the "boundary" between subsystems is *function clusters within one module*, not separate services. That choice is deliberate: keeps the dependency surface to `commander` + `tsx` only, ships as a single `npm i -g` install, and lets baselines be deterministic byte-stable JSON.

Four top-level command surfaces, all defined in `buildProgram` (in `src/cli.ts`, search: `function buildProgram`):

- **`analyse`** — discover files, run rules, print/serialise findings, set exit code from `--fail-on`.
- **`report`** — same pipeline, render-only output (`html` or `json`), optionally write to disk via `--output`; HTML uses the self-contained dark inspection-report renderer in `renderHtml`.
- **`list-rules`** — print rule descriptor metadata from the in-file catalogue (`RULE_DESCRIPTORS` / `renderRuleList` in `src/cli.ts`, search: `const RULE_DESCRIPTORS`).
- **`dashboard`** — boot a local HTTP server (`startDashboard` in `src/cli.ts`, search: `function startDashboard`) with a dark iframe shell and controls panel that re-runs `analyse` on demand.

`bin/gruff-ts` is a POSIX shell shim that resolves the local `tsx` loader and execs `node --import <tsx-loader> src/cli.ts "$@"`.

## Request Flow (analyse path)

1. `buildProgram` (search: `function buildProgram`) wires Commander; the `.action(...)` callback for `analyse` calls `normalizeOptions` then `analyse`.
2. `analyse(options)` (search: `export function analyse`) — load config → discover sources → optional git-diff filter → per-file `parseDiagnostics` + `analyseSource` → project-level `analyseProjectIndex` → optional baseline apply / generate → sort + dedupe by `fingerprint` → optional history append → return `AnalysisReport`.
3. `analyseSource` (search: `function analyseSource`) fans out to `analyseTextRules` (file-length, TODO density, sensitive data) and, for TypeScript/JavaScript extensions, `analyseTypeScriptRules` (function blocks, line patterns, class rules, dead code).
4. `analyseProjectIndex` (search: `function analyseProjectIndex`) builds a deterministic index from already-read discovered files for cross-file architecture/test-adequacy rules such as relative import depth, simple cycles, large-module concentration, and nearby-test checks.
5. `functionBlocks` (search: `function functionBlocks`) is a regex-based lexer over four function-shape patterns; `analyseBlocks` (search: `function analyseBlocks`) applies size/complexity/naming/doc rules per block.
6. `renderReport` (search: `function renderReport`) switches on `OutputFormat`; `exitFor` (search: `function exitFor`) maps severities to exit codes (2 if any diagnostic, 1 if `--fail-on` tripped, else 0).

## Trust Boundaries

`gruff-ts` is a developer CLI, not a network service — there is no auth model. Two surfaces still warrant care:

- **Sensitive-data scan** (`analyseSensitiveData` in `src/cli.ts`, search: `function analyseSensitiveData`). Matches AWS keys, PEM private-key blocks, JWTs, DB-URL passwords, vendor API-key prefixes. Raw matches are passed through `redact` (search: `function redact`) before reaching `metadata.preview`; raw secret values must never appear in `Finding.message` or any rendered output.
- **Dashboard server** (`startDashboard`). Default bind is loopback `127.0.0.1` on port 8767. The root route serves the iframe-plus-controls shell; the `/scan` route reads `projectRoot` and `path` from query string and runs `analyse` against them, swapping `process.cwd()` via `chdir` and back in `finally`. It must stay loopback-only by default; rebinding to `0.0.0.0` would expose the filesystem read/scan to the LAN.
- **`--diff` mode** shells out to `git diff --name-only` via `execFileSync` (`changedFiles` in `src/cli.ts`, search: `function changedFiles`). Argument vector is constructed from a fixed allowlist (`staged`/`working-tree`/`unstaged`) plus the user-supplied ref; the ref is passed as a separate argv element, not interpolated.

## Data Flow

State is filesystem-only — there is no database, queue, or external API.

- **Inputs:** source files matched by `discoverSources` (search: `function discoverSources`) with hardcoded ignore set in `isDefaultIgnoredDir` (search: `function isDefaultIgnoredDir`); optional `.gruff.json`, `.gruff.yaml`, or `.gruff.yml` config; optional baseline JSON; optional history JSON.
- **Outputs:** stdout (`text`/`json`/`markdown`/`github`/`hotspot`), self-contained dark HTML reports (also stdout unless `report --output`), the local dashboard shell/scan HTML, `list-rules` text or unversioned JSON catalogue output, `gruff-baseline.json` when `--generate-baseline` is set, `.gruff-history.json` when `--history-file` is passed.
- **Schemas (public contract):** `gruff.analysis.v1` (the `AnalysisReport`), `gruff.baseline.v1` (the suppression file written by `writeBaseline`, search: `function writeBaseline`), `gruff.hotspot.v1` (the trimmed top-offenders payload in `renderReport`'s `hotspot` branch). Bumping any of these is a breaking change for downstream consumers.
- **Determinism:** `Finding.fingerprint` (sha256 of `ruleId\0filePath\0line\0symbol`, sliced to 16 chars in `makeFinding`, search: `function makeFinding`) is the dedupe and baseline-match key. Findings are sorted by `(filePath, line, ruleId, message)` before dedupe so the report bytes are stable across runs.

## Deployment / Operations

- Distributed as an npm package (`package.json` declares `bin.gruff-ts → ./bin/gruff-ts`). License is `proprietary`.
- No CI workflow files (the `.github` directory is absent). `scripts/check.sh` and `scripts/start-dev.sh` are the only orchestration entry points beyond `npm run`.
- Local validation gate: `npm run check` runs `tsc --noEmit && npm test` (Node test runner via `node --import tsx --test`). `src/cli.test.ts` covers analyser rules, baselines, determinism, rule descriptors, report rendering, dashboard shell anchors, and JSON schema markers.
- Runtime targets Node 25 / ESM (`"type": "module"`) and TypeScript 5.9 with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `allowImportingTsExtensions`.
