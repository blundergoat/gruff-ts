# Architecture

## System Overview

`gruff-ts` is a dependency-light Node.js/ESM CLI that statically analyses TypeScript/JavaScript projects and common config/text assets, then emits findings, reports, baselines, SARIF, and rule catalogue metadata. The 0.1.2 release exposes 120 rules across 11 public pillars. The runtime is split across focused modules under `src/`, with `src/cli.ts` (19 lines) as a thin shell that wires `analyse` from `src/analyser.ts` into the commander program built by `src/cli-program.ts`. The dependency surface stays minimal - `commander` + `tsx` only - and baselines stay deterministic byte-stable JSON.

Seven primary command surfaces, registered in `src/cli-program.ts`:`buildProgram`:

- **`analyse`** - discover files, run rules, print/serialise findings, set exit code from `--fail-on`. Pipeline orchestrator lives in `src/analyser.ts`:`analyse`.
- **`report`** - same pipeline, render-only output (`html` or `json`), optionally write to disk via `--output`; HTML uses the self-contained dark inspection-report renderer in `src/report-renderers.ts`.
- **`list-rules`** - print rule descriptor metadata from the catalogue in `src/rules.ts`:`ruleDescriptors`; renderer in `src/rule-list.ts`.
- **`dashboard`** - boot a local HTTP server (`src/dashboard.ts`:`startDashboard`) with a dark iframe shell and controls panel that re-runs `analyse` on demand.
- **`summary`** - run the same scanner once and render a compact per-pillar/top-rule/top-offender digest without per-finding output.
- **`completion`** - emit lightweight shell completion scripts for bash, zsh, or fish (generated in `src/rule-list.ts`).
- **`list`** - print the Symfony-style command catalogue used when no command is supplied.

`bin/gruff-ts` is a POSIX shell shim that resolves the local `tsx` loader and execs `node --import <tsx-loader> src/cli.ts "$@"`.

## Request Flow (analyse path)

1. `src/cli-program.ts`:`buildProgram` wires Commander; the `.action(...)` callback for `analyse` calls `normalizeOptions` then the `analyse` callback passed in by `src/cli.ts`.
2. `src/analyser.ts`:`analyse` - load config (`src/config.ts`:`loadConfig`) → discover sources (`src/discovery.ts`:`discoverSources`) → optional git-diff filter → per-file `src/source-text.ts`:`parseDiagnostics` + `src/analyser.ts`:`analyseSource` → project-level `src/analyser.ts`:`analyseProjectIndex` → optional baseline apply / generate (`src/baseline.ts`) → sort + dedupe by `fingerprint` → optional history append → return `AnalysisReport`.
3. `src/analyser.ts`:`analyseSource` fans out to `src/analyser.ts`:`analyseTextRules` (file-length, TODO density, sensitive data via `src/sensitive-data-rules.ts`, project config via `src/project-config-rules.ts`) and, for TypeScript/JavaScript extensions, `src/analyser.ts`:`analyseTypeScriptRules` (function blocks, line patterns, class rules, dead code, doc rules, comment quality, declared-identifier inventory).
4. `src/project-rules.ts`:`buildProjectIndex` plus `analyseArchitectureRules` and `analyseTestAdequacyRules` build a deterministic index from already-read discovered files for cross-file rules: relative import depth, simple cycles, large-module concentration, missing-nearby-tests.
5. `src/blocks.ts`:`functionBlocks` is a regex-based lexer over four function-shape patterns; `src/analyser.ts`:`analyseBlocks` applies size/complexity/naming/doc rules per block via `src/blocks.ts`:`analyseBlockRules`, with parameter-naming fanout in `src/analyser.ts`:`pushParameterNamingFindings` (delegates to `src/naming-pushers.ts`).
6. **Per-file declared-identifier inventory (M37):** `src/class-rules.ts`:`collectDeclaredIdentifiers` builds one inventory per file from declarations + `FunctionBlock.params` + interface fields; `analyseInconsistentCasing` and `analyseAcronymCase` consume the same inventory (no second pass).
7. `src/report-renderers.ts`:`renderReport` switches on `OutputFormat`; severity-to-exit mapping lives in `src/cli-program.ts`:`exitFor` (2 if any diagnostic, 1 if `--fail-on` tripped, else 0).

## Trust Boundaries

`gruff-ts` is a developer CLI, not a network service - there is no auth model. Two surfaces still warrant care:

- **Sensitive-data scan** (`src/sensitive-data-rules.ts`:`analyseSensitiveData`). Matches AWS keys, PEM private-key blocks, JWTs, DB-URL passwords, vendor API-key prefixes. Raw matches are passed through the in-module `redact` helper before reaching `metadata.preview`; raw secret values must never appear in `Finding.message` or any rendered output.
- **Dashboard server** (`src/dashboard.ts`:`startDashboard`). Default bind is loopback `127.0.0.1` on port 8767. The root route serves the iframe-plus-controls shell; the `/scan` route reads `projectRoot` and `path` from query string and runs `analyse` against them, swapping `process.cwd()` via `chdir` and back in `finally`. It must stay loopback-only by default; rebinding to `0.0.0.0` would expose the filesystem read/scan to the LAN.
- **`--diff` mode** shells out to `git diff --name-only` via `execFileSync` (`src/findings-helpers.ts`:`changedFiles`). Argument vector is constructed from a fixed allowlist (`staged`/`working-tree`/`unstaged`) plus the user-supplied ref; the ref is passed as a separate argv element, not interpolated.

## Data Flow

State is filesystem-only - there is no database, queue, or external API.

- **Inputs:** source files matched by `src/discovery.ts`:`discoverSources` with hardcoded ignore set in `src/discovery.ts`:`isDefaultIgnoredDir`; optional `.gruff-ts.yaml` config; optional baseline JSON; optional history JSON.
- **Outputs:** stdout (`text`/`json`/`html`/`markdown`/`github`/`hotspot`/`sarif`), self-contained dark HTML reports (also stdout unless `report --output`), compact summary text, shell completion scripts, the local dashboard shell/scan HTML, `list-rules` text or unversioned JSON catalogue output, `gruff-baseline.json` when `--generate-baseline` is set, `.gruff-history.json` when `--history-file` is passed.
- **Schemas (public contract):** `gruff.analysis.v2` (the `AnalysisReport`), `gruff.baseline.v1` (the suppression file written by `src/baseline.ts`:`writeBaseline`), `gruff.hotspot.v1` (the trimmed top-offenders payload in `src/report-renderers.ts`'s `hotspot` branch). Bumping any of these is a breaking change for downstream consumers.
- **Determinism:** `Finding.fingerprint` (sha256 of `ruleId\0filePath\0line\0symbol`, sliced to 16 chars in `src/findings.ts`:`makeFinding`) is the dedupe and baseline-match key. Findings are sorted by `(filePath, line, ruleId, message)` before dedupe so the report bytes are stable across runs.

## Deployment / Operations

- Distributed as an npm package (`package.json` declares `bin.gruff-ts → ./bin/gruff-ts`). License is MIT.
- CI lives in `.github/workflows/ci.yml` and runs on pushes/PRs to `main` and `dev`: install with `npm ci`, run `npm run check`, then self-scan with `./bin/gruff-ts analyse . --fail-on=advisory`.
- Local validation gate: `npm run check` runs `tsc --noEmit && npm test` (Node test runner via `node --import tsx --test src/**/*.test.ts`). Focused `src/*.test.ts` files cover analyser rules, baselines, determinism, rule descriptors, console command parity, summary output, report rendering, dashboard shell anchors, SARIF, config, and JSON schema markers.
- Release validation helpers live in `scripts/`: `bump-version.sh`, `check.sh`, `preflight-checks.sh`, `start-dev.sh`, and `test-performance.sh`.
- Runtime is ESM (`"type": "module"`) and TypeScript 5.9 with `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and `allowImportingTsExtensions`.
