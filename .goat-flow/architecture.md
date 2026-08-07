# Architecture

## Intent

gruff-ts governs AI-generated code. Its reason for existing is the coding-agent hook: when an agent writes a change, gruff forces output a human who did not write it can sign off on - legible enough to verify by reading, secure where the reviewer's eye slips, and tested for real behaviour rather than padded with low-signal ceremony. The 11 pillars are means to that end: complexity, size, naming, and documentation serve verifiability; security and sensitive-data serve safety where review is weakest; test-quality serves honest tests over coverage theatre. Everything below - modules, schemas, determinism - is the machinery that makes those findings stable enough to gate an agent on. The hook is diff-scoped by design: an agent runs gruff on only the code it changed (`--diff` / `--since <ref>` / `--changed-ranges`, with `--changed-scope symbol|hunk`), so it fixes findings in its own change and a clean diff is never blocked by pre-existing findings elsewhere (see `docs/agent-hook.md`). See `docs/philosophy.md` for the product-level framing.

## System Overview

`gruff-ts` is a dependency-light Node.js/ESM CLI that statically analyses TypeScript/JavaScript projects and common config/text assets, then emits findings, reports, baselines, SARIF, and rule catalogue metadata. The current catalogue exposes 120 rules across 11 public pillars. The runtime is split across focused modules under `src/`, with `src/cli.ts` as a thin shell that wires `analyse` from `src/analyser.ts` into the commander program built by `src/cli-program.ts`. The three runtime dependencies have distinct jobs: `commander` owns the CLI, `tsx` launches the shipped TypeScript source, and `typescript` provides syntax-only parsing without type checking or emit. Baseline output is byte-stable; analysis reports are byte-stable after removing only the intentionally volatile `run.generatedAt` timestamp.

Eleven command surfaces are registered in `src/cli-program.ts`:`buildProgram`:

- **`analyse`** - discover files, run rules, print/serialise findings, set exit code from `--fail-on`. Pipeline orchestrator lives in `src/analyser.ts`:`analyse`.
- **`check-ignore`** - explain whether config, gitignore, or built-in policy excludes each path without running analysis.
- **`completion`** - emit lightweight shell completion scripts for bash, zsh, or fish.
- **`dashboard`** - boot a local HTTP server (`src/dashboard.ts`:`startDashboard`) with a report shell and controls that re-run `analyse` on demand.
- **`hook`** - emit the stable `gruff.hook.v1` coding-agent contract or its capability metadata.
- **`init`** - write a reviewable starter `.gruff-ts.yaml`, preserving supported user fields on `--force`.
- **`list`** - print the Symfony-style command catalogue used when no command is supplied.
- **`list-profiles`** - print bundled profile names, descriptions, and enabled-rule counts.
- **`list-rules`** - print rule descriptor metadata from `src/rules.ts`:`ruleDescriptors`; renderer lives in `src/rule-list.ts`.
- **`report`** - same pipeline, render-only output (`html` or `json`), optionally write to disk via `--output`; HTML uses the self-contained dark inspection-report renderer in `src/report-renderers.ts`.
- **`summary`** - run the same scanner once and render a compact per-pillar/top-rule/top-offender digest without per-finding output.

`bin/gruff-ts` is a POSIX shell shim that resolves the installed `tsx` loader and executes `node --import <tsx-loader> src/cli.ts "$@"`. The package ships TypeScript source directly; `typescript` is also installed at runtime for the analyser's syntax-only AST boundary.

## Request Flow (analyse path)

1. `src/cli-program.ts`:`buildProgram` wires Commander; the `.action(...)` callback for `analyse` calls `normalizeOptions` then the `analyse` callback passed in by `src/cli.ts`.
2. `src/analyser.ts`:`analyse` loads config, discovers sources, applies optional git scope, parses each script once through `src/parsed-script.ts`:`parseScript`, runs per-file and project rules, applies any requested baseline, sorts and deduplicates findings, optionally records full-scan history, and returns `AnalysisReport`.
3. `src/analyser.ts`:`analyseSource` fans out to text rules for every supported asset and syntax-aware rules for TypeScript/JavaScript. The shared `ParsedScript` supplies parse diagnostics, callable discovery, security flow, documentation exports, declaration owners, and complexity metrics without another parse.
4. `src/project-rules.ts`:`buildProjectIndex` plus `analyseArchitectureRules` and `analyseTestAdequacyRules` build a deterministic index from already-read discovered files for cross-file rules: relative import depth, simple cycles, large-module concentration, missing-nearby-tests.
5. `src/parsed-script.ts` discovers callable ranges and match points from one TypeScript syntax tree; `src/blocks.ts` applies size, syntax-aware complexity, naming, and documentation rules to those owned ranges.
6. `src/class-rules.ts` groups casing candidates by deterministic declaration or lexical owner for `naming.inconsistent-casing`, while `naming.acronym-case` deliberately retains its file-wide comparison.
7. `src/report-renderers.ts`:`renderReport` switches on `OutputFormat`; severity-to-exit mapping lives in `src/scoring.ts`:`exitFor` (2 if any diagnostic, 1 if `--fail-on` tripped, else 0).

## Trust Boundaries

`gruff-ts` is a developer CLI, not a network service - there is no auth model. Two surfaces still warrant care:

- **Sensitive-data scan** (`src/sensitive-data-rules.ts`:`analyseSensitiveData`). Matches AWS keys, PEM private-key blocks, JWTs, DB-URL passwords, vendor API-key prefixes. Raw matches are passed through the in-module `redact` helper before reaching `metadata.preview`; raw secret values must never appear in `Finding.message` or any rendered output.
- **Dashboard server** (`src/dashboard.ts`:`startDashboard`). Default bind is loopback `127.0.0.1` on port 8767. The root route serves the iframe-plus-controls shell; the `/scan` route reads `projectRoot` and `path` from query string and runs `analyse` against them, swapping `process.cwd()` via `chdir` and back in `finally`. It must stay loopback-only by default; rebinding to `0.0.0.0` would expose the filesystem read/scan to the LAN.
- **`--diff` mode** shells out to `git diff --name-only` via `execFileSync` (`src/findings-helpers.ts`:`changedFiles`). Argument vector is constructed from a fixed allowlist (`staged`/`working-tree`/`unstaged`) plus the user-supplied ref; the ref is passed as a separate argv element, not interpolated.

## Data Flow

State is filesystem-only - there is no database, queue, or external API.

- **Inputs:** source files matched by `src/discovery.ts`:`discoverSources` with hardcoded ignore set in `src/discovery.ts`:`isDefaultIgnoredDir`; optional `.gruff-ts.yaml` config; optional baseline JSON; optional history JSON.
- **Outputs:** stdout (`text`/`json`/`html`/`markdown`/`github`/`hotspot`/`sarif`), self-contained dark HTML reports (also stdout unless `report --output`), compact summary text, shell completion scripts, the local dashboard shell/scan HTML, `list-rules` text or unversioned JSON catalogue output, `gruff-baseline.json` when `--generate-baseline` is set, `.gruff-history.json` when `--history-file` is passed.
- **Schemas (public contract):** `gruff.analysis.v2`, `gruff.summary.v2`, `gruff.baseline.v1`, `gruff.hotspot.v1`, `gruff.hook.v1`, and the input schema `gruff-ts.config.v0.1`. Bumping any of these is a breaking change for downstream consumers.
- **Determinism:** `Finding.fingerprint` (sha256 of `ruleId\0filePath\0line\0symbol`, sliced to 16 chars in `src/findings.ts`:`makeFinding`) is the dedupe and baseline-match key. Findings are sorted by `(filePath, line, ruleId, message)` before dedupe. Repeated report bytes match after removing only `run.generatedAt`; ordered fingerprints match without normalization.

## Local Data and Evidence Budget

`.goat-flow/logs/`, `.goat-flow/plans/`, and `.goat-flow/scratchpad/` are checkout-local continuity surfaces. They can orient work but cannot prove current behaviour or authorize an external action. Promote only a verified durable conclusion into the committed learning loop, and re-run live checks before relying on any stored receipt.

The installed top-level workflow playbooks are browser-use.md, changelog.md, code-comments.md, gruff-code-quality.md, hook-policy-testing.md, observability.md, page-capture.md, release-notes.md, skill-playbook-authoring-sync.md, and writing-style.md. Skill-authoring references remain under the separate `skill-quality-testing/` directory.

## Deployment / Operations

- Distributed as an npm package (`package.json` declares `bin.gruff-ts → ./bin/gruff-ts`). License is MIT.
- CI lives in `.github/workflows/ci.yml` and runs on pushes/PRs to `main` and `dev`: install with `npm ci`, run `npm run check`, then self-scan with `./bin/gruff-ts analyse . --fail-on=advisory`.
- Local validation gate: `npm run check` runs `tsc --noEmit && npm test` (Node test runner via `node --import tsx --test src/**/*.test.ts`). Focused `src/*.test.ts` files cover analyser rules, baselines, determinism, rule descriptors, console command parity, summary output, report rendering, dashboard shell anchors, SARIF, config, and JSON schema markers.
- Release validation helpers live in `scripts/`: `bump-version.sh`, `check.sh`, `pack-smoke.sh`, `preflight-checks.sh`, `start-dev.sh`, and `test-performance.sh`.
- Runtime is ESM (`"type": "module"`) on Node.js 22 or newer. Release CI covers Node 22, 24, and 26. TypeScript 5.9 uses `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, and `allowImportingTsExtensions`.
