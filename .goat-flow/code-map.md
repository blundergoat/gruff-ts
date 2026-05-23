# Code Map

```
gruff-ts/
├── AGENTS.md                      = Codex instruction file (hot path; do not edit peer Claude surfaces)
├── CLAUDE.md                      = Claude instruction file (peer-agent surface; do not edit during Codex turns)
├── README.md                      = user-facing CLI overview, workflows, config, safety notes, and development commands
├── CHANGELOG.md                   = public release notes; 0.1.0 rule/catalogue surface
├── CONTRIBUTING.md                = contributor setup, rule-change checklist, docs expectations
├── SECURITY.md                    = public vulnerability reporting and security boundaries
├── package.json                   = npm manifest; declares bin "gruff-ts" → bin/gruff-ts; deps: commander, tsx
├── package-lock.json              = npm lockfile
├── tsconfig.json                  = strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
├── .gruff-ts.yaml                 = repo-level gruff-ts YAML config
├── .gitignore                     = ignores node_modules, dist, .gruff-history.json, gruff-baseline.json, local agent settings
├── .npmignore                     = npm publish ignore list
├── docs/
│   ├── CONFIGURATION.md           = config shape, ignored paths, allowlists, thresholds/options
│   ├── REPORTS_AND_CI.md          = output formats, exit codes, baselines, SARIF/GitHub, dashboard
│   └── RELEASING.md               = 0.1.0 / 0.1.x release checklist and package review
│
├── .github/
│   ├── git-commit-instructions.md = project commit-message policy
│   └── workflows/ci.yml           = npm ci → npm run check → gruff-ts self-scan on main/dev push/PR
│
├── bin/
│   └── gruff-ts                   = POSIX shell shim; resolves tsx loader and execs node --import <loader> src/cli.ts
│
├── src/                              = modular runtime plus focused node --test coverage
│   ├── cli.ts (19 lines)             = thin CLI shell: bootstrap + entrypoint guard + public re-exports; delegates to analyser.ts
│   ├── cli-program.ts (325)          = commander wiring; buildProgram(analyseFn) takes analyse() as a callback (avoids cli.ts ↔ cli-program.ts cycle)
│   ├── analyser.ts (459)             = analyse() orchestrator: load config → discover → per-file scan → project index → baseline apply → AnalysisReport
│   ├── discovery.ts (415)            = source walk, gitignore handling, scannable file extensions, default-ignored directory list
│   ├── project-rules.ts (500)        = cross-file rules: circular imports, deep relative imports, large-module concentration, missing-nearby-tests, import graph
│   ├── blocks.ts (687)               = functionBlocks regex lexer + block-scoped size/complexity/waste/naming/doc rules
│   ├── line-rules.ts (538)           = per-line modernisation, naming, security, and waste pattern rules
│   ├── class-rules.ts (326)          = class/interface rules plus per-file identifier inventory for casing/acronym checks
│   ├── dead-code-rules.ts (181)      = analyseDeadCode, analyseUnreachable, analyseUnusedImports
│   ├── doc-rules.ts (369)            = file overview, public docs, JSDoc tag, and interface documentation rules
│   ├── comment-rules.ts (605)        = comment quality rules: stale comments, TODO tracking, suppressions, rationale checks
│   ├── comment-scanner.ts (357)      = commentRecords (extracts JS comment records consumed by comment-rules.ts)
│   ├── context-doc-rules.ts (241)    = maintainer-context doc rubrics
│   ├── fixture-purpose-rules.ts (334)= fixture-purpose rubric pack
│   ├── test-block-rules.ts (347)     = analyseTestBlock: setup-bloat, assertion, mock, sleep, loop, and structural test rules
│   ├── safety-rules.ts (355)         = type-safety + reliability pushers: ts directives, non-null, double-cast, async/reliability, catch/throw rules
│   ├── security-flow-rules.ts (112)  = source-to-sink candidates: open redirect, path traversal, SSRF, dynamic RegExp
│   ├── github-actions-rules.ts (353) = GitHub Actions workflow security rules
│   ├── process-exec-rules.test.ts    = focused process-exec rule regression coverage
│   ├── naming-pushers.ts (191)       = shared naming-finding emitters
│   ├── project-config-rules.ts (425) = package.json, tsconfig, workflow, dependency, and config-health rules
│   ├── sensitive-data-rules.ts (288) = secret-like detectors with redacted previews
│   ├── source-text.ts (691)          = maskNonCode, parseDiagnostics, and source-text helpers
│   ├── text-scans.ts (196)           = todoMarkerSummary, byteLine, and generic text scans
│   ├── baseline.ts (90)              = applyBaseline, dedupeFindings, writeBaseline, recordHistory, DEFAULT_BASELINE
│   ├── scoring.ts (74)               = scoreReport, summarize, exitFor
│   ├── rules.ts (135)                = RULE_DESCRIPTORS catalogue: 121 rule descriptors across 11 pillars
│   ├── rule-list.ts (179)            = list-rules command renderer + shell-completion script generator
│   ├── dashboard.ts (105)            = local HTTP dashboard server (127.0.0.1:8767); iframe shell + /scan endpoint
│   ├── report-renderers.ts (659)     = text/json/html/markdown/github/hotspot/SARIF renderers plus summary output
│   ├── config.ts (618)               = loadConfig YAML subset parser, ruleEnabled, ruleSeverity, threshold, optionNumber
│   ├── findings.ts (45)              = makeFinding (sha256 fingerprint sliced to 16 chars; stable identity tuple for baselines)
│   ├── findings-helpers.ts (98)      = finding() thin wrapper, changedFiles() git-diff bridge
│   ├── types.ts (113)                = public surface types: Finding, AnalysisReport, AnalysisOptions, Pillar, Severity, RuleDescriptor, OutputFormat, Config, RunDiagnostic
│   ├── constants.ts (4)              = VERSION
│   ├── test-fixtures.ts (621)        = shared noisy/clean fixture strings used by rule tests
│   └── *.test.ts                     = focused Node test files for rule packs, fixtures, CLI surfaces, reports, contracts, and false-positive tuning
│
├── scripts/
│   ├── bump-version.sh            = semver bump/check for package.json + src/constants.ts
│   ├── check.sh                   = wrapper for `npm run check` (tsc --noEmit && npm test)
│   ├── preflight-checks.sh        = release gate: npm run check, self-scan, optional shellcheck
│   ├── start-dev.sh               = wrapper for `npm run start-dev` with env host/port/project-root overrides
│   └── test-performance.sh        = gruff-perf.v1 performance matrix/baseline helper
│
├── fixtures/
│   └── sample.ts                  = sample source used by manual smoke tests / dashboard
│
├── .claude/                       = Claude Code agent surface
│   ├── settings.json              = harness settings (committed)
│   ├── settings.local.json        = local-only overrides (gitignored)
│   ├── hooks/
│   │   └── deny-dangerous.sh      = PreToolUse hook blocking risky bash patterns
│   └── skills/
│       ├── goat/                  = dispatcher skill
│       ├── goat-plan/             = milestone planner
│       ├── goat-debug/            = debug skill
│       ├── goat-review/           = code review skill
│       ├── goat-critique/         = multi-perspective critique skill
│       ├── goat-security/         = security review skill
│       └── goat-qa/               = QA/test skill
│
├── .agents/                       = shared Codex skill surface (goat, goat-plan/debug/review/critique/security/qa)
├── .codex/                        = Codex config and deny-dangerous hooks
│
├── .goat-flow/                    = shared learning loop + skill packs (see .goat-flow/README files inline)
│   ├── config.yaml                = goat-flow version (1.7.0) and skill install policy
│   ├── architecture.md            = system overview (this companion file)
│   ├── code-map.md                = this file
│   ├── glossary.md                = domain term definitions
│   ├── security-policy.md         = scoped security review policy
│   ├── footguns/, lessons/, patterns/, decisions/    = learning loop dirs (READMEs inside)
│   ├── tasks/, scratchpad/        = ephemeral work (gitignored contents)
│   ├── logs/sessions/, logs/quality/, logs/critiques/, logs/security/    = local continuity + skill output
│   ├── skill-reference/           = meta references (skill-preamble, skill-conventions, README)
│   └── skill-playbooks/           = tool availability checks (browser-use, page-capture, skill-quality-testing)
│
├── node_modules/                  = npm dependencies (vendored, do not edit)
└── .idea/                         = JetBrains IDE config (gitignored, do not edit)
```

Generated/gitignored at runtime (paths exist only after the user runs them):
- `gruff-baseline.json` - written by `analyse --generate-baseline`
- `.gruff-history.json` - written by `analyse --history-file <path>`
- `.goat-flow/scratchpad/gruff-ts-extended-baseline.json` - local close-out smoke baseline
- `dist/` - reserved; project ships TS directly via tsx, no compiled output today
