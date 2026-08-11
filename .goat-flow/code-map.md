# Code Map

```
gruff-ts/
├── AGENTS.md                      = Codex instruction file (hot path; do not edit peer Claude surfaces)
├── CLAUDE.md                      = Claude instruction file (peer-agent surface; do not edit during Codex turns)
├── README.md                      = user-facing CLI overview, workflows, config, safety notes, and development commands
├── CHANGELOG.md                   = dated public release notes; current 0.5.0 behavior and compatibility changes
├── CONTRIBUTING.md                = contributor setup, rule-change checklist, docs expectations
├── SECURITY.md                    = public vulnerability reporting and security boundaries
├── package.json                   = npm manifest; declares bin "gruff-ts" -> bin/gruff-ts; runtime deps: commander, tsx, typescript
├── package-lock.json              = npm lockfile
├── tsconfig.json                  = strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
├── .gruff-ts.yaml                 = repo-level gruff-ts YAML config
├── .gitignore                     = ignores node_modules, dist, .gruff-history.json, gruff-baseline.json, local agent settings
├── .npmignore                     = secondary npm ignore list; package.json files allowlist remains authoritative
├── docs/
│   ├── configuration.md           = config shape, ignored paths, allowlists, thresholds/options
│   ├── reports-and-ci.md          = output formats, exit codes, baselines, SARIF/GitHub, dashboard
│   └── releasing.md               = 0.5.0 release gates, package review, and installed-tarball smoke
│
├── .github/
│   ├── git-commit-instructions.md = project commit-message policy
│   └── workflows/ci.yml           = npm ci → npm run check → gruff-ts self-scan on main/dev push/PR
│
├── bin/
│   └── gruff-ts                   = POSIX shell shim; resolves tsx loader and execs node --import <loader> src/cli.ts
│
├── src/                           = modular runtime plus focused Node test coverage
│   ├── cli.ts                     = thin CLI bootstrap and public re-exports; delegates to analyser.ts
│   ├── cli-program.ts             = Commander wiring for the eleven registered commands and shared option normalization
│   ├── analyser.ts                = scan orchestrator: config -> discovery -> shared parse -> rules -> baseline -> report
│   ├── parsed-script.ts           = one TypeScript syntax parse per script, shared by callable, docs, flow, owner, and complexity consumers
│   ├── complexity-metrics.ts      = syntax-aware cyclomatic, cognitive, and nesting measurements with deterministic breakdowns
│   ├── discovery.ts               = source walk, gitignore handling, supported extensions, and default ignored directories
│   ├── project-rules.ts           = cross-file imports, cycles, module concentration, and nearby-test analysis
│   ├── blocks.ts                  = callable-owned size, complexity, waste, naming, and documentation rules
│   ├── line-rules.ts              = per-line modernisation, naming, security, and waste patterns
│   ├── class-rules.ts             = declaration rules plus owner-scoped casing and file-wide acronym checks
│   ├── public-exports.ts          = supported public declaration inventory for class/file contract checks
│   ├── dead-code-rules.ts         = unreachable code, unused imports, and unused private methods
│   ├── doc-rules.ts               = file overview, public docs, JSDoc tag, and interface rules
│   ├── comment-rules.ts           = stale comment, tracking, suppression, and rationale rules
│   ├── comment-scanner.ts         = JavaScript and TypeScript comment records consumed by comment rules
│   ├── context-doc-rules.ts       = maintainer-context documentation rubrics
│   ├── fixture-purpose-rules.ts   = fixture-purpose rubric pack
│   ├── test-block-rules.ts        = setup, assertion, mock, sleep, loop, and structural test rules
│   ├── safety-rules.ts            = type-safety, async reliability, catch, and throw rules
│   ├── security-flow-rules.ts     = syntax-aware source-to-sink candidates and unsafe parser/execution checks
│   ├── github-actions-rules.ts    = GitHub Actions workflow and permission rules
│   ├── process-exec-metadata.ts   = safe process-call metadata shared by execution findings
│   ├── naming-pushers.ts          = shared naming finding emitters and remediation metadata
│   ├── project-config-rules.ts    = package, TypeScript, workflow, dependency, and config-health rules
│   ├── sensitive-data-rules.ts    = secret-like detectors with allowlisted redacted previews
│   ├── source-text.ts             = non-code masking and source-text helpers
│   ├── text-scans.ts              = tracking-marker summaries, byte lines, and generic text scans
│   ├── baseline-options.ts        = baseline option resolution shared by CLI commands
│   ├── baseline.ts                = baseline apply/write, finding dedupe, and history recording
│   ├── scoring.ts                 = report scoring, summaries, and finding exit semantics
│   ├── pillar-summary.ts          = canonical summary pillar rows and ordering
│   ├── rules.ts                   = catalogue of exactly 120 descriptors across 11 pillars
│   ├── rule-list.ts               = list-rules, profile list, and shell completion rendering
│   ├── dashboard.ts               = loopback dashboard server and scan endpoint
│   ├── report-html.ts             = escaped self-contained HTML and dashboard report rendering
│   ├── report-renderers.ts        = text, JSON, Markdown, GitHub, hotspot, SARIF, and summary rendering
│   ├── config.ts                  = config loading and effective rule settings
│   ├── config-parse.ts            = dependency-free YAML subset parsing and value narrowing
│   ├── config-preservation.ts     = fields retained across init --force regeneration
│   ├── config-load-error.ts       = user-facing config error and remediation context
│   ├── findings.ts                = stable finding construction and fingerprint identity
│   ├── findings-helpers.ts        = shared finding helpers and centralized severity overrides
│   ├── static-analysis-redundant-rules.ts = low-signal static-analysis test detection
│   ├── types.ts                   = public Finding, report, option, config, and descriptor types
│   ├── constants.ts               = package version constant
│   ├── test-fixtures.ts           = shared synthetic projects and fixture helpers for tests
│   └── *.test.ts                  = focused Node suites for rules, CLI, reports, contracts, and release truth
│
├── scripts/
│   ├── bump-version.sh            = semver bump/check for package.json + src/constants.ts
│   ├── check.sh                   = wrapper for `npm run check` (tsc --noEmit && npm test)
│   ├── pack-smoke.sh              = pack, manifest, fresh-install, output, and exit-semantics release gate
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
├── .codex/                        = Codex config and permission profile (deny hook shared in .goat-flow/hooks/)
│
├── .goat-flow/                    = shared learning loop + skill packs (see .goat-flow/README files inline)
│   ├── config.yaml                = goat-flow version (1.15.1) and skill install policy
│   ├── architecture.md            = system overview (this companion file)
│   ├── code-map.md                = this file
│   ├── glossary.md                = domain term definitions
│   ├── security-policy.md         = scoped security review policy
│   ├── hooks/                     = shared deny-dangerous + gruff-code-quality hooks
│   ├── learning-loop/{footguns,lessons,patterns,decisions}/ = learning loop dirs (READMEs inside)
│   ├── plans/, scratchpad/        = milestone plans + ephemeral work (gitignored contents)
│   ├── logs/sessions/, logs/quality/, logs/critiques/, logs/security/    = local continuity + skill output
│   ├── skill-docs/                = meta references (skill-preamble, skill-conventions, README)
│   └── skill-docs/playbooks/      = browser-use.md, changelog.md, code-comments.md, gruff-code-quality.md, hook-policy-testing.md, observability.md, page-capture.md, release-notes.md, skill-playbook-authoring-sync.md, writing-style.md
│
├── node_modules/                  = goat-flow's manifest-backed views/ HTML view inventory is (about, home, hooks, plans, projects, prompts, quality, settings, setup, skills, workspace); other npm dependencies are vendored and must not be edited
└── .idea/                         = JetBrains IDE config (gitignored, do not edit)
```

Generated/gitignored at runtime (paths exist only after the user runs them):
- `gruff-baseline.json` - written by `analyse --generate-baseline`
- `.gruff-history.json` - written by `analyse --history-file <path>`
- `dist/` - reserved; project ships TypeScript directly via tsx, with typescript used for syntax-only parsing
