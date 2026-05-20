# Code Map

```
gruff-ts/
├── CLAUDE.md                      = agent instruction file (hot path)
├── README.md                      = user-facing CLI overview, workflows, config, safety notes, and development commands
├── package.json                   = npm manifest; declares bin "gruff-ts" → bin/gruff-ts; deps: commander, tsx
├── package-lock.json              = npm lockfile
├── tsconfig.json                  = strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
├── .gruff-ts.yaml                 = repo-level gruff-ts YAML config
├── .gitignore                     = ignores node_modules, dist, .gruff-history.json, gruff-baseline.json, .claude/settings.local.json
├── .npmignore                     = npm publish ignore list
│
├── bin/
│   └── gruff-ts                   = POSIX shell shim; resolves tsx loader and execs node --import <loader> src/cli.ts
│
├── src/                              = modular runtime (32 modules, ~13.5k lines); cli.ts is now a thin shell
│   ├── cli.ts (19 lines)             = thin CLI shell: bootstrap + entrypoint guard + public re-exports; delegates to analyser.ts
│   ├── cli.test.ts                   = node --test suite (105 tests): analyser rules, baselines, determinism, descriptors, list-rules, summary, console parity, HTML report parity, dashboard shell anchors, JSON schemaVersion marker
│   ├── cli-program.ts (313)          = commander wiring; buildProgram(analyseFn) takes analyse() as a callback (avoids cli.ts ↔ cli-program.ts cycle)
│   ├── analyser.ts (409)             = analyse() orchestrator: load config → discover → per-file scan → project index → baseline apply → AnalysisReport; also per-file rule fanout and parameter-naming fanout
│   ├── discovery.ts (408)            = source walk, gitignore handling, default-ignored directory list (isDefaultIgnoredDir)
│   ├── project-rules.ts (475)        = cross-file rules: circular imports, deep relative imports, large-module concentration, missing-nearby-tests, import-graph build
│   ├── blocks.ts (637)               = functionBlocks regex lexer + FunctionBlock + BlockRuleContext + block-scoped rules (size, complexity, naming.generic-function, useless-return, etc.) + parameterNames
│   ├── test-block-rules.ts (276)     = analyseTestBlock: setup-bloat, assertion-quality, mock-quality, magic-number assertions
│   ├── line-rules.ts (417)           = per-line rules: loose-equality, optional-chaining, nullish-coalescing, identifier-quality declarations, hungarian-notation
│   ├── safety-rules.ts (336)         = type-safety + reliability pushers: ts-directive, non-null assertion, double-cast, exported-any, async-forEach, floating-promise, useless/swallowed catches, non-error-throw
│   ├── dead-code-rules.ts (154)      = analyseDeadCode, analyseUnreachable, analyseUnusedImports
│   ├── class-rules.ts (297)          = class rules, analyseInterfaceFields, collectDeclaredIdentifiers (per-file identifier inventory), analyseInconsistentCasing, analyseAcronymCase
│   ├── doc-rules.ts (369)            = analyseDocRules, analyseFileOverviewDoc, analyseInterfaceDocs (JSDoc enforcement)
│   ├── comment-rules.ts (563)        = analyseCommentQualityRules (M31-M33 comment quality pack)
│   ├── comment-scanner.ts (357)      = commentRecords (extracts JS comment records consumed by comment-rules.ts)
│   ├── context-doc-rules.ts (241)    = maintainer-context doc rubrics (M32)
│   ├── fixture-purpose-rules.ts (326)= fixture-purpose rubric pack (M33)
│   ├── naming-pushers.ts (182)       = pushAbbreviationAt / pushBooleanPrefixAt / pushIdentifierQualityAt / pushNegativeBooleanAt / pushShortVariableAt — shared naming-finding emitters
│   ├── project-config-rules.ts (424) = analyseProjectConfigRules (package.json, tsconfig.json, etc. — risky-config detection)
│   ├── sensitive-data-rules.ts (228) = analyseSensitiveData (AWS keys, JWTs, PEM blocks, DB-URL passwords, vendor API-key prefixes); redacts before metadata
│   ├── source-text.ts (567)          = maskNonCode (mask comments+strings for line-scanning), parseDiagnostics, source-text helpers
│   ├── text-scans.ts (186)           = todoMarkerSummary + generic text scans
│   ├── baseline.ts (89)              = applyBaseline, dedupeFindings, writeBaseline, recordHistory, DEFAULT_BASELINE
│   ├── scoring.ts (73)               = scoreReport (gruff.analysis.v1 score field) + summarize (severity totals)
│   ├── rules.ts (124)                = RULE_DESCRIPTORS catalogue: ruleId, pillar, severity, confidence, description, remediation, threshold/optionKeys
│   ├── rule-list.ts (178)            = list-rules command renderer + shell-completion script generator
│   ├── dashboard.ts (104)            = local HTTP dashboard server (127.0.0.1:8767); iframe shell + /scan endpoint that re-runs analyse on demand
│   ├── report-renderers.ts (647)     = output renderers: text/json/markdown/github/hotspot + the self-contained dark HTML inspection report
│   ├── config.ts (615)               = loadConfig (.gruff-ts.yaml parser), ruleEnabled, ruleSeverity, threshold, optionNumber
│   ├── findings.ts (44)              = makeFinding (sha256 fingerprint sliced to 16 chars; the stable identity tuple for baselines)
│   ├── findings-helpers.ts (98)      = finding() thin wrapper, changedFiles() git-diff bridge
│   ├── types.ts (113)                = public surface types: Finding, AnalysisReport, AnalysisOptions, Pillar, Severity, RuleDescriptor, OutputFormat, Config, RunDiagnostic
│   └── constants.ts (3)              = VERSION
│
├── scripts/
│   ├── check.sh                   = wrapper for `npm run check` (tsc --noEmit && npm test)
│   └── start-dev.sh               = wrapper for `npm run start-dev` (tsx src/cli.ts dashboard)
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
├── .goat-flow/                    = shared learning loop + skill packs (see .goat-flow/README files inline)
│   ├── config.yaml                = goat-flow version (1.6.0) and enabled agents
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
- `gruff-baseline.json` — written by `analyse --generate-baseline`
- `.gruff-history.json` — written by `analyse --history-file <path>`
- `.goat-flow/scratchpad/gruff-ts-extended-baseline.json` — local close-out smoke baseline
- `dist/` — reserved; project ships TS directly via tsx, no compiled output today
