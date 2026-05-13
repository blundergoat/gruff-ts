# Code Map

```
gruff-ts/
├── CLAUDE.md                      = agent instruction file (hot path)
├── README.md                      = user-facing CLI overview, workflows, config, safety notes, and development commands
├── package.json                   = npm manifest; declares bin "gruff-ts" → bin/gruff-ts; deps: commander, tsx
├── package-lock.json              = npm lockfile
├── tsconfig.json                  = strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
├── .gruff.yaml                    = repo-level gruff-ts config; YAML counterpart to supported JSON config
├── .gitignore                     = ignores node_modules, dist, .gruff-history.json, gruff-baseline.json, .claude/settings.local.json
├── .npmignore                     = npm publish ignore list
│
├── bin/
│   └── gruff-ts                   = POSIX shell shim; resolves tsx loader and execs node --import <loader> src/cli.ts
│
├── src/
│   ├── cli.ts                     = entire runtime (~3233 lines): analyse(), project index, rule descriptors, buildProgram(), all rule fns, dashboard server
│   └── cli.test.ts                = node --test tests; covers analyse() rules, baselines, determinism, descriptors, list-rules, and JSON schemaVersion marker
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
- `.goat-flow/scratchpad/gruff-ts-extended-baseline.json` — local close-out smoke baseline from M09
- `dist/` — reserved; project ships TS directly via tsx, no compiled output today
