# Contributing

Thanks for taking the time to improve `gruff-ts`.

## Development Setup

```bash
npm install
npm run check
```

Useful local commands:

```bash
npm test
./bin/gruff-ts analyse . --fail-on=none
./bin/gruff-ts list-rules
npm run start-dev
```

CI runs the same core gate with `npm run check`, then runs
`./bin/gruff-ts analyse . --fail-on=advisory`.

## Project Shape

The runtime lives under `src/`:

- `src/cli.ts` - thin bootstrap and public re-export shell.
- `src/cli-program.ts` - Commander program wiring and option normalization.
- `src/analyser.ts` - scan orchestration and per-file/project rule fanout.
- `src/discovery.ts` - source-file discovery and `.gitignore` handling.
- `src/rules.ts` - canonical rule descriptor catalogue.
- `src/blocks.ts`, `src/line-rules.ts`, `src/class-rules.ts`,
  `src/dead-code-rules.ts`, `src/doc-rules.ts`, `src/comment-rules.ts`,
  `src/context-doc-rules.ts`, `src/fixture-purpose-rules.ts`,
  `src/test-block-rules.ts`, `src/security-flow-rules.ts`,
  `src/github-actions-rules.ts`, and `src/safety-rules.ts` - focused rule
  packs.
- `src/sensitive-data-rules.ts` - sensitive-data rule descriptors and
  detectors.
- `src/project-config-rules.ts` - package and tsconfig rule descriptors.
- `src/baseline.ts`, `src/config.ts`, `src/dashboard.ts`, `src/findings.ts`,
  `src/rule-list.ts`, `src/scoring.ts`, `src/source-text.ts`,
  `src/text-scans.ts`, `src/report-renderers.ts`, `src/constants.ts`,
  `src/types.ts` - shared helpers, contracts, and renderers.
- `src/*.test.ts` - Node test runner coverage for scanner behavior, rule
  packs, fixtures, reports, and CLI surfaces.

Keep changes small and local. Do not add runtime dependencies beyond
`commander` and `tsx` unless that direction is explicitly accepted first.

## Rules For Rule Changes

When adding or changing a rule:

- Add or update a `RuleDescriptor`.
- Include focused noisy and clean fixtures.
- Preserve the public `Finding` shape.
- Preserve fingerprint inputs unless a breaking schema change is planned.
- Add config threshold coverage when the rule has thresholds.
- Run `npm run check`.

Every finding must keep a stable `fingerprint`. Baselines depend on it.

## Documentation Changes

Update docs when behavior changes:

- `README.md` for user-facing workflow changes.
- `CHANGELOG.md` for release-visible changes.
- `docs/CONFIGURATION.md` for config shape or threshold changes.
- `docs/REPORTS_AND_CI.md` for output, CI, dashboard, or baseline changes.
- `docs/RELEASING.md` for release process changes.

## Pull Request Checklist

- [ ] Tests or fixtures cover the behavior change.
- [ ] `npm run check` passes.
- [ ] Public schemas are unchanged, or the breaking change is documented.
- [ ] Baseline/fingerprint behavior is unchanged, or the migration path is
      documented.
- [ ] Docs and changelog are updated when user-visible behavior changes.

## Security Issues

Do not open a public issue containing secrets, exploit payloads, or private
repository details. Follow [SECURITY.md](SECURITY.md).
