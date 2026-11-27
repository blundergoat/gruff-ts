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

CI runs `npm run check` followed by `./bin/gruff-ts analyse . --fail-on=advisory`. You can run the full local gate (including docs-drift checks and shellcheck) with `bash scripts/preflight-checks.sh`.

## Project Layout

Runtime code lives under `src/`:

- `src/cli.ts` - thin bootstrap and public re-export shell.
- `src/cli-program.ts` - Commander wiring and option normalization.
- `src/analyser.ts` - scan orchestration and per-file/project rule fanout.
- `src/discovery.ts` - file discovery, `.gitignore`, and ignore classification.
- `src/parsed-script.ts` - shared syntax-only TypeScript AST helpers.
- `src/rules.ts` - canonical rule descriptor catalogue.
- `src/blocks.ts`, `src/line-rules.ts`, `src/class-rules.ts`,
  `src/dead-code-rules.ts`, `src/doc-rules.ts`, `src/comment-rules.ts`,
  `src/context-doc-rules.ts`, `src/fixture-purpose-rules.ts`,
  `src/test-block-rules.ts`, `src/duplicate-test-group-rules.ts`,
  `src/security-flow-rules.ts`, `src/github-actions-rules.ts`, and
  `src/safety-rules.ts` - focused rule packs.
- `src/sensitive-data-rules.ts` and `src/sensitive-exclusions.ts` - sensitive-data
  detectors, exclusions, and built-in test-path skips.
- `src/project-config-rules.ts` and `src/project-rules.ts` - package, tsconfig,
  and cross-file architecture rules.
- `src/baseline.ts`, `src/baseline-identity.ts`, `src/config.ts`,
  `src/migrate-config.ts`, `src/profiles.ts`, `src/inline-suppressions.ts`,
  `src/dashboard.ts`, `src/findings.ts`, `src/rule-list.ts`, `src/scoring.ts`,
  `src/source-text.ts`, `src/text-scans.ts`, `src/report-renderers.ts`,
  `src/constants.ts`, `src/types.ts` - shared helpers, contracts, and renderers.
- `src/*.test.ts` - Node test runner coverage for scanner behavior, rule
  packs, fixtures, reports, and CLI surfaces.

Keep changes small and local. Do not add runtime dependencies beyond
`commander`, `tsx`, and `typescript` unless explicitly approved first.

## Making Rule Changes

When adding or changing a rule:

- Add or update its `RuleDescriptor` in `src/rules.ts`.
- Add focused noisy and clean fixtures.
- Preserve the public `Finding` shape and fingerprint inputs unless a breaking
  schema bump is planned.
- Add config threshold coverage when the rule has thresholds.
- Run `npm run check` and `./bin/gruff-ts analyse . --fail-on=advisory`.

Every finding needs a stable baseline identity. Baseline matching and SARIF alert grouping both read that identity rather than `fingerprint`.

## Documentation Changes

Update docs when behavior changes:

- `README.md` for user-facing workflow changes.
- `CHANGELOG.md` for release-visible changes.
- `docs/configuration.md` for config shape or threshold changes.
- `docs/output-formats.md` for output-format, schema, or exit-code changes.
- `docs/ci-integration.md` for CI and baseline changes.
- `docs/dashboard.md` for dashboard changes.
- `UPGRADING.md` for a change that breaks an existing project.
- `docs/releasing.md` for release process changes.
- `docs/reports-and-ci.md` is a retained compatibility page: point it at the owned pages above
  rather than restating them there.

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
