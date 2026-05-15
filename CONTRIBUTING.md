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

## Project Shape

The runtime intentionally lives in one TypeScript file:

- `src/cli.ts` - CLI, scanner, rules, renderers, dashboard, config, baselines.
- `src/cli.test.ts` - Node test runner coverage for scanner behavior and CLI
  surfaces.

Keep changes small and local. Do not split the runtime into modules or add
runtime dependencies unless that direction is explicitly accepted first.

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
