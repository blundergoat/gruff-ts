# Releasing

This checklist prepares the public `0.1.0` release and subsequent `0.1.x`
patch releases.

## Bump The Version

`scripts/bump-version.sh <semver>` updates `package.json` and
`src/constants.ts` together so the CLI `--version` output and the published
package version cannot drift apart. For the initial `0.1.0` release, the
version should already be `0.1.0`; use `--check` instead of bumping unless the
release version changes.

```bash
scripts/bump-version.sh --check
scripts/bump-version.sh 0.1.1
scripts/bump-version.sh --check
```

The script edits files in place and does not commit or tag. After running it,
update `CHANGELOG.md` and run `npm run check`.

## Before Publishing

- [ ] `scripts/bump-version.sh --check` reports the intended version.
- [ ] `CHANGELOG.md` has an entry for the new version with today's date.
- [ ] `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and docs under `docs/`
      reflect any user-visible changes.
- [ ] `.goat-flow/tasks/0.1/` has no unresolved release blockers beyond
      explicitly accepted `human-verification-pending` milestones.
- [ ] `LICENSE` is present and `package.json` `license` field matches.
- [ ] `npm run check` passes.
- [ ] `scripts/preflight-checks.sh` passes (runs `npm run check`, a full
      `gruff-ts` self-scan, and `shellcheck` on `scripts/*.sh` when
      `shellcheck` is installed).
- [ ] `npm pack --dry-run` shows only publishable runtime, docs, scripts, and
      metadata files.
- [ ] Local smoke scan succeeds:

```bash
./bin/gruff-ts
./bin/gruff-ts analyse fixtures/sample.ts --fail-on=none
./bin/gruff-ts summary fixtures/sample.ts --fail-on=none
./bin/gruff-ts report fixtures/sample.ts --output /tmp/gruff-ts-report.html
./bin/gruff-ts list-rules
```

## Package Review

Preview package contents:

```bash
npm pack --dry-run
```

The package should include:

- `bin/gruff-ts`
- `src/` (all runtime `.ts` files; `src/**/*.test.ts` files are excluded by
  `.npmignore`)
- `scripts/` (`bump-version.sh`, `check.sh`, `preflight-checks.sh`,
  `start-dev.sh`, `test-performance.sh`)
- `fixtures/sample.ts`
- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `LICENSE`
- `docs/`
- `package.json`
- `tsconfig.json`

The package must exclude:

- `node_modules/`
- `coverage/`
- `.agents/`, `.claude/`, `.codex/`, `.github/`, and `.goat-flow/`
- `AGENTS.md` and `CLAUDE.md`
- `.gruff-ts.yaml` (this repo's local config)
- env and secret files (`.env`, `.env.*` except `.env.example`)
- local scratchpad or log artifacts
- `src/**/*.test.ts`

## Publish

```bash
npm publish
```

Use the appropriate npm access flag for the package ownership model.

## After Publishing

- [ ] Install the published package in a temporary project.
- [ ] Run `gruff-ts --help`.
- [ ] Run `gruff-ts analyse . --fail-on=none`.
- [ ] Run `gruff-ts summary . --fail-on=none`.
- [ ] Run `gruff-ts list-rules`.
- [ ] Verify `README.md` install instructions from a clean checkout.
- [ ] Tag the release in git (`git tag v0.1.0 && git push --tags`) and create
      or update public release notes from `CHANGELOG.md`.
