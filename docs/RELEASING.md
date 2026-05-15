# Releasing

This checklist is for preparing a public 0.1.x release.

## Before Publishing

- [ ] Decide the license. `package.json` currently declares `proprietary`; add a
      `LICENSE` file and update package metadata if this is intended to be open
      source.
- [ ] Ensure `package.json` has the intended version.
- [ ] Confirm the CLI `VERSION` constant in `src/cli.ts` matches
      `package.json`.
- [ ] Update `CHANGELOG.md`.
- [ ] Review `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and docs under
      `docs/`.
- [ ] Run `npm run check`.
- [ ] Run a local smoke scan:

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

Check that the package includes:

- `bin/gruff-ts`
- `src/cli.ts`
- `README.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/`
- `package.json`

Check that the package excludes:

- `node_modules/`
- `coverage/`
- `.agents/`, `.claude/`, `.codex/`, and `.goat-flow/`
- `AGENTS.md` and `CLAUDE.md`
- local config and environment files
- local scratchpad/log artifacts
- test files if that remains the intended package shape

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
- [ ] Verify README install instructions from a clean checkout.
- [ ] Create or update the public release notes from `CHANGELOG.md`.
