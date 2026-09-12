# Releasing

This checklist prepares the public `@blundergoat/gruff-ts@0.6.0` release.
Publishing, git tags, and public release creation are maintainer-owned actions.

## Bump The Version

Run the coordinated bump only after the release version is approved:

```bash
scripts/bump-version.sh 0.6.0
scripts/bump-version.sh --check
```

The script updates `package.json`, `package-lock.json`, and `src/constants.ts`
together. It does not commit, tag, or publish. The dated `CHANGELOG.md` header
must already match the requested version.

## Required Release Gates

- [ ] `scripts/bump-version.sh --check` reports the intended version.
- [ ] `CHANGELOG.md` has the intended version and release date.
- [ ] `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, and public docs describe
      the shipped behavior.
- [ ] Every required release milestone is complete and human gates are
      accepted.
- [ ] `LICENSE` is present and matches the package's MIT license declaration.
- [ ] `npm run check` passes.
- [ ] `scripts/preflight-checks.sh` passes its version, audit, TypeScript,
      unit-test, self-scan, and available ShellCheck gates.
- [ ] `npm pack --dry-run` contains only the reviewed package surface.
- [ ] `bash scripts/pack-smoke.sh` passes. This installed-tarball gate is
      mandatory and deliberately separate from the fast unit-test path.
- [ ] Repository CI passes on Node.js 22, 24, and 26. Node 22 is the package
      minimum; 24 is Active LTS and 26 is Current in the dated 2026-07-12
      [Node.js release table](https://nodejs.org/en/about/previous-releases).

## Package Review

Inspect the exact npm selection:

```bash
npm pack --dry-run
```

The package should include:

- `bin/gruff-ts`
- runtime `src/*.ts` modules
- public docs under `docs/`, except the maintainer-only release checklist and
  coding standards
- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `LICENSE`
- `package.json` and `tsconfig.json`

The package must exclude:

- `src/**/*.test.ts` and `src/fixtures/`
- `scripts/` and root `fixtures/`
- `node_modules/`, coverage, and local build output
- `.agents/`, `.claude/`, `.codex/`, `.github/`, and `.goat-flow/`
- agent instruction files and this repository's `.gruff-ts.yaml`
- environment, secret, scratchpad, and session-log files

The manifest's `files` allowlist is authoritative. `.npmignore` does not remove
a path that the allowlist explicitly includes, so review the actual dry-run or
tarball rather than inferring package contents from ignore rules.

## Installed Package Smoke

Run the maintained consumer-path check:

```bash
bash scripts/pack-smoke.sh
```

It packs into a temporary directory, checks the tar manifest, installs the
tarball into a fresh project, runs the installed binary against a generated
known finding, and verifies JSON output plus finding exit status. It must not
import runtime files from the development checkout.

## Publish And Verify

`bash scripts/npm-publish.sh` is the publish wrapper. It reads the name and version from
`package.json`, verifies npm authentication, checks version lockstep, runs the release preflight
gate, prints a dry-run summary, and requires manual confirmation before it calls `npm publish`.
The tag and the public release remain maintainer-owned actions performed through the approved
release process after every gate above is green.

After publication:

- [ ] Install the exact published version in a fresh temporary project.
- [ ] Run `gruff-ts --help`.
- [ ] Run `gruff-ts analyse . --fail-on=none`.
- [ ] Run `gruff-ts summary . --fail-on=none`.
- [ ] Run `gruff-ts list-rules` and confirm 120 descriptors.
- [ ] Verify the public README installation flow.
- [ ] Confirm the public release notes match the dated changelog.
