---
category: packaging
last_reviewed: 2026-06-06
---

# Packaging / npm publish footguns

## Footgun: a `files` allowlist in package.json bypasses root `.npmignore` inside listed dirs

**Status:** active | **Created:** 2026-06-06 | **Evidence:** OBSERVED

When `package.json` has a `files` array and that array names a **directory**
(for example `"src/"` or `"docs/"`), npm-packlist includes the whole directory
and does **not** apply the root `.npmignore` to prune within it. Root-level
patterns such as `src/**/*.test.ts`, `/src/fixtures/`, or `/docs/releasing.md`
are silently ignored for anything inside a `files`-listed dir, so those files
still ship.

The trap is counterintuitive: adding a `files` allowlist to *tighten* the
package can *loosen* it. Observed on 2026-06-06 while trimming the published
package - adding `"files": ["src/", ...]` took the tarball from 64 to 91 files,
pulling every `*.test.ts` and `src/fixtures/` back in, because the existing
`.npmignore` exclusions no longer applied.

Fix: put exclusions as `!` negations **inside** the `files` array (npm-packlist
honours them there), not in `.npmignore`:

```jsonc
"files": [
  "src/", "!src/**/*.test.ts", "!src/fixtures/",
  "docs/", "!docs/releasing.md", "!docs/coding-standards/"
]
```

The root `.npmignore` then only matters as a fallback if the `files` field is
ever removed (see its header, search: `Defense-in-depth fallback`). Always
confirm real contents with `npm pack --dry-run` (or extract the actual `.tgz`) -
never assume the two mechanisms compose. Evidence: `package.json`
(search: `"!src/**/*.test.ts"`).
