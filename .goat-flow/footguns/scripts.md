---
category: scripts
last_reviewed: 2026-05-24
---

# Shell scripts footguns

## Footgun: `mapfile -t` over `node -e "console.log(arr.join('\n'))"` produces `[""]` when the array is empty

**Status:** active | **Created:** 2026-05-24 | **Evidence:** OBSERVED

Pattern that looks safe but isn't: a shell function shells out to `node -e "...console.log(Object.keys(x).join('\n'))"` and the caller reads the result with `mapfile -t arr < <(...)`. When the JS-side array is empty, `[].join('\n')` is `""`, `console.log("")` emits a single newline, and `mapfile -t` then reads **one element** whose value is the empty string (`arr=("")` with `${#arr[@]} == 1`), not the zero-length array (`${#arr[@]} == 0`) the author expected. Any downstream `[[ ${#arr[@]} -gt 0 ]]` guard passes, the loop runs once with `dependency=""`, and `npm install --save-prod "${dependency}@latest"` becomes `npm install --save-prod @latest` — installing or attempting to install a bogus package.

Hit in `scripts/dependency-update.sh` (search: `function read_direct_dependencies`) on 2026-05-24 — fixed by emitting one `console.log(key)` per element instead of joining first:

```bash
# Bad: empty section → `[""]`, length 1
node -e "console.log(Object.keys(pkg['$field'] || {}).join('\n'));"

# Good: empty section → `[]`, length 0
node -e "for (const key of Object.keys(pkg['$field'] || {})) console.log(key);"
```

The same trap is latent in any future `mapfile -t < <(node -e "...")` or `mapfile -t < <(jq -r '.foo[]' …)` where the producer might emit zero lines but a stray newline sneaks in. Two defences:

1. **Producer-side**: emit one line per element with no leading/trailing scaffolding. `for (const x of arr) console.log(x)` for JS, `jq -r '.foo[]?'` (note `?` for empty-safe) for JSON.
2. **Consumer-side**: after `mapfile -t arr`, filter empties before iterating: `arr=("${arr[@]/#/}"); for x in "${arr[@]}"; do [[ -n "$x" ]] && ...; done` — verbose, but it protects against the trap even when the producer is third-party.

`${#arr[@]} -gt 0` is **not** sufficient on its own. The trap is that bash treats `("")` as a one-element array.
