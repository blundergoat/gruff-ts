# ADR-010: Named Config Profiles With `extends:` Inheritance

**Status:** Implemented
**Date:** 2026-05-31

## Decision

Ship three bundled, readable profile presets - `gruff.minimal` (security and
sensitive-data only), `gruff.recommended` (every pillar at descriptor defaults),
and `gruff.strict` (every pillar with tightened size/complexity/secret
thresholds) - and a `profile:` config block plus a `--profile <name-or-path>`
flag that select one. The inline object form (`extends:` + `rules:` +
`ignoredPaths:`) lets a team extend a base and override a few knobs.

Profiles select rules by pillar (gruff's taxonomy is pillar-based) and flatten,
at config-load time, into a delta from the descriptor defaults. `recommended`
flattens to an EMPTY delta, which is what makes `--profile recommended` and a
zero-config scan produce byte-identical findings.

Resolution precedence, highest first, is fixed and documented: the `--profile`
CLI flag, then a config-file `profile:` block, then the `extends:` base chain,
then the built-in default `recommended`. A top-level `rules:` entry still
overrides the profile for that one rule (most-specific wins).

This is config-only. No `gruff.analysis.*`, `gruff.baseline.*`, or
`gruff.hotspot.*` schema changes; no change to the `Finding` shape or the
default-ignored directory list.

## Context

Teams adopting gruff across many repos otherwise copy-paste a per-rule config
enumerating every rule. A one-line `profile: recommended` replaces that, and
`extends:` lets an org share one base profile and override per repo.

`extends:` accepts a built-in name or a RELATIVE FILE PATH only - never a remote
URL and never a shell command - so a profile cannot become a code-execution or
SSRF vector. Cycles in the `extends:` chain are detected with an ordered
visited-set and rejected with a message naming both ends, rather than recursing
until the stack overflows. Every rule-id reference (in a preset override or a
user profile) is validated against `RULE_DESCRIPTORS` at load time, so a typo
fails fast instead of silently no-opping at scan time.

Flattening is deterministic and child-wins: a child profile's per-rule fields
override the parent's same-rule fields, and a child `ignoredPaths` array
replaces (does not concatenate) the parent's. Last-wins is documented because a
key appearing at multiple inheritance levels must resolve the same way every
run or baselines would churn.

The resolver needs the file parser (`parseConfigFile`), which lived in
`config.ts`; `config.ts` in turn needs the resolver. To keep `config.ts` legible
(it was one line under the `size.file-length` budget) and to avoid a circular
import, the zero-dependency YAML-subset parser, the file reader, the shared
suggestion strings, and the value-narrowing helpers moved to a new
`config-parse.ts` that depends only on Node IO and `ConfigLoadError`.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Pillar-keyed presets with an explicit threshold list | A reviewer must trust the pillar-to-rule expansion. | Accepted: each preset reads in one pass and the expansion is validated against the catalogue at load. |
| Enumerate every rule id in each preset | 120-line presets no reviewer reads; drifts as rules change. | Rejected: unreadable and high-maintenance. |
| `recommended` as a non-empty curated set | Drifts from "current default", breaking the parity contract. | Rejected: `recommended` MUST equal descriptor defaults, so it is an empty delta. |
| Allow `extends:` URLs / npm packages | Remote fetch is a supply-chain and SSRF risk. | Rejected: file paths only this milestone; defer package sharing until usage argues for it. |
| Tolerate `extends:` cycles (rely on stack overflow) | Hangs or crashes with an opaque error. | Rejected: cycles are detected and rejected with both names in order. |

## Reversibility

Reversible: profiles layer on top of the existing per-rule loader rather than
replacing it, so a config with a top-level `rules:` block and no `profile:`
behaves exactly as before. Removing the feature would drop `profiles.ts`, the
resolver in `config.ts`, the `--profile` flag, and `list-profiles`, with no
schema migration because nothing in the output contract changed. The
`config-parse.ts` split is independently reversible by moving the parser back.
