# ADR-012: Adopt typescript as a syntax-only runtime parser dependency

**Status:** Accepted
**Date:** 2026-05-31
**Author(s):** Claude, user
**Ticket/Context:** M25 (security rule expansion) needs a real parser to move path-traversal / SSRF / open-redirect / dynamic-regexp from same-line heuristics to bounded intra-function flow, and to add deserialization + XXE detection. The milestone body asserted this was "approved" but no ADR recorded it; the 2026-05-30 decision-gate review flagged it as unratified and CLAUDE.md still listed runtime dependencies as `commander` + `tsx` only. This ADR is that ratification.

## Decision

Promote `typescript` from a `devDependency` to a runtime `dependency`, and use it
exclusively through its **syntax-only** API (`ts.createSourceFile`). This is a
deliberate, user-approved exception to the prior CLAUDE.md hard rule "never
introduce runtime dependencies beyond `commander` + `tsx`" and to the earlier
"no TypeScript compiler" kill criterion carried by M00.

The exception is bounded. In-scope: `ts.createSourceFile` parsing of `.ts` /
`.tsx` / `.js` / `.jsx` to a syntax tree, walked by the security rules. Out of
scope and treated as kill criteria for any code that imports `typescript`:

- the type checker, `ts.Program`, or `ts.createProgram`;
- the language service or any incremental/build server;
- any bundler, transpile, or emit execution;
- any package-registry, advisory-feed, or network access.

`dependencies` becomes `{ commander, tsx, typescript }`. That is the only
contract change this ADR authorises. `gruff.analysis.v2`, `gruff.baseline.v1`,
`gruff.hotspot.v1`, the `Finding` shape, the dashboard wire format, SARIF
partial fingerprints, and `tsconfig.json` all stay frozen.

## Context

gruff has been regex-only by design: `functionBlocks` and `parseDiagnostics` are
lightweight character scanners, not a TS tokenizer (`.goat-flow/footguns/parser.md`).
That keeps the install small and the analyser fast, but it caps security
precision: a same-line heuristic cannot follow a tainted value from an external
source through an intermediate variable to a sink, so path-traversal / SSRF /
open-redirect / dynamic-regexp can only ever be same-line "candidate" findings,
and intra-procedural taint, insecure deserialization, and XXE are out of reach.

Under ADR-005 a security rule earns its place by helping a reviewer catch what
their eye slips past in agent-generated code. AST-bounded flow is the lever that
raises both precision (fewer false candidates) and breadth (deserialization, XXE)
at once. The TypeScript compiler ships exactly the parser needed and nothing about
`ts.createSourceFile` requires the type checker, a program, or the network, so the
cost is a larger install, not a new class of runtime behaviour.

Interaction with M00 (npath removal): M00 partly justified deleting
`complexity.npath` by noting a real path metric needs an AST and gruff was
regex-only. That premise flips here, but M00's other reason stands - `cognitive`
already subsumes npath - so npath stays removed. This ADR does not re-open it.

Port scope: this is a gruff-ts-local decision. Each port adopts its own language's
native parser if and when its security column argues for it; this ADR does not
bind the other ports.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| Stay regex-only | SSRF/path-traversal stay same-line candidates; deserialization/XXE and any cross-line taint are unreachable. Security column cannot reach a full pass. | Rejected: caps the milestone's core value; the reviewer-facing security depth is the point. |
| Vendor a hand-rolled mini-parser | Re-implements a TS tokenizer gruff already depends on at build time; high bug surface, ongoing maintenance, drift from real TS syntax. | Rejected: more risk than the dependency it avoids. |
| Adopt `typescript` with the type checker / `ts.Program` | Pulls in resolution, multi-file programs, and a large perf/footprint cost; "hooks run constantly, so speed is correctness" (ADR-008). | Rejected: kill criterion. Syntax-only parsing is enough for intra-function flow. |
| Adopt `typescript` syntax-only (`ts.createSourceFile`) | Larger install; one runtime dependency added. | **Accepted**: bounded, deterministic, no network, and the minimum needed for AST-bounded security flow. |

## Consequences

- `package.json` `dependencies` gains `typescript`; `package-lock.json` is
  regenerated so the lockstep check (`scripts/bump-version.sh --check`) stays green.
- The security rules gain a shared syntax-only AST with a masked-text fallback on
  parse failure, so a file the parser cannot handle degrades rather than crashes.
- CLAUDE.md's "runtime dependencies limited to `commander` + `tsx`" line is now
  qualified by this ADR; future runtime-dependency additions remain Ask First and
  are not implied by this one.
- Re-expressing existing same-line security rules on the AST must preserve their
  rule ids and fingerprints where the same evidence still appears on one line; any
  unrelated fingerprint churn is a regression.

## Reversibility

Reversible but costed. Reverting means moving `typescript` back to
`devDependencies`, deleting the AST layer, and restoring the same-line heuristics
for any rule that was upgraded - the flow-based precision and the
deserialization/XXE breadth would be lost, and the masked-text fallback would
become the only path. No schema, baseline, or finding-shape change is involved, so
a revert is internal: consumers would see only the removed/again-same-line
security findings. Revisit if the install-size or runtime cost of shipping the
compiler proves unacceptable in real hook usage.
