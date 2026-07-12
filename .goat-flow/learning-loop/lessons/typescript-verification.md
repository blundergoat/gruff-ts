---
category: typescript-verification
last_reviewed: 2026-07-12
---

# TypeScript verification lessons

## Lesson: narrow regex-backed strings before joining a typed syntax inventory

**Created:** 2026-07-12

**What happened:** The syntax-backed public-export inventory exposed a closed declaration-kind union, while the retained regex fallback returned the same five values through an older `kind: string` interface. The first `npx tsc --noEmit` stopped with `ExportedDeclaration[]` not assignable to `PublicExportDeclaration[]`, even though the runtime regex cannot produce another kind.

**Evidence:** `src/class-rules.ts` (search: `kind: declaration.kind as PublicExportDeclaration`) now narrows only at the legacy adapter boundary; the next `npx tsc --noEmit` exits 0 and the syntax path remains union-typed end to end.

**Prevention:** When a new syntax model meets a legacy regex model, do not widen the new union to `string`. Translate or narrow the legacy value at one reviewed boundary, and keep downstream user-facing metadata closed over the documented vocabulary.
