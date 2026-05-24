---
category: rule-catalogue
last_reviewed: 2026-05-24
---

# Rule catalogue patterns

## Pattern: removing a rule from the gruff-ts catalogue
**Created:** 2026-05-24

**When to use:** the user asks to delete a rule (e.g. `docs.todo-density`, `naming.abbreviation`). This is a multi-file change with non-obvious surface area; missing any one step leaves either a test failure, a hallucinated descriptor, or an orphan YAML entry.

**Mechanical checklist** (run grep for the rule id first to confirm the full surface area; this list is the minimum):

1. **`src/rules.ts`** — delete the descriptor entry from `RULE_DESCRIPTORS` (search: `ruleId: "<id>"`). Catalogue is alphabetised by `ruleId` and that ordering is asserted by `rule descriptors cover emitted rules and fixture-backed coverage` — do not reshuffle siblings.

2. **Implementation module** — find via `grep -rn "<rule-id>" src/` and delete:
   - The body that calls `findings.push({ ruleId: "<id>", … })` and any helper called only from it.
   - The matching import in callers (the `pushXxxAt` function for pusher-style rules lives in `src/naming-pushers.ts`; call sites are in `src/analyser.ts` (`pushParameterNamingFindings`), `src/class-rules.ts` (`analyseInterfaceFields`), `src/line-rules.ts` (`pushVariableNameFindings`)).
   - Any helper-only imports that go unused (e.g. `todoMarkerSummary` was only used by `docs.todo-density`; dropping the rule orphaned the entire `commentTextForLine` chain in `src/text-scans.ts`).

3. **`src/types.ts` + `src/config.ts`** — if the rule had a dedicated config field (e.g. `abbreviationDenylist: Set<string>`), drop:
   - The field in `interface Config` (`src/types.ts`).
   - The seed entry in `defaultConfig()` (`src/config.ts`, search: `function defaultConfig`).
   - The `applyNamingAllowlist(config, allowlists, "<key>")` call in `applyAllowlistConfig`.
   - The string literal in the `applyNamingAllowlist` type-union signature.

4. **`src/init-config.ts`** — drop any commented `# default:`/`# <key>:` block in `renderAllowlistsSection` that references the removed config field, and any `RULE_OPTION_DEFAULTS` entry if the rule had `optionKeys`.

5. **`.gruff-ts.yaml`** — delete the rule block (search: `<rule-id>:`) and any allowlist-comment block for a removed config field.

6. **Tests** — at minimum:
   - Per-rule test file (e.g. `src/naming-rules.test.ts`, `src/css-and-todo-rules.test.ts`) — drop the dedicated tests and any references in shared canonical lists such as `NAMING_PILLAR_RULE_IDS`.
   - `src/test-fixtures.ts` — drop the rule from `catalogueCoverageOptions` (`function catalogueCoverageOptions`).
   - `src/rule-catalogue.test.ts` — drop the rule from `riskyRuleIdsRequiringNoisyValidProof` and the `riskyRuleQualityDoctrine` array if present.
   - `src/cli.test.ts` — drop dedicated tests AND remove the rule id from any `noisyRules` Set in the scanner-guardrail tests (`test("scanner guardrail fixtures keep noisy-valid …")`).
   - Any cross-rule overlap test (e.g. `test("naming rule pack cross-rule overlap stays disjoint")`) that references the removed rule needs its fixture and assertions trimmed.

7. **`docs/rules.md`** — delete the bullet under the matching pillar AND decrement two counts: the total ("X rules across 11 pillars" at the top) and the per-pillar count in `## Pillar Counts`.

8. **`docs/configuration.md`** — drop the rule from the example YAML if present, the allowlist table row if the rule had a dedicated field, and any Adoption Defaults block that names it.

9. **`.goat-flow/glossary.md`** — replace any prose example that uses the rule id (the rule-id glossary entry lists examples; substitute another extant rule).

**Verification:** `grep -rn "<rule-id>" src/ docs/ .gruff-ts.yaml .goat-flow/` should return ONLY incidental string matches (historical milestone filenames, comment context). Run `npm run check` — both descriptor-coverage and YAML-parity tests in `src/rule-catalogue.test.ts` and `src/init-config.test.ts` cross-check that the YAML, registry, and implementation agree. Watch for `tests N pass N fail 0`.

**Footgun reminder:** removing a rule is a stealth breaking change for consumers (orphans `gruff.baseline.v1` entries, no-ops user-side `.gruff-ts.yaml` overrides, breaks CI grep checks). Schema version `gruff.analysis.v1` is NOT bumped — the user has to explicitly ask, per CLAUDE.md Hard Rules.

## Pattern: preserving user customisations across config regeneration
**Created:** 2026-05-24

**When to use:** any flow that overwrites `.gruff-ts.yaml` from defaults (`gruff-ts init --force`, future migrate flows). The naive approach — render defaults and write — silently destroys user-curated `paths.ignore`, `allowlists.acceptedAbbreviations`, per-rule `threshold`/`severity`/`options` tuning, and disabled-rule states.

**Shape** (see `src/init-config.ts`, search: `function readExistingIgnoredPaths`):

```ts
function writeDefaultConfig(projectRoot: string, shouldOverwrite: boolean): InitResult {
  const path = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
  const fileExists = existsSync(path);
  if (fileExists && !shouldOverwrite) {
    return { path, status: "exists" };
  }
  const preservedIgnoredPaths = fileExists ? readExistingIgnoredPaths(projectRoot) : [];
  writeFileSync(path, renderDefaultConfig(preservedIgnoredPaths));
  return { path, status: fileExists ? "overwritten" : "written" };
}

function readExistingIgnoredPaths(projectRoot: string): readonly string[] {
  try {
    const config = loadConfig(projectRoot, { /* minimal AnalysisOptions */ });
    return config.ignoredPaths;
  } catch {
    return [];
  }
}
```

Three invariants:

1. **Default parameter on the renderer.** `renderDefaultConfig(ignoredPaths: readonly string[] = [])` keeps every existing caller working unchanged (tests calling `renderDefaultConfig()` still produce the fresh-project output). The new path is opt-in by passing the preserved value.

2. **Read via `loadConfig`, not bespoke YAML parsing.** Reusing `loadConfig` (`src/config.ts`) keeps the YAML grammar single-sourced — a future grammar tweak (new scalar form, inline-array support) flows through automatically. Wrap in try/catch and fall back to `[]` so a malformed-but-clobbered config does not block regeneration.

3. **Render real block sequences, not inline `[a, b]`.** `JSON.stringify(value)` produces a YAML-safe double-quoted scalar that round-trips through `loadConfig`. Inline arrays are valid YAML but visually break the comments-above-list style the init renderer uses.

**Extending to other fields:** the same shape applies to `allowlists.acceptedAbbreviations`, `allowlists.bannedGenericNames`, per-rule overrides, etc. The current implementation only preserves `paths.ignore` because that was the regression the user hit; extending requires (a) a parallel `readExistingAcceptedAbbreviations`-style helper, (b) a renderer parameter with `[]` default, and (c) a test in `src/init-config.test.ts` mirroring `test("gruff-ts init --force preserves the existing paths.ignore entries")`.

**Footgun this defuses:** `gruff-ts init --force regenerates the whole YAML and can wipe user customisations` in `.goat-flow/footguns/schema-and-cli.md`. Cross-link if the preservation surface area grows.
