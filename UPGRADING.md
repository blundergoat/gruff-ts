# Upgrading

How to move a project between `gruff-ts` lines, what each move breaks, and how to go back.
Every break below is the one this port's own `CHANGELOG.md` records; nothing here is a plan.

## What is stable across `0.5.x`

- Rule identifiers. A released `ruleId` keeps its meaning; it is not renamed or repurposed inside a line.
- The configuration file's name and its documented keys.
- Exit codes for the documented severity gate.
- The analysis envelope's schema version, which changes only on a minor line.

## What changes in `0.6.0`

`0.6.0` is a coordinated family release: the same break lands in all five ports rather than one at a
time, so a project using more than one of them moves once. This port's recorded breaks are:

1. **baselines move to the family `gruff.baseline.v3` file, and every finding identity changes once** — A baseline row now stores one line-free identity and a count: sha256 over the tool language, native rule id, project-relative path, and a subject that is the symbol plus its declaration ordinal, or, when no symbol is named, the message with its measured values normalised. The rest of this entry is in `CHANGELOG.md`.
2. **sensitive-data findings can no longer be baselined** — A generated baseline counts them by rule under `sensitive.counts` and stores no row, path, or message for them, and a hand-written row cannot hide one: a secret stays visible and blocking until it is fixed or excluded with a reason under `sensitiveExclusions`.
3. **SARIF `partialFingerprints.gruffFingerprint` is the ratified identity, and a secret carries none** — Code scanning grouped alerts by the line-bearing fingerprint, so an alert closed and reopened every time code moved above it. It is now the same durable identity baseline matching reads: every existing alert closes and reopens once at this break, and each one then survives an ordinary edit. Two same-named declarations in one file, previously one alert, become two. The rest of this entry is in `CHANGELOG.md`.
4. **every score changes - the family adopts one normalized scoring formula** — A pillar is now `floor + (100 - floor) / (1 + density / densityScale)`, where `density` is the pillar's summed severity-by-confidence weight divided by the number of TypeScript files that were actually evaluated. Scores no longer track project size: duplicating a project leaves its grade unchanged, where before it fell. The rest of this entry is in `CHANGELOG.md`.
5. **the composite can be null, and so can a pillar or file grade** — `score.composite.score` and `score.composite.grade` are `null` when the run evaluated nothing at all: an empty directory, or one whose every TypeScript file failed to parse, previously reported a perfect `100` and grade `A`. Every human view renders `Composite: n/a (nothing evaluated)` in that case.
6. **findings are weighted by analyzer confidence for the first time** — gruff-ts had no confidence dimension: a low-confidence heuristic finding weighed exactly as much as a high-confidence one, so a noisy rule could drag a pillar as hard as a certain defect. Weights are now 0.5 low, 0.75 medium, 1.0 high, matching the four sibling ports.
7. **`score.pillars[]` lists every rule-backed pillar and carries `applicable` and `grade`** — It previously listed only the pillars that had findings, so a reader could not tell a reachable clean pillar from one no rule can reach.
8. **JSON machine contracts move from v2 to family v3** — `analyse` and `report --format=json` now emit `gruff.analysis.v3`; `summary --format=json` emits the same envelope as `gruff.summary.v3`, with only the top-level `findings` array removed, so `--top` affects text only. The rest of this entry is in `CHANGELOG.md`.
9. **default scans use the family fallback policy** — Non-VCS fallbacks now defer to any governing `.gitignore` and match at any depth, committed control metadata stays scannable, and explicit supported files bypass Git and fallback exclusions. VCS internals remain blocked even with `--include-ignored`.
10. **the per-command exit gate moves from `minimumSeverity:` to `failOn:`** — A hand-written `0.5` configuration whose `minimumSeverity:` is the per-command map is refused with exit 2 rather than reinterpreted, so `0.6.0` does not run at all until the mapping is renamed to `failOn:`. `failOn:` takes the same `analyse`, `summary`, and `report` keys, the same `advisory | warning | error | none` values, and the same CLI flag > config > binary default precedence; `dashboard` is still not a key. `minimumSeverity:` stays as a different setting: one severity that hides quieter findings from the report without changing the score or the exit code.

11. **the agent-hook contract moves from `gruff.hook.v1` to `gruff.hook.v2`** — The payload's `contractVersion` changes and the envelope gains two required keys, `run` and `suppressions`. `run` carries the audit data a consumer needs to trust the verdict — mode, scope, the operands as given, `analysedFiles`, and the applied baseline — and `suppressions` carries one row per configured sensitive exclusion the run applied, `[]` when none are configured. The exits are ratified as three and no others: `0` when nothing reached the gate, `1` when something did under an explicit consumer request (`--fail-on`, `--fail-on-new`, or `--fail-on-diagnostics`), and `2` when the run could not happen. Update any consumer that validates the payload's key set; one that reads only the keys it needs is unaffected. The contract is `gruff-spec/contracts/core/hook.v2.json`, ratified 2026-09-06.

12. **`report` no longer accepts `--no-baseline`** — The option was registered on `report` and did nothing: `report` never applies a baseline, and its JSON carried `baseline: null` with or without the flag. `report --baseline` additionally suggested `--no-baseline` in its error, pointing at the no-op. The option is gone and `report --no-baseline` now exits `2`. Remove it from any `report` invocation. `analyse` and `summary` keep `--no-baseline`, where it does suppress the auto-discovered baseline.

## Upgrade workflow (`0.5.x` → `0.6.0`)

1. Read the list above and decide which breaks touch your project. A project with no committed
   baseline and no hand-written configuration is usually unaffected by all but the rule changes.
2. Upgrade the package:

   ```bash
   npm install --save-dev @blundergoat/gruff-ts@^0.6
   ```

3. Regenerate the configuration if you hand-wrote one: `gruff-ts init --force` rewrites it
   with the current schema version and preserves your `paths.ignore`, `failOn:`, and
   `sensitiveExclusions:` entries. Any `rules:` tuning is reset to the shipped defaults, so copy
   those overrides back into the regenerated file by hand.
4. Carry a baseline forward rather than regenerating it, so previously reviewed findings stay
   reviewed: `gruff-ts analyse --migrate-baseline <old> --generate-baseline <new>`. It writes a
   separate file and never modifies the original.
5. Re-run `gruff-ts summary .` and compare the finding count with the one you had. A rule
   whose default changed will move it; a rule whose identity changed will not.

## Limitations

- A baseline generated before `0.6.0` cannot be read directly. Migrate it; do not hand-edit it.
- Sensitive-data findings are not baselineable in `0.6.0`. A project that had suppressed them through
  a baseline needs a reason-bearing configuration exclusion instead.
- Identities change once, at this release. A finding you had already reviewed will look new until the
  migration has run.

## Retreat

If the upgrade costs more than it is worth today, pin the previous line and come back to it:

```bash
npm install --save-dev @blundergoat/gruff-ts@~0.5
```

Keep the pre-upgrade baseline file. It stays readable by the line that produced it, and the migration
command reads it whenever you return.

## Reporting an upgrade regression

Open an issue at <https://github.com/blundergoat/gruff-ts/issues> with the version you moved
from, the version you moved to, the command you ran, and the finding that changed. A finding that
moved without a break above it is a regression rather than an upgrade cost.
