# ADR-004: Per-Command minimumSeverity Config Block + Config Schema Version

**Status:** Accepted
**Date:** 2026-05-27
**Author(s):** Operator, Claude
**Ticket/Context:** `.goat-flow/tasks/0.1.3/ISSUE.md`, cross-port `gruff-go/.goat-flow/logs/critiques/2026-05-26-config-wording-brainstorm-b5k2x.md`

## Decision

Introduce two coupled config-schema additions to `.gruff-ts.yaml`:

1. **`schemaVersion: gruff-ts.config.v0.1`** - a new required top-level field. Configs missing the field, or carrying any other version string, fail loading with a clear error listing the supported version.
2. **`minimumSeverity:`** - a new top-level block mapping `analyse` / `summary` / `report` to a `FailThreshold` value (`advisory | warning | error | none`). Acts as a per-command default for `--fail-on` when the flag is absent.

The precedence chain for `--fail-on` is:

```
CLI flag (--fail-on=X)  >  minimumSeverity.<cmd> in .gruff-ts.yaml  >  binary default
```

The binary defaults flip to align with the operator's "show everything, fail on anything" gating philosophy:

| Command | Old default | New default |
|---------|-------------|-------------|
| `analyse` | `error` | `advisory` |
| `summary` | `error` | `advisory` |
| `report` | `none` | `none` (unchanged) |

The `dashboard` subcommand is intentionally omitted from `minimumSeverity:` because it has no `--fail-on` flag today; a `minimumSeverity.dashboard:` entry would be a silent no-op CI footgun. The validator rejects `dashboard` as a key with a clear error pointing at this deferral.

The off-switch value is **`none`** (not `never`). `gruff-ts` has shipped `none` as the FailThreshold off-switch since 0.1.0; the cross-port family converged on `none` after a linguistic re-evaluation (see the gruff-go wording-brainstorm log).

## Context

`gruff-ts` had rule-level config overrides (`rules.*.severity`, `rules.*.threshold`) but no surface where config could default a top-level CLI flag. Operators running `gruff-ts analyse .` in CI had to remember to pass `--fail-on=advisory` on every invocation to match the "fail on anything" gating philosophy; missing the flag meant the binary default (`error`) silently let warning- and advisory-tier findings pass.

The cross-port family (`gruff-go`, `gruff-rs`, `gruff-py`, `gruff-php`) is converging on the same `minimumSeverity:` shape so operators running multiple ports don't fragment muscle memory. The wording-brainstorm critique on the gruff-go side picked `minimumSeverity:` (a noun) over `failOn:` (a verb) and `defaults.failOn:` (nested) because the noun position reads naturally with the four canonical values.

`.gruff-ts.yaml` had no top-level schema version, so any future config-shape change would have to either guess at compatibility or land in lockstep with a hard cut. Introducing `schemaVersion: gruff-ts.config.v0.1` as a required field at the 0.1.x pre-public-adoption stage trades a one-time migration cost (every existing config gains a line) for a clean lever on future shape changes. This is consistent with the no-legacy-compat policy: pre-1.0, breaks are sharp, not gradual.

## Failure Mode Comparison

| Option | What fails | Why rejected or accepted |
| --- | --- | --- |
| `failOn:` (verb wording) at top level | Reads as a directive ("fail on X") that pairs awkwardly with `none` ("fail on none"). Cross-port consumers reading both `gruff-ts` and `gruff-go` configs would see verb wording in one place and noun wording elsewhere. | Rejected by the cross-port brainstorm in favour of `minimumSeverity:`. |
| `defaults.failOn:` (nested) | Adds a `defaults` block whose contents grow unbounded; encourages "another default here" creep. Doesn't read naturally for cross-command thresholds. | Rejected: a flat `minimumSeverity:` block scoped to commands is clearer. |
| `exitOn:` (ESLint convention) | Closer to existing tooling vocabulary but conflates "what the rule emits" with "what the CLI exits on." | Rejected: severity is a rule-emit concept; `minimumSeverity` is closer to the user's mental model. |
| `never` as off-switch | An earlier draft used `never` for the off value. Reads naturally with a verb key (`failOn: never`) but reads awkwardly as a noun-position value (`minimumSeverity: never`). | Rejected after linguistic re-evaluation: `none` reads as "no minimum severity = no gate" and is what `gruff-ts` has shipped since 0.1.0. |
| `minimumSeverity.dashboard:` accepted | Dashboard has no `--fail-on` flag. Accepting the key would silently no-op and operators would expect gating behaviour that never fires. | Rejected: the validator throws on `dashboard` with a documented error explaining the omission. |
| Optional `schemaVersion:` with default | Easier short-term migration; existing configs still load. But every future config-shape change would have to guess what version a missing field implies. | Rejected: pre-1.0 is the right time to make the field required. Migration is a one-line edit per project. |
| Skip schema versioning entirely | No migration cost. | Rejected: when the next config-shape change arrives, the operator has no clean lever for "is this config compatible." |

## Namespace Coexistence

The new config-input schema string `gruff-ts.config.v0.1` lives in a different namespace than the existing output schemas:

| Schema | Namespace | Lives in |
|--------|-----------|----------|
| `gruff-ts.config.v0.1` | input | `.gruff-ts.yaml` |
| `gruff.analysis.v2` | output | `analyse --format=json` payload |
| `gruff.summary.v2` | output | `summary --format=json` payload |
| `gruff.baseline.v1` | output | baseline files |
| `gruff.hotspot.v1` | output | `--format=hotspot` payload |

The `gruff-ts.config.*` namespace is distinct from `gruff.*.*` (no port prefix) and the file contexts don't overlap. A future reader should not assume the version numbers track together.

## Cross-Port Coordination

`gruff-go`, `gruff-rs`, `gruff-py`, and `gruff-php` are tracking the same `minimumSeverity:` dimension. Each port owns its own implementation, but the shared decision is the four-value vocabulary (`advisory | warning | error | none`) and the precedence chain (CLI flag > config > binary default). The `none`-over-`never` flip noted above applies across the family.

Coordination is out of scope for this ADR - surface it via the gruff-go ISSUE.md update or each port's own decision log as those teams pick up the work.

## Consequences

- **Breaking on config load**: every existing `.gruff-ts.yaml` becomes invalid until the operator adds `schemaVersion: gruff-ts.config.v0.1`. The repo's own root config is updated in lockstep with the validator landing.
- **Breaking on CI exit code**: every CI gate using the `analyse` or `summary` default (no `--fail-on` flag) goes from "fail on error only" to "fail on anything." Operators that want the old behaviour set `--fail-on=error` explicitly or pin `minimumSeverity.<cmd>: error` in their config.
- **Cross-port harmony**: operators running multiple ports get a single mental model for "where do I pin the gating threshold."
- **Future config-shape changes** have a clean lever (`gruff-ts.config.v0.2`, etc.) instead of guessing at backward compatibility.
