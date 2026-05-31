// Built-in gruff profile presets: the named rule selections that `profile:` / `--profile` resolve.
// Each preset is a compact, fully readable definition - a reviewer scans all three in one pass.
// Profiles select rules by PILLAR (gruff's taxonomy is pillar-based) and layer explicit per-rule
// threshold tightenings on top; `src/config.ts`:`resolveProfile` expands these against
// `RULE_DESCRIPTORS` at config-load time and validates every rule-id reference. This module owns the
// canonical rule list (via `ruleDescriptors`) so `config.ts` need not import `rules.ts` directly.
import { ruleDescriptors } from "./rules.ts";
import type { Pillar, ProfileDefinition, ProfileRuleSetting, Severity } from "./types.ts";

// The eleven pillars listed explicitly so `recommended`/`strict` enable the whole catalogue without
// referencing an implicit "all rules" default - the selection is greppable here, not derived elsewhere.
const ALL_PILLARS: readonly Pillar[] = [
  "complexity",
  "dead-code",
  "design",
  "documentation",
  "maintainability",
  "modernisation",
  "naming",
  "security",
  "sensitive-data",
  "size",
  "test-quality",
] as const;

// The name applied when neither the CLI flag nor the config file names a profile, and the implicit
// base for an inline `profile:` block that omits `extends:`. `recommended` flattens to an empty delta,
// so "no profile" and "profile: recommended" are behaviourally identical (the parity contract).
const DEFAULT_PROFILE_NAME = "gruff.recommended";

/**
 * A built-in profile preset in its compact, readable source form. `enabledPillars` selects which
 * pillars' rules fire; every rule outside that set is disabled. `thresholds` and `severities` are
 * explicit per-rule tightenings layered on the enabled set. Keeping presets pillar-keyed (plus a
 * short override list) means a reviewer reads the intent in one pass, and the rule-id references in
 * `thresholds`/`severities` are validated against `RULE_DESCRIPTORS` when this module loads.
 */
export interface BuiltInProfile {
  name: string;
  description: string;
  enabledPillars: readonly Pillar[];
  thresholds: Readonly<Record<string, number>>;
  severities: Readonly<Record<string, Severity>>;
}

// One-line digest of a built-in profile for the `list-profiles` command. Carries the enabled/total
// rule counts and the pillar selection so operators can compare presets without resolving each one.
export interface ProfileSummary {
  name: string;
  description: string;
  enabledRuleCount: number;
  totalRuleCount: number;
  enabledPillars: readonly Pillar[];
  tightenedThresholdCount: number;
}

/*
 * The three built-in presets in source form. This array IS the readable preset catalogue the kill
 * criteria require: minimal (sanity/security only), recommended (current default behaviour, a no-op
 * delta), strict (every pillar enabled with tightened size/complexity/secret thresholds). Strict only
 * tightens thresholds - it enables no new rule, because recommended already enables the whole
 * catalogue - so a strict scan reports at least as many findings as recommended, never fewer.
 */
const BUILT_IN_PROFILE_SPECS: readonly BuiltInProfile[] = [
  {
    name: "gruff.minimal",
    description: "Security and sensitive-data rules only - the smallest sanity gate for adopting gruff incrementally.",
    enabledPillars: ["security", "sensitive-data"],
    thresholds: {},
    severities: {},
  },
  {
    name: "gruff.recommended",
    description: "Every pillar at its default threshold and severity - identical to gruff's zero-config behaviour.",
    enabledPillars: ALL_PILLARS,
    thresholds: {},
    severities: {},
  },
  {
    name: "gruff.strict",
    description: "Every pillar enabled with tightened size, complexity, and secret thresholds for high-bar repositories.",
    enabledPillars: ALL_PILLARS,
    thresholds: {
      "complexity.cognitive": 10,
      "complexity.cyclomatic": 10,
      "design.deep-relative-import": 1,
      "design.large-module-concentration": 40,
      "size.file-length": 400,
      "size.function-length": 60,
      "size.parameter-count": 4,
      "sensitive-data.hardcoded-env-value": 12,
      "sensitive-data.high-entropy-string": 24,
      "test-quality.setup-bloat": 8,
    },
    severities: {},
  },
] as const;

// Canonical rule catalogue, captured once at module load. Sorted for determinism so flattened
// profiles and `list-profiles` output never churn between runs.
const DESCRIPTORS = ruleDescriptors();

// Every rule id gruff recognises. Exported so `config.ts` can reject a user profile that references a
// rule outside the catalogue at load time (a preset typo would otherwise silently no-op at scan time).
const KNOWN_RULE_IDS: ReadonlySet<string> = new Set(DESCRIPTORS.map((descriptor) => descriptor.ruleId));

// Map from rule id to its pillar, used when validating that a preset's threshold/severity override
// targets a rule inside one of the preset's enabled pillars (a dead override otherwise).
const RULE_PILLARS: ReadonlyMap<string, Pillar> = new Map(DESCRIPTORS.map((descriptor) => [descriptor.ruleId, descriptor.pillar]));

/*
 * Expands one compact preset into a flattened ProfileDefinition: a rule-id keyed delta from the
 * descriptor defaults. Rules outside the enabled pillars get an explicit `{ enabled: false }`; enabled
 * rules with a threshold/severity override get that override; enabled rules at their default are
 * OMITTED so the delta stays minimal and `recommended` flattens to an empty map (the parity contract).
 * Throws if any override key is unknown or targets a disabled pillar - this is the load-time
 * validation the kill criteria require.
 */
function profileDefinitionFromSpec(spec: BuiltInProfile): ProfileDefinition {
  assertOverrideKeys(spec);
  const enabledPillars = new Set<Pillar>(spec.enabledPillars);
  const rules = new Map<string, ProfileRuleSetting>();
  for (const descriptor of DESCRIPTORS) {
    if (!enabledPillars.has(descriptor.pillar)) {
      rules.set(descriptor.ruleId, { enabled: false });
      continue;
    }
    const setting = enabledRuleSetting(spec, descriptor.ruleId);
    if (setting) {
      rules.set(descriptor.ruleId, setting);
    }
  }
  return { name: spec.name, rules, ignoredPaths: [] };
}

// Builds the override entry for an enabled rule, or undefined when the rule sits at its descriptor
// default (so the flattened delta omits it). Threshold and severity are independent optional knobs.
function enabledRuleSetting(spec: BuiltInProfile, ruleId: string): ProfileRuleSetting | undefined {
  const threshold = spec.thresholds[ruleId];
  const severity = spec.severities[ruleId];
  if (threshold === undefined && severity === undefined) {
    return undefined;
  }
  return {
    enabled: true,
    ...(threshold !== undefined ? { threshold } : {}),
    ...(severity !== undefined ? { severity } : {}),
  };
}

/*
 * Validates a preset's override keys at load time. Every key in `thresholds`/`severities` must be a
 * real rule id (caught by `KNOWN_RULE_IDS`) and must live in one of the preset's enabled pillars - a
 * threshold on a disabled rule would never fire and signals a preset authoring mistake. Throws a plain
 * Error (not ConfigLoadError) because this is an internal contract on bundled presets, not user input.
 */
function assertOverrideKeys(spec: BuiltInProfile): void {
  const enabledPillars = new Set<Pillar>(spec.enabledPillars);
  for (const ruleId of [...Object.keys(spec.thresholds), ...Object.keys(spec.severities)]) {
    const pillar = RULE_PILLARS.get(ruleId);
    if (pillar === undefined) {
      throw new Error(`Built-in profile "${spec.name}" references unknown rule id "${ruleId}". Every override key must be in RULE_DESCRIPTORS.`);
    }
    if (!enabledPillars.has(pillar)) {
      throw new Error(`Built-in profile "${spec.name}" overrides "${ruleId}" but its pillar "${pillar}" is not enabled. The override would never fire.`);
    }
  }
}

/**
 * The bundled profile catalogue, keyed by name. Values are the flattened ProfileDefinitions that
 * `resolveProfile` clones and overlays. Built once at module load, which is where preset rule-id
 * references are validated - so an authoring mistake fails fast on import, never silently at scan time.
 */
export const BUILT_IN_PROFILES: ReadonlyMap<string, ProfileDefinition> = new Map(
  BUILT_IN_PROFILE_SPECS.map((spec) => [spec.name, profileDefinitionFromSpec(spec)]),
);

/**
 * Reports whether a rule id is part of gruff's catalogue. Used by the profile resolver to reject a
 * user profile that names a rule outside `RULE_DESCRIPTORS` before any scan runs.
 *
 * @param ruleId Candidate rule id from a user profile's `rules:` block.
 * @returns True when the id is a known rule, false otherwise.
 */
export function isKnownRuleId(ruleId: string): boolean {
  return KNOWN_RULE_IDS.has(ruleId);
}

/**
 * Returns the built-in profile names in catalogue order for error messages and CLI hints.
 *
 * @returns The bundled profile names, e.g. `["gruff.minimal", "gruff.recommended", "gruff.strict"]`.
 */
export function builtInProfileNames(): string[] {
  return BUILT_IN_PROFILE_SPECS.map((spec) => spec.name);
}

/**
 * Builds the one-line digest of every built-in profile for the `list-profiles` command.
 *
 * @returns Per-profile summaries with enabled/total rule counts, pillar selection, and threshold count.
 */
export function profileSummaries(): ProfileSummary[] {
  const totalRuleCount = DESCRIPTORS.length;
  return BUILT_IN_PROFILE_SPECS.map((spec) => {
    const definition = BUILT_IN_PROFILES.get(spec.name);
    const disabledCount = definition ? countDisabledRules(definition) : 0;
    return {
      name: spec.name,
      description: spec.description,
      enabledRuleCount: totalRuleCount - disabledCount,
      totalRuleCount,
      enabledPillars: spec.enabledPillars,
      tightenedThresholdCount: Object.keys(spec.thresholds).length,
    };
  });
}

// Counts the rules a flattened profile explicitly disables, so the enabled count is the catalogue
// size minus the disables (enabled-at-default rules are omitted from the delta and stay enabled).
function countDisabledRules(definition: ProfileDefinition): number {
  let disabled = 0;
  for (const setting of definition.rules.values()) {
    if (setting.enabled === false) {
      disabled += 1;
    }
  }
  return disabled;
}

export { DEFAULT_PROFILE_NAME };
