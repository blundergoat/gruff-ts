// Built-in gruff profile presets: the named rule selections that `profile:` / `--profile` resolve.
// Each preset is a compact, fully readable definition - a reviewer scans all three in one pass.
// Profiles select rules by PILLAR (gruff's taxonomy is pillar-based) and layer explicit per-rule
// threshold tightenings on top; `src/config.ts`:`resolveProfile` expands these against
// `RULE_DESCRIPTORS` at config-load time and validates every rule-id reference. This module owns the
// canonical rule list (via `ruleDescriptors`) so `config.ts` need not import `rules.ts` directly.
import { ruleDescriptors } from "./rules.ts";
import type { Pillar, ProfileDefinition, ProfileRuleSetting, Severity } from "./types.ts";

// The eleven pillars listed explicitly so `recommended`/`strict` enable every pillar without
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
 * delta), strict (every pillar enabled with tightened size/complexity/design thresholds). Strict only
 * tightens thresholds - it enables no new rule, because recommended already enables every rule that
 * is on by default - so a strict scan reports at least as many findings as recommended, never fewer.
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
    description: "Every pillar enabled with tightened size, complexity, and design thresholds for high-bar repositories.",
    enabledPillars: ALL_PILLARS,
    thresholds: {
      "design.deep-relative-import": 1,
      "design.large-module-concentration": 40,
      "size.file-length": 400,
      "size.function-length": 60,
      "size.parameter-count": 4,
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

/**
 * Builds a bundled preset's profile delta so that applying it limits the scan to the selected pillars.
 *
 * @param spec - bundled preset supplying the profile name, enabled pillars and rule overrides
 * @returns the named profile delta with disabled rules outside those pillars, threshold or severity overrides within them and no ignored paths
 * @throws {Error} - if an override names an unknown rule or a rule whose pillar the preset does not enable
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

// Returns the enabled override for ruleId using threshold and severity from spec.
// Returns undefined when spec provides neither override, so the flattened profile omits that rule.
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

/**
 * Validates bundled preset overrides at load time; failures throw Error rather than ConfigLoadError.
 *
 * @param spec - preset whose override keys must name catalogue rules in its enabled pillars
 * @returns - nothing after validating the preset's override keys
 * @throws {Error} - when an override names an unknown rule or a rule outside the preset's enabled pillars
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
 * user profile that names a rule outside RULE_DESCRIPTORS before any scan runs.
 *
 * @param ruleId - candidate rule id from a user profile's rules block
 * @returns - true when the id is a known rule, false otherwise
 */
export function isKnownRuleId(ruleId: string): boolean {
  return KNOWN_RULE_IDS.has(ruleId);
}

/**
 * Returns the pillar a rule id belongs to, for config sections that accept only one pillar's rules.
 * Reuses the preset-validation map so pillar-scoped config checks read the same canonical catalogue.
 *
 * @param ruleId - candidate rule id from a user's configuration
 * @returns - the rule's pillar, or undefined when the id is outside the catalogue
 */
export function rulePillar(ruleId: string): Pillar | undefined {
  return RULE_PILLARS.get(ruleId);
}

/**
 * Reports whether a configured value is a pillar name rather than a rule id.
 * Sensitive exclusion validation uses this check to report a pillar name where one exact rule id is required.
 *
 * @param candidate - value the user wrote where a rule id is required
 * @returns - true when the value names one of gruff's pillars
 */
export function isPillarName(candidate: string): boolean {
  return ALL_PILLARS.some((pillar) => pillar === candidate);
}

// Option keys a rule descriptor declares for `rules.<id>.options`, empty when the rule has none.
// Exported for config validation so `config.ts` keeps depending on this module, not `rules.ts`.
const RULE_OPTION_KEYS: ReadonlyMap<string, readonly string[]> = new Map(DESCRIPTORS.map((descriptor) => [descriptor.ruleId, descriptor.optionKeys ?? []]));

/**
 * Returns the option keys accepted in a rule's options configuration.
 *
 * @param ruleId - rule id already validated against the catalogue
 * @returns - the declared option keys, or an empty array for an unknown rule or a rule with no options
 */
export function ruleOptionKeys(ruleId: string): readonly string[] {
  return RULE_OPTION_KEYS.get(ruleId) ?? [];
}

/**
 * Returns the built-in profile names in catalogue order for error messages and CLI hints.
 *
 * @returns - bundled profile names in catalogue order
 */
export function builtInProfileNames(): string[] {
  return BUILT_IN_PROFILE_SPECS.map((spec) => spec.name);
}

/**
 * Collects the built-in profile summaries used by the text and JSON formats of list-profiles.
 *
 * @returns - per-profile summaries with enabled/total rule counts, pillar selection, and threshold count
 */
export function profileSummaries(): ProfileSummary[] {
  const totalRuleCount = DESCRIPTORS.length;
  return BUILT_IN_PROFILE_SPECS.map((spec) => {
    const definition = BUILT_IN_PROFILES.get(spec.name);
    return {
      name: spec.name,
      description: spec.description,
      enabledRuleCount: countEnabledRules(definition),
      totalRuleCount,
      enabledPillars: spec.enabledPillars,
      tightenedThresholdCount: Object.keys(spec.thresholds).length,
    };
  });
}

// Returns the enabled-rule count for the flattened profile, using descriptor defaults for unset rules or when no profile is supplied.
// A rule that ships off by default counts only when the profile explicitly enables it.
function countEnabledRules(definition: ProfileDefinition | undefined): number {
  return DESCRIPTORS.filter((descriptor) => definition?.rules.get(descriptor.ruleId)?.enabled ?? descriptor.isEnabledByDefault !== false).length;
}

export { DEFAULT_PROFILE_NAME };
