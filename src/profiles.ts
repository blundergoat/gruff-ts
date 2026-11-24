// Built-in gruff profile presets resolved by `profile:` in config and `--profile` on the CLI.
//
// Each preset is pillar-keyed with optional per-rule threshold or severity tightenings so a maintainer can read all three in one pass:
// - `resolveProfile` in `src/config.ts` expands presets against `RULE_DESCRIPTORS` and validates every rule-id reference;
// - this module owns the canonical rule catalogue view so `config.ts` stays decoupled from `rules.ts`.
import { ruleDescriptors } from "./rules.ts";
import type { Pillar, ProfileDefinition, ProfileRuleSetting, Severity } from "./types.ts";

// Eleven pillars listed explicitly so `recommended` and `strict` stay greppable here instead of deriving an implicit "all rules" default.
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

// Default preset applied when neither the CLI nor config names a profile, and the implicit base when an inline `profile:` omits `extends:`.
// `gruff.recommended` flattens to an empty delta so zero-config scans and `profile: recommended` behave identically.
const DEFAULT_PROFILE_NAME = "gruff.recommended";

/**
 * Compact source form of a built-in profile preset before expansion against the rule catalogue.
 *
 * `enabledPillars` selects which pillars fire (disabling all others); `thresholds` and `severities` layer explicit tightenings on top.
 * Every rule ID in `thresholds` or `severities` is validated against `RULE_DESCRIPTORS` when this module loads.
 */
export interface BuiltInProfile {
  name: string;
  description: string;
  enabledPillars: readonly Pillar[];
  thresholds: Readonly<Record<string, number>>;
  severities: Readonly<Record<string, Severity>>;
}

// One-line digest of a built-in profile shown by `gruff-ts list-profiles` so operators can compare presets without expanding them.
export interface ProfileSummary {
  name: string;
  description: string;
  enabledRuleCount: number;
  totalRuleCount: number;
  enabledPillars: readonly Pillar[];
  tightenedThresholdCount: number;
}

/*
 * The three built-in presets shipped with gruff-ts, validated against the live rule catalogue on import.
 *
 * Strict only tightens thresholds and enables no extra off-by-default rules, so it never reports fewer findings than recommended:
 * - `gruff.minimal`: security and sensitive-data pillars only;
 * - `gruff.recommended`: zero-config parity across every pillar;
 * - `gruff.strict`: every pillar with tightened size and design thresholds.
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
    description: "Every pillar enabled with tightened size and design thresholds for high-bar repositories.",
    enabledPillars: ALL_PILLARS,
    thresholds: {
      "design.large-module-concentration": 40,
      "size.file-length": 400,
      "size.function-length": 60,
      "size.parameter-count": 4,
    },
    severities: {},
  },
] as const;

// Canonical rule catalogue captured once at module load in deterministic order so flattened profiles and `list-profiles` never churn.
const DESCRIPTORS = ruleDescriptors();

// Every rule ID gruff recognises; used by `config.ts` and `selectors.ts` to reject typos before scanning.
const KNOWN_RULE_IDS: ReadonlySet<string> = new Set(DESCRIPTORS.map((descriptor) => descriptor.ruleId));

// Rule-to-pillar lookup used to reject dead preset overrides targeting a rule whose pillar the preset left disabled.
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

/**
 * Builds the enabled override for a rule using threshold and severity overrides from the preset.
 *
 * @param spec - built-in preset supplying threshold and severity override maps
 * @param ruleId - catalogue rule id to look up in the preset's overrides
 * @returns the enabled rule setting with configured overrides, or undefined when neither is set so the flattened profile omits that rule
 */
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
 * Bundled profile catalogue built once at module load so invalid preset rule IDs fail fast on import instead of silently no-opping at scan time.
 * `resolveProfile` clones and overlays entries from this map.
 */
export const BUILT_IN_PROFILES: ReadonlyMap<string, ProfileDefinition> = new Map(
  BUILT_IN_PROFILE_SPECS.map((spec) => [spec.name, profileDefinitionFromSpec(spec)]),
);

/**
 * Reports whether a rule ID exists in gruff's live rule catalogue.
 * Used by config loading and CLI selectors to reject typos and retired IDs before scanning.
 *
 * @param ruleId - candidate rule ID from a config, profile, or CLI selector
 * @returns True when `ruleId` is in the active catalogue; false otherwise.
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

/**
 * Counts enabled rules for a flattened profile, using descriptor defaults for unset rules or when no profile is supplied.
 * A rule that ships off by default counts only when the profile explicitly enables it.
 *
 * @param definition - flattened profile definition to inspect, or undefined to evaluate catalogue defaults
 * @returns total number of rules in the catalogue that are enabled for the profile
 */
function countEnabledRules(definition: ProfileDefinition | undefined): number {
  return DESCRIPTORS.filter((descriptor) => definition?.rules.get(descriptor.ruleId)?.enabled ?? descriptor.isEnabledByDefault !== false).length;
}

export { DEFAULT_PROFILE_NAME };
