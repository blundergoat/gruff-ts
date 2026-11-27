/*
 * The two families of rule selector, kept apart because they answer different questions.
 *
 * Applies the rule and pillar choices a user makes when running or viewing an analysis.
 *
 * Use `--include-rule` to run a narrower set of rules and score that set.
 * Use `--show-rule` to focus the report while keeping the score and exit status of the evaluated scan.
 */
import { ConfigLoadError } from "./config-load-error.ts";
import { isKnownRuleId, isPillarName } from "./profiles.ts";
import { ruleDescriptors } from "./rules.ts";
import type { Config, ExecutionSelectors, Finding, Pillar, Severity } from "./types.ts";

// Severity ladder for the display floor; a finding at or above the requested rank is shown.
const SEVERITY_RANK: Record<Severity, number> = { advisory: 0, warning: 1, error: 2 };

/*
 * The user's report view, selected by severity and included or hidden rules and pillars.
 */
export interface DisplaySelectors {
  minSeverity?: Severity;
  showRules: string[];
  hideRules: string[];
  showPillars: string[];
  hidePillars: string[];
}

/**
 * Checks whether execution selectors request any rule or pillar filtering, preserving configured enablement when false.
 *
 * @param selectors - execution include and exclude lists for rules and pillars
 * @returns True if any include or exclude list is non-empty; false preserves configured rule enablement.
 */
export function isExecutionRequested(selectors: ExecutionSelectors): boolean {
  return selectors.includeRules.length > 0 || selectors.excludeRules.length > 0
    || selectors.includePillars.length > 0 || selectors.excludePillars.length > 0;
}

/**
 * Checks whether the effective display selectors specify a severity floor or any rule or pillar filter.
 *
 * @param selectors - display filter settings; when every selector is unset or empty, all received findings stay visible
 * @returns True when a minimum severity or any show/hide rule or pillar filter is active.
 */
export function isDisplayRequested(selectors: DisplaySelectors): boolean {
  return selectors.minSeverity !== undefined || selectors.showRules.length > 0 || selectors.hideRules.length > 0
    || selectors.showPillars.length > 0 || selectors.hidePillars.length > 0;
}

/**
 * Limits the scan before scoring when the user passes rule or pillar execution flags.
 *
 * @param config - analysis settings whose rule map is updated in place
 * @param selectors - execution filters for rules and pillars. Missing or inactive selectors leave the config unchanged.
 * @returns - Nothing. Disables excluded rules in the config while preserving their other settings.
 * @throws {ConfigLoadError} when a selector is unknown or leaves no enabled rules.
 */
export function applyExecutionSelectors(config: Config, selectors: ExecutionSelectors | undefined): void {
  // A run that named no selector keeps the catalogue the user's config already chose.
  if (selectors === undefined || !isExecutionRequested(selectors)) {
    return;
  }
  const unknownRule = [...selectors.includeRules, ...selectors.excludeRules].find((ruleId) => !isKnownRuleId(ruleId));
  // A mistyped rule ID can lead the user to expect coverage that never ran.
  if (unknownRule !== undefined) {
    throw new ConfigLoadError(`Unknown execution selector rule: ${JSON.stringify(unknownRule)}.`, "Use a rule ID from gruff-ts list-rules.", false);
  }
  const unknownPillar = [...selectors.includePillars, ...selectors.excludePillars].find((pillar) => !isPillarName(pillar));
  // A misspelled pillar gets feedback before the CLI can show a misleading empty report.
  if (unknownPillar !== undefined) {
    throw new ConfigLoadError(`Unknown execution selector pillar: ${JSON.stringify(unknownPillar)}.`, "Use a pillar name from gruff-ts list-rules.", false);
  }
  const descriptors = ruleDescriptors();
  // Evaluate the user's include and exclude flags against every rule in the catalogue.
  for (const descriptor of descriptors) {
    // An excluded rule is switched off outright; every other setting the user configured for it survives.
    if (!executionAllows(selectors, descriptor.ruleId, descriptor.pillar)) {
      const existing = config.rules.get(descriptor.ruleId);
      config.rules.set(descriptor.ruleId, { ...existing, options: existing?.options ?? new Map(), enabled: false });
    }
  }
  // If these flags and project settings leave no active rule, the scan cannot produce a meaningful score.
  if (!descriptors.some((descriptor) => config.rules.get(descriptor.ruleId)?.enabled ?? descriptor.isEnabledByDefault !== false)) {
    throw new ConfigLoadError("Execution selectors leave no rules enabled.", "Select an enabled rule or enable a rule in your configuration.", false);
  }
}

/**
 * Evaluates whether a rule and its pillar pass the execution selectors; every non-empty include list must match and either exclude list vetoes.
 *
 * @param selectors - execution include and exclude lists for rules and pillars
 * @param ruleId - identifier of the candidate rule being evaluated
 * @param pillar - pillar to which the candidate rule belongs
 * @returns True if the rule and pillar match all non-empty include lists and appear in neither exclude list.
 */
function executionAllows(selectors: ExecutionSelectors, ruleId: string, pillar: Pillar): boolean {
  // An empty rule include list keeps all rules eligible for the other filters.
  if (selectors.includeRules.length > 0 && !selectors.includeRules.includes(ruleId)) {
    return false;
  }
  // An empty pillar include list keeps all pillars eligible for the other filters.
  if (selectors.includePillars.length > 0 && !selectors.includePillars.includes(pillar)) {
    return false;
  }
  return !selectors.excludeRules.includes(ruleId) && !selectors.excludePillars.includes(pillar);
}

/**
 * Validates every rule ID and pillar name passed to `--show-rule`, `--hide-rule`, `--show-pillar`, or `--hide-pillar`.
 * Rejects typos or retired IDs before rendering so a misspelled display filter cannot silently hide findings.
 *
 * @param selectors - display filter settings whose show/hide rule and pillar lists are checked; empty lists pass immediately
 * @returns Nothing. Completes when every named display selector exists in the active catalogue.
 * @throws {ConfigLoadError} when any show/hide rule ID or pillar name is unknown.
 */
export function validateDisplaySelectors(selectors: DisplaySelectors): void {
  const unknownRule = [...selectors.showRules, ...selectors.hideRules].find((ruleId) => !isKnownRuleId(ruleId));
  // A mistyped or retired rule ID would silently hide or keep findings the user intended to filter.
  if (unknownRule !== undefined) {
    throw new ConfigLoadError(`Unknown display selector rule: ${JSON.stringify(unknownRule)}.`, "Use a rule ID from gruff-ts list-rules.", false);
  }
  const unknownPillar = [...selectors.showPillars, ...selectors.hidePillars].find((pillar) => !isPillarName(pillar));
  // A misspelled pillar gets immediate feedback instead of producing an empty report view.
  if (unknownPillar !== undefined) {
    throw new ConfigLoadError(`Unknown display selector pillar: ${JSON.stringify(unknownPillar)}.`, "Use a pillar name from gruff-ts list-rules.", false);
  }
}

/**
 * Select which findings appear in the report. Stable contract: the score and exit code are already decided.
 * Validates show/hide rule and pillar names before filtering so typos fail loudly instead of silently hiding results.
 *
 * @param findings - scored findings available for display; an empty list still validates selector names and stays empty
 * @param selectors - display restrictions for this run, including any explicit minimum severity
 * @param configuredFloor - project minimum severity used when the run supplies none; undefined applies no config floor
 * @returns A filtered list when an effective restriction is active, or the original list when none is active.
 * @throws {ConfigLoadError} when a display selector names an unknown rule ID or pillar.
 */
export function applyDisplaySelectors(findings: Finding[], selectors: DisplaySelectors, configuredFloor: Severity | undefined): Finding[] {
  validateDisplaySelectors(selectors);
  const floor = selectors.minSeverity ?? configuredFloor;
  const effective: DisplaySelectors = { ...selectors, ...(floor === undefined ? {} : { minSeverity: floor }) };
  // Nothing was asked for, so the report shows exactly what the run found.
  if (!isDisplayRequested(effective)) {
    return findings;
  }
  return findings.filter((finding) => displayAllows(effective, finding));
}

/**
 * Decides whether to show a finding using the severity floor and rule and pillar lists.
 * To pass, the finding must meet any configured floor, match each non-empty show list, and match neither hide list.
 *
 * @param selectors - display filter settings including optional severity floor and show/hide lists
 * @param finding - scored finding evaluated for report visibility
 * @returns True when the finding satisfies the severity floor, show lists, and hide lists.
 */
function displayAllows(selectors: DisplaySelectors, finding: Finding): boolean {
  if (selectors.minSeverity !== undefined && SEVERITY_RANK[finding.severity] < SEVERITY_RANK[selectors.minSeverity]) {
    return false;
  }
  if (selectors.showRules.length > 0 && !selectors.showRules.includes(finding.ruleId)) {
    return false;
  }
  if (selectors.showPillars.length > 0 && !selectors.showPillars.includes(finding.pillar)) {
    return false;
  }
  return !selectors.hideRules.includes(finding.ruleId) && !selectors.hidePillars.includes(finding.pillar);
}
