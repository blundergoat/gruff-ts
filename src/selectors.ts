/*
 * The two families of rule selector, kept apart because they answer different questions.
 *
 * An execution selector decides which rules run, so the score moves with it and a hidden problem is genuinely not
 * counted. A presentation selector decides what the report shows, so the score, the summary's denominator and the
 * exit code stay exactly what the full run produced.
 *
 * Mixing the two is the failure this module exists to prevent: a user who narrowed their screen to one rule must
 * not be told their project improved (FAMILY-CONTRACT.md, search: `## 7. CLI surface`).
 */
import { ruleDescriptors } from "./rules.ts";
import type { Config, ExecutionSelectors, Finding, Pillar, Severity } from "./types.ts";

// Severity ladder for the display floor; a finding at or above the requested rank is shown.
const SEVERITY_RANK: Record<Severity, number> = { advisory: 0, warning: 1, error: 2 };

/*
 * What the finished report shows, chosen by `--min-severity`, `--show-rule`, `--hide-rule`, `--show-pillar` and
 * `--hide-pillar`. None of these changes what ran, so none of them moves the score.
 */
export interface DisplaySelectors {
  minSeverity?: Severity;
  showRules: string[];
  hideRules: string[];
  showPillars: string[];
  hidePillars: string[];
}

// Returns whether selectors contains rule or pillar include/exclude entries; false preserves the configured rule enablement.
export function isExecutionRequested(selectors: ExecutionSelectors): boolean {
  return selectors.includeRules.length > 0 || selectors.excludeRules.length > 0
    || selectors.includePillars.length > 0 || selectors.excludePillars.length > 0;
}

// Returns true when the effective selectors specify a severity floor or a rule or pillar filter.
// With every selector unset or empty, the display keeps all findings it receives.
export function isDisplayRequested(selectors: DisplaySelectors): boolean {
  return selectors.minSeverity !== undefined || selectors.showRules.length > 0 || selectors.hideRules.length > 0
    || selectors.showPillars.length > 0 || selectors.hidePillars.length > 0;
}

/**
 * Turns off rules excluded by execution selectors before scanning because a rule that never runs cannot lower the score.
 * Display filters only change which findings are shown.
 *
 * @param config - analysis settings whose rule map is updated in place
 * @param selectors - execution filters for rules and pillars. Missing or inactive selectors leave the config unchanged.
 * @returns - Nothing. Disables excluded rules in the config while preserving their other settings.
 */
export function applyExecutionSelectors(config: Config, selectors: ExecutionSelectors | undefined): void {
  // A run that named no selector keeps the catalogue the user's config already chose.
  if (selectors === undefined || !isExecutionRequested(selectors)) {
    return;
  }
  for (const descriptor of ruleDescriptors()) {
    // An excluded rule is switched off outright; every other setting the user configured for it survives.
    if (!executionAllows(selectors, descriptor.ruleId, descriptor.pillar)) {
      const existing = config.rules.get(descriptor.ruleId);
      config.rules.set(descriptor.ruleId, { ...existing, options: existing?.options ?? new Map(), enabled: false });
    }
  }
}

// Returns whether ruleId and its pillar pass selectors: every nonempty include list must match, and either exclude list vetoes.
function executionAllows(selectors: ExecutionSelectors, ruleId: string, pillar: Pillar): boolean {
  if (selectors.includeRules.length > 0 && !selectors.includeRules.includes(ruleId)) {
    return false;
  }
  if (selectors.includePillars.length > 0 && !selectors.includePillars.includes(pillar)) {
    return false;
  }
  return !selectors.excludeRules.includes(ruleId) && !selectors.excludePillars.includes(pillar);
}

/**
 * Select which findings appear in the report. Stable contract: the score and exit code are already decided.
 *
 * @param findings - scored findings available for display
 * @param selectors - display restrictions for this run, including any explicit minimum severity
 * @param configuredFloor - project minimum severity used when the run supplies none
 * @returns A filtered list when an effective restriction is active, or the original list when none is active.
 */
export function applyDisplaySelectors(findings: Finding[], selectors: DisplaySelectors, configuredFloor: Severity | undefined): Finding[] {
  const floor = selectors.minSeverity ?? configuredFloor;
  const effective: DisplaySelectors = { ...selectors, ...(floor === undefined ? {} : { minSeverity: floor }) };
  // Nothing was asked for, so the report shows exactly what the run found.
  if (!isDisplayRequested(effective)) {
    return findings;
  }
  return findings.filter((finding) => displayAllows(effective, finding));
}

// Uses the severity floor and the rule and pillar lists in selectors to decide whether to show a finding.
// To return true, the finding must meet any configured floor, match each nonempty show list, and match neither hide list.
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
