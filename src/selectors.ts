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

// True when the user actually asked to narrow what runs; an untouched run keeps the whole catalogue.
export function isExecutionRequested(selectors: ExecutionSelectors): boolean {
  return selectors.includeRules.length > 0 || selectors.excludeRules.length > 0
    || selectors.includePillars.length > 0 || selectors.excludePillars.length > 0;
}

// True when the user actually asked to narrow the report; an untouched run shows everything it found.
export function isDisplayRequested(selectors: DisplaySelectors): boolean {
  return selectors.minSeverity !== undefined || selectors.showRules.length > 0 || selectors.hideRules.length > 0
    || selectors.showPillars.length > 0 || selectors.hidePillars.length > 0;
}

/*
 * Turns off every rule the execution selectors exclude, before anything is scanned.
 *
 * Disabling in the config rather than filtering afterwards is what makes the score honest: a rule that never ran
 * cannot penalise the project, which is the whole difference between `--include-rule` and `--show-rule`.
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

// Decides whether one catalogue rule survives the execution selectors: an include list narrows, an exclude list cuts.
function executionAllows(selectors: ExecutionSelectors, ruleId: string, pillar: Pillar): boolean {
  if (selectors.includeRules.length > 0 && !selectors.includeRules.includes(ruleId)) {
    return false;
  }
  if (selectors.includePillars.length > 0 && !selectors.includePillars.includes(pillar)) {
    return false;
  }
  return !selectors.excludeRules.includes(ruleId) && !selectors.excludePillars.includes(pillar);
}

/*
 * Hides from the report every finding the presentation selectors exclude, leaving the score untouched.
 *
 * The configured `minimumSeverity:` floor applies when the user passed no `--min-severity`; typing the flag is the
 * user overriding their own project default for this one run.
 *
 * Stable contract: this runs after the score and the exit code are decided, so hiding a finding never improves either.
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

// Decides whether one finding is shown: it must clear the floor, survive the hide lists, and be in any show list.
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
