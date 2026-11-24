// Computes the quality scores and grades a user sees in reports and score history.
//
// A scan scores the rules and files it evaluated. Correlated findings share a penalty when they describe the same declaration.
// CI uses the configured finding threshold to decide whether to pass or fail independently of the score.
import { grade } from "./pillar-summary.ts";
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisReport, Confidence, FailThreshold, Finding, Pillar, Severity } from "./types.ts";

// Every pillar that has at least one rule behind it. The composite averages over this whole set,
// because averaging only finding-bearing pillars let a pillar vanish from the mean the moment its
// last finding was fixed - lowering the headline score for finishing a pillar.
const SCOREABLE_PILLARS: readonly Pillar[] = [...new Set(ruleDescriptors().map((descriptor) => descriptor.pillar))];

// Ratified family scoring parameters. The shape `bounded-normalized-density-floored` was ratified
// 2026-09-01 and these values 2026-09-03; all five ports carry the same numbers, so changing either
// is a family decision rather than a gruff-ts one. SCORE_FLOOR bounds how far one saturated pillar
// can drag the composite; DENSITY_SCALE is the per-file finding density at which a pillar sits half
// way between the floor and 100.
const SCORE_FLOOR = 50;
const DENSITY_SCALE = 0.1;

/**
 * Computes a pillar or file score using the shared density curve, where scaling penalty and file count together preserves the score.
 *
 * @param weight - Summed penalty weight for the pillar or file.
 * @param evaluatedFiles - Number of evaluated files used to normalize the penalty density.
 * @returns Rounded score on the bounded density curve, or null when evaluatedFiles is nonpositive because there is no score to include.
 */
function curveScore(weight: number, evaluatedFiles: number): number | null {
  if (evaluatedFiles <= 0) {
    return null;
  }
  const density = weight / evaluatedFiles;
  return roundScore(SCORE_FLOOR + (100 - SCORE_FLOOR) / (1 + density / DENSITY_SCALE));
}

/**
 * Rounds one score to the ratified two decimals, normalizing negative zero away because JSON
 * projection keeps it in some ports and not others.
 *
 * @param rawScore - Unrounded numeric score to normalize.
 * @returns Score rounded to two decimal places with negative zero normalized to 0.
 */
function roundScore(rawScore: number): number {
  const rounded = Math.round(rawScore * 100) / 100;
  return rounded === 0 ? 0 : rounded;
}

/**
 * Builds the overall grade, pillar scores, and highest-priority files for the user's report.
 * Invariant: each evaluated or finding-bearing pillar appears once, and a clean pillar scores 100 with evaluated files.
 *
 * @param findings - Findings emitted by the scan to aggregate into pillar, cluster, rule, and file scores.
 * @param evaluatedFiles - Count of evaluated files; zero or less yields null scores and grades because there is no measurement.
 * @param evaluatedPillars - Pillars evaluated by the run so clean pillars still appear alongside finding-bearing ones.
 * @returns Report score summary with composite score, grade, evaluated file count, pillars, clusters, rule attribution, and top offenders.
 */
function scoreReport(findings: Finding[], evaluatedFiles: number, evaluatedPillars: Iterable<Pillar> = SCOREABLE_PILLARS): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  const penalties = scoringPenaltyMap(findings);
  // Use each finding in both the pillar breakdown and the list of files a user can address.
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const scoredPillars = [...new Set([...evaluatedPillars, ...byPillar.keys()])];
  const pillars = scoredPillars.map((pillar) => {
    // Evaluated pillars with no findings still appear as clean in the report.
    const pillarFindings = byPillar.get(pillar) ?? [];
    const penalty = roundScore(pillarFindings.reduce((sum, finding) => sum + findingPenalty(penalties, finding), 0));
    const score = curveScore(penalty, evaluatedFiles);
    return { pillar, applicable: true, score, grade: score === null ? null : grade(score), penalty, findings: pillarFindings.length };
  });
  const applicableScores = pillars.flatMap((pillar) => (pillar.score === null ? [] : [pillar.score]));
  // Without evaluated files, pillars and the composite have null scores and grades because the scan has no measurement.
  const composite =
    applicableScores.length === 0 ? null : roundScore(applicableScores.reduce((sum, score) => sum + score, 0) / applicableScores.length);
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => {
      // A file's density is its own weighted findings, so file and project scores share one curve.
      const penalty = roundScore(fileFindings.reduce((sum, finding) => sum + findingPenalty(penalties, finding), 0));
      return { filePath, score: evaluatedFiles <= 0 ? null : curveScore(penalty, 1), penalty, findings: fileFindings.length };
    })
    .sort((left, right) => (left.score ?? 100) - (right.score ?? 100));
  return {
    composite,
    grade: composite === null ? null : grade(composite),
    evaluatedFiles,
    scoredPillars,
    clusters: correlatedClusters(findings, penalties),
    ruleAttribution: ruleAttribution(findings, penalties),
    pillars,
    topOffenders,
  };
}

/**
 * Builds cluster rows for groups of at least two supplied correlated findings sharing a file and symbol in stable file and symbol order.
 *
 * @param findings - Findings to group by correlated complexity cluster key.
 * @param penalties - Precomputed penalty map summed per group, falling back to normal finding weight for missing entries.
 * @returns Cluster rows sorted by file and symbol with sorted rule IDs, counts, and rounded weights, or empty when no group qualifies.
 */
function correlatedClusters(findings: Finding[], penalties: ReadonlyMap<Finding, number>): AnalysisReport["score"]["clusters"] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = complexityClusterKey(finding);
    if (key) {
      groups.set(key, [...(groups.get(key) ?? []), finding]);
    }
  }
  return [...groups.values()]
    // A lone correlated finding billed its own full weight, so it is not a cluster to report.
    .filter((group) => group.length >= 2)
    .map((group) => ({
      file: group[0]!.filePath,
      symbol: String(group[0]!.symbol),
      ruleIds: group.map((finding) => finding.ruleId).sort(),
      findings: group.length,
      weight: roundScore(group.reduce((sum, finding) => sum + findingPenalty(penalties, finding), 0)),
    }))
    .sort((left, right) => left.file.localeCompare(right.file) || left.symbol.localeCompare(right.symbol));
}

/**
 * Aggregates finding counts and rounded scoring penalties by native rule ID in stable rule ID order.
 * The attribution contract keeps the native rule ID even when reporting groups concepts.
 *
 * @param findings - Findings to tally by rule ID; rules with no findings produce no row.
 * @param penalties - Precomputed penalty map used per finding, falling back to normal finding weight when an entry is missing.
 * @returns Attribution entries sorted by native rule ID with finding counts and rounded total weights.
 */
function ruleAttribution(findings: Finding[], penalties: ReadonlyMap<Finding, number>): AnalysisReport["score"]["ruleAttribution"] {
  const totals = new Map<string, { findings: number; weight: number }>();
  for (const finding of findings) {
    const entry = totals.get(finding.ruleId) ?? { findings: 0, weight: 0 };
    totals.set(finding.ruleId, { findings: entry.findings + 1, weight: entry.weight + findingPenalty(penalties, finding) });
  }
  return [...totals.entries()]
    .map(([ruleId, entry]) => ({ ruleId, findings: entry.findings, weight: roundScore(entry.weight) }))
    .sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

/**
 * Computes severity tallies emitted in native analysis state, where the four-key shape
 * (advisory/warning/error/total) is nested under summary.findings by the v3 machine adapter.
 *
 * @param findings - Findings to count across advisory, warning, error, and total; total must match the findings array length.
 * @returns Object containing advisory, warning, error, and total counts.
 */
function summarize(findings: Finding[]) {
  return {
    advisory: findings.filter((finding) => finding.severity === "advisory").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    error: findings.filter((finding) => finding.severity === "error").length,
    total: findings.length,
  };
}

/**
 * Apply the three-value exit contract used by CI and the dashboard, with invalidating diagnostics taking precedence over findings.
 * Diagnostics invalidate the run by default. An explicit false leaves the finding gate in effect.
 *
 * @param report - Analysis results whose diagnostics and findings determine the exit status.
 * @param failOn - Minimum severity for a finding to fail the gate. The none setting disables the finding gate.
 * @param minConfidence - Confidence floor a finding must also meet. The default low admits all finding confidence levels.
 * @returns 2 for any run-invalidating diagnostic, otherwise 1 if any finding meets both floors, otherwise 0.
 */
function exitFor(report: AnalysisReport, failOn: FailThreshold, minConfidence: Confidence = "low"): number {
  if (report.diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false)) {
    return 2;
  }
  return report.findings.some((finding) => reachesGate(finding, failOn, minConfidence)) ? 1 : 0;
}

/**
 * Checks whether a finding meets both the severity floor and the confidence floor; both must pass to reach the gate.
 *
 * @param finding - Finding whose severity and confidence are evaluated against the gate floors.
 * @param failOn - Minimum severity threshold; setting it to none always returns false so findings cannot fail the run.
 * @param minConfidence - Minimum confidence rank required alongside the severity floor.
 * @returns True if finding satisfies both failOn and minConfidence, otherwise false.
 */
function reachesGate(finding: Finding, failOn: FailThreshold, minConfidence: Confidence): boolean {
  return thresholdTriggered(failOn, finding.severity) && CONFIDENCE_GATE_RANK[finding.confidence] >= CONFIDENCE_GATE_RANK[minConfidence];
}

// Confidence ladder for the gate; a finding at or above the requested rank can reach it.
const CONFIDENCE_GATE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

/**
 * Checks whether a finding's severity reaches the configured failure threshold, where warning is a floor
 * that includes warnings and errors because higher severities qualify, and error includes only errors.
 *
 * @param thresholdValue - Configured failure threshold; none never triggers, and advisory includes every severity.
 * @param severity - Finding severity to compare against thresholdValue.
 * @returns True when severity meets or exceeds thresholdValue, otherwise false.
 */
function thresholdTriggered(thresholdValue: FailThreshold, severity: Severity): boolean {
  if (thresholdValue === "none") {
    return false;
  }
  if (thresholdValue === "advisory") {
    return true;
  }
  if (thresholdValue === "warning") {
    return severity === "warning" || severity === "error";
  }
  return severity === "error";
}

/**
 * Returns the ratified family severity weight, identical in all five ports so changing it is a family decision.
 *
 * @param severity - Finding severity level to map to its base weight.
 * @returns Numeric scoring weight: 12 for error, 4 for warning, or 1 for advisory.
 */
function severityPenalty(severity: Severity): number {
  return severity === "error" ? 12 : severity === "warning" ? 4 : 1;
}

/**
 * Maps finding confidence to its multiplier so scoring density charges uncertain findings less than high-confidence ones.
 *
 * @param confidence - Confidence level of a finding.
 * @returns Multiplier for severity weight: 1 for high, 0.75 for medium, or 0.5 for low.
 */
function confidenceWeight(confidence: Confidence): number {
  return confidence === "high" ? 1 : confidence === "medium" ? 0.75 : 0.5;
}

/**
 * Computes one finding's ratified weight by multiplying its severity weight by its confidence weight.
 * Invariant: the weight is never negative, and a low-confidence finding always weighs less than the same severity at high confidence.
 *
 * @param finding - Finding whose severity and confidence determine its weight.
 * @returns Non-negative product of severityPenalty and confidenceWeight.
 */
function findingWeight(finding: Finding): number {
  return severityPenalty(finding.severity) * confidenceWeight(finding.confidence);
}

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cyclomatic", "size.function-length"]);

/**
 * Builds a scoring penalty map keyed by the input findings, where unclustered findings and singleton clusters keep their own weight.
 * Invariant: findings in a complexity cluster share its highest weight equally so that one function incurs one combined penalty.
 *
 * @param findings - Findings to assign individual or cluster-shared scoring penalties.
 * @returns Map from each finding to its effective scoring penalty.
 */
function scoringPenaltyMap(findings: Finding[]): Map<Finding, number> {
  const penalties = new Map<Finding, number>();
  const clusters = new Map<string, Finding[]>();
  for (const finding of findings) {
    penalties.set(finding, findingWeight(finding));
    const key = complexityClusterKey(finding);
    if (key) {
      clusters.set(key, [...(clusters.get(key) ?? []), finding]);
    }
  }
  for (const cluster of clusters.values()) {
    if (cluster.length < 2) {
      continue;
    }
    const sharedPenalty = Math.max(...cluster.map(findingWeight)) / cluster.length;
    cluster.forEach((finding) => penalties.set(finding, sharedPenalty));
  }
  return penalties;
}

/**
 * Derives a grouping key for related complexity findings on one declaration so the report can share their penalty.
 * Invariant: findings without a symbol or a matching rule keep their own penalty and return no group key.
 *
 * @param finding - Finding to inspect for declaration identity and correlated complexity rule membership.
 * @returns Composite file and declaration key when correlated, or undefined when the finding stays unclustered.
 */
function complexityClusterKey(finding: Finding): string | undefined {
  // Without a declaration to match, keep the finding visible as its own contribution to the score.
  if (!finding.symbol || !CORRELATED_COMPLEXITY_RULE_IDS.has(finding.ruleId)) {
    return undefined;
  }
  // Prefer the declaration identity when present so same-named functions can receive separate penalties.
  return `${finding.filePath}\0${finding.baselineSubject ?? finding.symbol}`;
}

/**
 * Resolves a finding's effective penalty from precomputed penalties or falls back to its individual weight.
 * Invariant: returns the finding's precomputed penalty, including zero, when present in the map.
 *
 * @param penalties - Precomputed penalty lookup keyed by finding instance.
 * @param finding - Finding whose effective penalty is needed.
 * @returns Precomputed penalty from penalties, or findingWeight when the map has no entry.
 */
function findingPenalty(penalties: ReadonlyMap<Finding, number>, finding: Finding): number {
  return penalties.get(finding) ?? findingWeight(finding);
}

/**
 * Shows how each severity scores in the human summary. Each bucket applies its severity penalty with a zero floor.
 * The breakdown belongs to the summary and keeps the gruff.analysis.v3 report schema stable.
 *
 * @param findings - findings to count by their reported severity
 * @returns - count, score and letter grade for each severity. A bucket with no findings scores 100.
 */
function severityGradeBreakdown(findings: Finding[]): {
  error: { grade: string; score: number; count: number };
  warning: { grade: string; score: number; count: number };
  advisory: { grade: string; score: number; count: number };
} {
  const counts = { error: 0, warning: 0, advisory: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return {
    error: severityBucket("error", counts.error),
    warning: severityBucket("warning", counts.warning),
    advisory: severityBucket("advisory", counts.advisory),
  };
}

/**
 * Computes a linear severity-only bucket score and grade clamped at zero, without using the project density curve or confidence weights.
 *
 * @param severity - Severity level whose base penalty scales the bucket deduction.
 * @param count - Number of findings recorded at the supplied severity.
 * @returns Bucket containing the letter grade, clamped score, and finding count.
 */
function severityBucket(severity: Severity, count: number): { grade: string; score: number; count: number } {
  const score = Math.max(0, 100 - count * severityPenalty(severity));
  return { grade: grade(score), score, count };
}

/**
 * Formats one composite score line for text reports, using a shared message when either score or grade is null.
 *
 * @param composite - Numeric composite score, or null when nothing was evaluated.
 * @param gradeLetter - Letter grade label for the composite score, or null when nothing was evaluated.
 * @returns Formatted composite line, or the shared nothing-evaluated message if either input is null.
 */
function compositeLine(composite: number | null, gradeLetter: string | null): string {
  return composite === null || gradeLetter === null
    ? "Composite: n/a (nothing evaluated)"
    : `Composite: ${gradeLetter} (${composite.toFixed(2)} / 100)`;
}

export { compositeLine, scoreReport, summarize, exitFor, severityGradeBreakdown };
