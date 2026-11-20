// Score, grade, and fail-on helpers derived from finding severities for reports and CLI exits.
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

// Returns a pillar or file score using the shared density curve. weight is the summed penalty, and evaluatedFiles is the file count.
// Scaling the penalty and file count together preserves the score. A nonpositive file count returns null because there is no score to include.
function curveScore(weight: number, evaluatedFiles: number): number | null {
  if (evaluatedFiles <= 0) {
    return null;
  }
  const density = weight / evaluatedFiles;
  return roundScore(SCORE_FLOOR + (100 - SCORE_FLOOR) / (1 + density / DENSITY_SCALE));
}

// Rounds one score to the ratified two decimals, normalizing negative zero away because JSON
// projection keeps it in some ports and not others.
function roundScore(rawScore: number): number {
  const rounded = Math.round(rawScore * 100) / 100;
  return rounded === 0 ? 0 : rounded;
}

// Returns the native score breakdown, using the scan findings as penalties and the evaluated-file count to normalize pillar scores.
// Invariant: each rule-backed or finding-bearing pillar appears once. With evaluated files, a clean pillar scores 100.
// The composite averages numeric pillar scores. Only files with findings are listed, lowest score first or unscored when no files were evaluated.
function scoreReport(findings: Finding[], evaluatedFiles: number): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  const penalties = scoringPenaltyMap(findings);
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const scoredPillars = [...new Set([...SCOREABLE_PILLARS, ...byPillar.keys()])];
  const pillars = scoredPillars.map((pillar) => {
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

// Return cluster rows for groups of at least two supplied correlated findings sharing a file and symbol. No qualifying group means no rows.
// Sum the supplied penalties, using the normal finding weight for a missing entry, so readers can see the group's charge.
// Stable file and symbol order keeps unchanged cluster rows comparable across runs.
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

// Return finding counts and rounded scoring penalties by native rule ID, in stable rule ID order.
// Tally the supplied findings using the precomputed penalties, or the normal finding weight for entries missing from the map.
// Rules with no findings have no row. The attribution contract keeps the native rule ID even when reporting groups concepts.
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

// Severity tallies emitted in native analysis state. The four-key shape
// (advisory/warning/error/total) is nested under summary.findings by the v3 machine adapter, and
// total must match the findings array length.
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

// Return whether finding reaches the severity floor failOn and the confidence floor minConfidence; both must pass.
// failOn set to none always returns false, so findings cannot fail the run.
function reachesGate(finding: Finding, failOn: FailThreshold, minConfidence: Confidence): boolean {
  return thresholdTriggered(failOn, finding.severity) && CONFIDENCE_GATE_RANK[finding.confidence] >= CONFIDENCE_GATE_RANK[minConfidence];
}

// Confidence ladder for the gate; a finding at or above the requested rank can reach it.
const CONFIDENCE_GATE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

// Returns whether the finding's severity reaches the configured failure threshold.
// None never triggers, and advisory includes every severity.
// Warning includes warnings and errors because it is a floor. Error includes only errors.
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

// Ratified family severity weights, identical in all five ports. Changing them is a family
// decision. Return severity's scoring weight: 12 for error, 4 for warning, or 1 for advisory.
function severityPenalty(severity: Severity): number {
  return severity === "error" ? 12 : severity === "warning" ? 4 : 1;
}

// Return confidence's multiplier: 1 for high, 0.75 for medium, or 0.5 for low.
// The scoring density multiplies severity by this weight so uncertain findings cost less.
function confidenceWeight(confidence: Confidence): number {
  return confidence === "high" ? 1 : confidence === "medium" ? 0.75 : 0.5;
}

// One finding's ratified weight: its severity weight multiplied by its confidence weight.
// Invariant: the weight is never negative, and a low-confidence finding always weighs less than the
// same severity at high confidence.
function findingWeight(finding: Finding): number {
  return severityPenalty(finding.severity) * confidenceWeight(finding.confidence);
}

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cyclomatic", "size.function-length"]);

// Returns a scoring penalty map keyed by the input findings. Unclustered findings and singleton clusters keep their own weight.
// Invariant: findings in a complexity cluster share its highest weight equally so that one function incurs one combined penalty.
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

// Return the file-and-symbol key for a finding from a correlated complexity rule.
// Return undefined if the symbol is missing or the rule is outside that set, so the finding keeps its own penalty.
// The stable key excludes the line because related rules can report the same function at different lines.
function complexityClusterKey(finding: Finding): string | undefined {
  if (!finding.symbol || !CORRELATED_COMPLEXITY_RULE_IDS.has(finding.ruleId)) {
    return undefined;
  }
  return `${finding.filePath}\0${finding.symbol}`;
}

// Invariant: returns the finding's precomputed penalty, including zero, or its severity and confidence weight when the map has no entry.
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

// Return a grade, score, and count for count findings at the supplied severity, using a linear severity-only penalty clamped at zero.
// This summary bucket does not use the project density curve or confidence weights.
function severityBucket(severity: Severity, count: number): { grade: string; score: number; count: number } {
  const score = Math.max(0, 100 - count * severityPenalty(severity));
  return { grade: grade(score), score, count };
}

// Format one composite line for text reports, with a shared message for runs that evaluated nothing.
// composite is the numeric score and gradeLetter its label; either null value returns the nothing-evaluated message.
function compositeLine(composite: number | null, gradeLetter: string | null): string {
  return composite === null || gradeLetter === null
    ? "Composite: n/a (nothing evaluated)"
    : `Composite: ${gradeLetter} (${composite.toFixed(2)} / 100)`;
}

export { compositeLine, scoreReport, summarize, exitFor, severityGradeBreakdown };
