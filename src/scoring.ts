// Score, grade, and fail-on helpers derived from finding severities for reports and CLI exits.
import { grade } from "./pillar-summary.ts";
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisReport, FailThreshold, Finding, Pillar, Severity } from "./types.ts";

// Every pillar that has at least one rule behind it. The composite averages over this whole set,
// because averaging only finding-bearing pillars let a pillar vanish from the mean the moment its
// last finding was fixed - lowering the headline score for finishing a pillar.
const SCOREABLE_PILLARS: readonly Pillar[] = [...new Set(ruleDescriptors().map((descriptor) => descriptor.pillar))];

// Builds the native per-pillar and per-file score breakdown. The v3 JSON adapter preserves these
// values while reshaping the composite and offender paths for the family envelope. The composite
// is the mean over every rule-backed pillar, with a clean pillar counting as 100, so removing a
// finding can never decrease it. The `pillars` array lists only finding-bearing pillars.
// `topOffenders` is the full file list sorted worst-first; renderers cap it themselves.
// Invariant: clean pillars count as 100, removing a finding cannot lower the composite, and values
// remain unchanged when the v3 adapter reshapes them.
function scoreReport(findings: Finding[]): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  const penalties = scoringPenaltyMap(findings);
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const pillars = [...byPillar.entries()].map(([pillar, pillarFindings]) => {
    const penalty = pillarFindings.reduce((sum, finding) => sum + findingPenalty(penalties, finding), 0);
    return { pillar, score: Math.max(0, 100 - penalty), penalty, findings: pillarFindings.length };
  });
  const scoredPillarTotal = pillars.reduce((sum, pillar) => sum + pillar.score, 0);
  const cleanPillarCount = Math.max(0, SCOREABLE_PILLARS.length - pillars.length);
  const composite = SCOREABLE_PILLARS.length === 0 ? 100 : (scoredPillarTotal + 100 * cleanPillarCount) / SCOREABLE_PILLARS.length;
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => ({
      filePath,
      score: Math.max(0, 100 - fileFindings.reduce((sum, finding) => sum + findingPenalty(penalties, finding), 0)),
      findings: fileFindings.length,
    }))
    .sort((left, right) => left.score - right.score);
  return { composite, grade: grade(composite), pillars, topOffenders };
}

// Severity tallies emitted in native analysis state. The four-key shape
// (advisory/warning/error/total) is nested under `summary.findings` by the v3 machine adapter, and
// `total` must match the findings array length.
function summarize(findings: Finding[]) {
  return {
    advisory: findings.filter((finding) => finding.severity === "advisory").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    error: findings.filter((finding) => finding.severity === "error").length,
    total: findings.length,
  };
}

// Process exit contract: 2 when diagnostics were emitted (parse/IO failures the user must know about),
// 1 when any finding crosses `failOn`, 0 otherwise. CI scripts and the dashboard runner depend on
// this three-value invariant; reshuffling the precedence is a stable-contract regression.
function exitFor(report: AnalysisReport, failOn: FailThreshold): number {
  if (report.diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false)) {
    return 2;
  }
  return report.findings.some((finding) => thresholdTriggered(failOn, finding.severity)) ? 1 : 0;
}

// Severity ladder: "none" never triggers, "advisory" triggers on anything, "warning" needs at least
// warning, "error" needs error. Order is intentional - `failOn=warning` must still trigger on errors.
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

// Penalty weights tuned so a handful of errors visibly drag a pillar below a passing grade while
// a long tail of advisories cannot single-handedly fail a healthy pillar. Adjusting these shifts
// every historical score and the grade letters in `scores.jsonl`.
function severityPenalty(severity: Severity): number {
  return severity === "error" ? 8 : severity === "warning" ? 4 : 1.5;
}

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cognitive", "complexity.cyclomatic", "size.function-length"]);

// Correlated complexity findings describe one hard-to-review function.
// Invariant: detailed reports keep every rule finding while grade math splits one max-severity penalty.
function scoringPenaltyMap(findings: Finding[]): Map<Finding, number> {
  const penalties = new Map<Finding, number>();
  const clusters = new Map<string, Finding[]>();
  for (const finding of findings) {
    penalties.set(finding, severityPenalty(finding.severity));
    const key = complexityClusterKey(finding);
    if (key) {
      clusters.set(key, [...(clusters.get(key) ?? []), finding]);
    }
  }
  for (const cluster of clusters.values()) {
    if (cluster.length < 2) {
      continue;
    }
    const sharedPenalty = Math.max(...cluster.map((finding) => severityPenalty(finding.severity))) / cluster.length;
    cluster.forEach((finding) => penalties.set(finding, sharedPenalty));
  }
  return penalties;
}

// Invariant: line+symbol grouping prevents unrelated functions in the same file from sharing score relief.
function complexityClusterKey(finding: Finding): string | undefined {
  if (!finding.symbol || !finding.line || !CORRELATED_COMPLEXITY_RULE_IDS.has(finding.ruleId)) {
    return undefined;
  }
  return `${finding.filePath}\0${finding.symbol}\0${finding.line}`;
}

// Invariant: one finding uses one precomputed score penalty or the normal severity weight fallback.
function findingPenalty(penalties: ReadonlyMap<Finding, number>, finding: Finding): number {
  return penalties.get(finding) ?? severityPenalty(finding.severity);
}

/*
 * Per-severity grade breakdown for the human summary block. The composite headline alone hides the
 * fact that an F can be driven entirely by advisories (goat-flow scan: F at 12.9 with 0 errors / 276
 * warnings / 1367 advisories). Mirrors the existing pillar formula `100 - count * severityPenalty`
 * so the math stays consistent with how a single-rule pillar would score. The report-shape
 * invariant matters: severity breakdowns and correlated complexity clustering must not add native
 * score fields or change the `gruff.analysis.v3` machine envelope.
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

// Single severity bucket using the same `score = max(0, 100 - count * penalty)` formula as the
// pillar reduce in `scoreReport`. Returns the bucket plus its grade letter so renderers don't have
// to import `grade` separately.
function severityBucket(severity: Severity, count: number): { grade: string; score: number; count: number } {
  const score = Math.max(0, 100 - count * severityPenalty(severity));
  return { grade: grade(score), score, count };
}

export { scoreReport, summarize, exitFor, severityGradeBreakdown };
