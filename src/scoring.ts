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

// Applies the ratified pillar curve to one summed weight. Dividing by the evaluated-file count
// before transforming is what makes a duplicated project score the same as the original: twice the
// findings over twice the code is one ratio. Returns null when nothing was evaluated, because an
// empty scan has no health to report and a number here would present it as perfect.
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

// Builds the native per-pillar and per-file score breakdown. The v3 JSON adapter preserves these
// values while reshaping the composite and offender paths for the family envelope. The composite is
// the mean over every rule-backed pillar, with a clean pillar counting as 100, so removing a finding
// can never decrease it. Every scoreable pillar gets a row now, not only the finding-bearing ones,
// so a reader can tell a reachable clean pillar from one no rule can reach.
// `topOffenders` is the full file list sorted worst-first; renderers cap it themselves.
// Invariant: every scoreable pillar appears exactly once, a clean pillar scores 100, and the
// composite is null only when no pillar could be scored at all.
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
  // No pillar had an opinion, so there is no composite. Returning 100 here is what let an empty
  // directory grade A before the M06 break.
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

// Lists every correlated concept that billed one shared weight, so a reader can see which findings
// the grade counted once rather than inferring it from a total lower than the sum of its parts.
// Invariant: every published cluster holds two or more findings sharing one file and symbol, its
// weight never exceeds what those findings would carry unclustered, and the rows are sorted by file
// then symbol so two runs over unchanged input publish the same bytes.
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

// Reports how much weight each native rule removed from the score. The key is the native ruleId: a
// conceptId may group reporting, but the ratified contract never makes it the attribution key.
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

/*
 * Process exit contract: 2 when diagnostics were emitted (parse/IO failures the user must know about),
 * 1 when any finding crosses both `failOn` and `minConfidence`, 0 otherwise. CI scripts and the dashboard
 * runner depend on this three-value invariant; reshuffling the precedence is a stable-contract regression.
 *
 * The two floors are independent: severity says how much a finding matters, confidence says how sure the
 * analyser is, and either one alone can keep a finding away from the gate. `minConfidence` defaults to `low`,
 * which admits everything and leaves a caller that never asked for a confidence floor unaffected.
 */
function exitFor(report: AnalysisReport, failOn: FailThreshold, minConfidence: Confidence = "low"): number {
  if (report.diagnostics.some((diagnostic) => diagnostic.invalidatesRun !== false)) {
    return 2;
  }
  return report.findings.some((finding) => reachesGate(finding, failOn, minConfidence)) ? 1 : 0;
}

// True when one finding clears both floors, which is the only way a run fails on findings.
// Stable contract: severity and confidence are independent, so either floor alone can keep a finding away from the gate.
function reachesGate(finding: Finding, failOn: FailThreshold, minConfidence: Confidence): boolean {
  return thresholdTriggered(failOn, finding.severity) && CONFIDENCE_GATE_RANK[finding.confidence] >= CONFIDENCE_GATE_RANK[minConfidence];
}

// Confidence ladder for the gate; a finding at or above the requested rank can reach it.
const CONFIDENCE_GATE_RANK: Record<Confidence, number> = { low: 0, medium: 1, high: 2 };

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

// Ratified family severity weights, identical in all five ports. Changing them is a family
// decision. The error weight rose from 8 and the advisory weight fell from 1.5 at the M06 break,
// so every historical score and every grade letter in `scores.jsonl` moves.
function severityPenalty(severity: Severity): number {
  return severity === "error" ? 12 : severity === "warning" ? 4 : 1;
}

// Ratified confidence weights. gruff-ts had no confidence dimension before M06: a low-confidence
// heuristic finding weighed exactly as much as a high-confidence one, so a noisy rule could drag a
// pillar as hard as a certain defect. The ratified density multiplies severity by confidence.
function confidenceWeight(confidence: Confidence): number {
  return confidence === "high" ? 1 : confidence === "medium" ? 0.75 : 0.5;
}

// One finding's ratified weight: its severity weight multiplied by its confidence weight.
// Invariant: the weight is never negative, and a low-confidence finding always weighs less than the
// same severity at high confidence.
function findingWeight(finding: Finding): number {
  return severityPenalty(finding.severity) * confidenceWeight(finding.confidence);
}

const CORRELATED_COMPLEXITY_RULE_IDS = new Set(["complexity.cognitive", "complexity.cyclomatic", "size.function-length"]);

// Correlated complexity findings describe one hard-to-review function.
// Invariant: detailed reports keep every rule finding while grade math splits one max-severity penalty.
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

// The ratified contract keys clustering on project-relative file and qualified symbol without line
// identity, because correlated rules disagree about which line to report and a line in the key splits
// one root cause into two.
// Invariant: symbol grouping prevents unrelated functions in the same file from sharing score relief.
function complexityClusterKey(finding: Finding): string | undefined {
  if (!finding.symbol || !CORRELATED_COMPLEXITY_RULE_IDS.has(finding.ruleId)) {
    return undefined;
  }
  return `${finding.filePath}\0${finding.symbol}`;
}

// Invariant: one finding uses one precomputed score penalty or the normal severity weight fallback.
function findingPenalty(penalties: ReadonlyMap<Finding, number>, finding: Finding): number {
  return penalties.get(finding) ?? findingWeight(finding);
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

// Renders one canonical composite line. A run that evaluated nothing has no composite, and every
// gruff-ts surface says so in the same words rather than printing a number that reads as a grade.
function compositeLine(composite: number | null, gradeLetter: string | null): string {
  return composite === null || gradeLetter === null
    ? "Composite: n/a (nothing evaluated)"
    : `Composite: ${gradeLetter} (${composite.toFixed(2)} / 100)`;
}

export { compositeLine, scoreReport, summarize, exitFor, severityGradeBreakdown };
