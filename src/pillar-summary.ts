/*
 * Shared pillar-row construction and grade helper for CLI text, Markdown, HTML, and dashboard reports.
 *
 * Lives in its own module so renderers (`report-renderers.ts`, `report-html.ts`) and scoring (`scoring.ts`) share one implementation without cycles:
 * - preserves the cross-port human Pillars table sort order (findings descending, then pillar ascending);
 * - keeps unevaluated pillars (`score: null`) explicitly labeled `n/a` instead of reporting a synthetic `A/100`.
 */
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisReport, Finding, Pillar } from "./types.ts";

// Aggregated per-pillar row shared across text, Markdown, and HTML renderers.
//
// `isApplicable` comes from the rule catalogue so a clean pillar with zero findings still appears in the Pillars table.
// `score` is `null` (with `grade: "n/a"`) when the report explicitly marks the pillar unevaluated, such as a zero-file scan.
interface PillarRow {
  pillar: Pillar;
  grade: string;
  score: number | null;
  penalty: number;
  isApplicable: boolean;
  findings: number;
  advisory: number;
  warning: number;
  error: number;
}

// Per-pillar severity tally for pillars with at least one finding; exported for consumers of `countSeverityByPillar`.
interface PillarSeverityCounts {
  advisory: number;
  warning: number;
  error: number;
}

/**
 * Builds the shared pillar summary for text, Markdown, and HTML reports.
 * Keeps one row per applicable pillar even when there are no findings so consecutive runs compare the same table shape.
 *
 * @param report - analysis report supplying pillar scores and findings to tally by severity; an empty findings list still emits every pillar
 * @returns Deterministic rows in findings DESC, pillar ASC order. Unevaluated null scores keep `n/a`; absent entries default to A/100.
 */
function buildPillarRows(report: AnalysisReport): PillarRow[] {
  const scoreByPillar = new Map(report.score.pillars.map((entry) => [entry.pillar, entry] as const));
  const severityByPillar = countSeverityByPillar(report.findings);
  const rows: PillarRow[] = [...applicablePillarSet()].map((pillar) => buildPillarRow(pillar, scoreByPillar.get(pillar), severityByPillar.get(pillar)));
  rows.sort(comparePillarRows);
  return rows;
}

/**
 * Tallies severity counts by pillar from the report's findings for the stable Pillars table schema.
 * A pillar with no findings has no map entry, so the row builder supplies its zero counts.
 *
 * @param findings - reported findings whose pillar and severity values are tallied; an empty array yields an empty map
 * @returns Map of per-pillar advisory, warning, and error counts for pillars with at least one finding.
 */
function countSeverityByPillar(findings: Finding[]): Map<Pillar, PillarSeverityCounts> {
  const severityByPillar = new Map<Pillar, PillarSeverityCounts>();
  // Accumulate each finding under its primary pillar so summary severities match the report's finding list.
  for (const finding of findings) {
    const counts = severityByPillar.get(finding.pillar) ?? { advisory: 0, warning: 0, error: 0 };
    counts[finding.severity] += 1;
    severityByPillar.set(finding.pillar, counts);
  }
  return severityByPillar;
}

/**
 * Builds the summary row for one applicable pillar; stable contract derives the total from the same tally as its severity columns.
 * Preserves an explicit `null` score as `n/a` when nothing was evaluated; falls back to `A/100` when a partial fixture omits the entry.
 *
 * @param pillar - pillar to label in the summary table
 * @param scoreEntry - score and penalty for that pillar; `score: null` renders `n/a`, while `undefined` defaults to 100 and 0
 * @param severities - reported findings by severity for that pillar; `undefined` means zero findings in every severity bucket
 * @returns The applicable pillar's row with its grade, score (or `null` when unevaluated), penalty, and finding counts.
 */
function buildPillarRow(pillar: Pillar, scoreEntry: AnalysisReport["score"]["pillars"][number] | undefined, severities: PillarSeverityCounts | undefined): PillarRow {
  // Distinguish an explicit unevaluated `null` (0 evaluated files) from an omitted entry in a partial fixture.
  const score = scoreEntry === undefined ? 100 : scoreEntry.score;
  const counts = severities ?? { advisory: 0, warning: 0, error: 0 };
  return {
    pillar,
    grade: score === null ? "n/a" : grade(score),
    score,
    penalty: scoreEntry?.penalty ?? 0,
    isApplicable: true,
    findings: counts.advisory + counts.warning + counts.error,
    advisory: counts.advisory,
    warning: counts.warning,
    error: counts.error,
  };
}

/**
 * Compares two pillar rows for descending finding count, then ascending pillar name in the shared renderer order.
 *
 * @param leftRow - first pillar row to compare
 * @param rightRow - second pillar row to compare
 * @returns negative when leftRow sorts first, zero for equal keys, and positive when rightRow sorts first
 */
function comparePillarRows(leftRow: PillarRow, rightRow: PillarRow): number {
  if (leftRow.findings !== rightRow.findings) {
    return rightRow.findings - leftRow.findings;
  }
  return leftRow.pillar.localeCompare(rightRow.pillar);
}

/**
 * Collects applicable pillars from the rule catalogue so the cross-port human table stays stable.
 * Every pillar that could fire appears even when the current run produced no findings for it.
 *
 * @returns set of pillars represented by the registered rule descriptors
 */
function applicablePillarSet(): Set<Pillar> {
  const pillars = new Set<Pillar>();
  for (const descriptor of ruleDescriptors()) {
    pillars.add(descriptor.pillar);
  }
  return pillars;
}

/**
 * Converts a composite or pillar score to a letter grade using the stable 90, 80, 70, and 60 thresholds.
 * Changing a threshold changes grades only for scores that cross the revised boundary.
 *
 * @param score - composite or pillar score to convert to a letter grade
 * @returns letter grade A through D at or above 90, 80, 70, and 60 respectively, or F below 60
 */
function grade(score: number): string {
  if (score >= 90) {
    return "A";
  }
  if (score >= 80) {
    return "B";
  }
  if (score >= 70) {
    return "C";
  }
  if (score >= 60) {
    return "D";
  }
  return "F";
}

export { buildPillarRows, grade };
export type { PillarRow, PillarSeverityCounts };
