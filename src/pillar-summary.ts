/*
 * Shared pillar-row construction + grade helper. Lives in its own module so the text/markdown
 * renderers (`report-renderers.ts`), the HTML renderer (`report-html.ts`), and the score builder
 * (`scoring.ts`) can all source the same `buildPillarRows` and `grade` logic without forming a
 * dependency cycle between renderer modules. Every row feeds the cross-port human Pillars table,
 * so findings-descending/pillar-ascending order and a clean A/100 fallback must stay byte-stable.
 */
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisReport, Finding, Pillar } from "./types.ts";

// Aggregated per-pillar row used by every renderer. `applicable` is derived from the rule
// catalogue rather than the live findings so the row set stays stable across runs (a pillar with
// zero findings today is still applicable). `grade` is derived from `score` via the shared
// `grade()` helper so historical pillar scores keep their existing grade letters.
interface PillarRow {
  pillar: Pillar;
  grade: string;
  score: number;
  penalty: number;
  isApplicable: boolean;
  findings: number;
  advisory: number;
  warning: number;
  error: number;
}

// Per-pillar severity tally - one entry per pillar that produced at least one finding. Renderers
// see these counts indirectly through `buildPillarRows`; the type is exported only so other
// modules in this package can name it when consuming `countSeverityByPillar`.
interface PillarSeverityCounts {
  advisory: number;
  warning: number;
  error: number;
}

/**
 * Builds the shared pillar summary for text, Markdown and HTML reports.
 * Keeps one row per applicable pillar even when there are no findings, so comparisons cover the same pillars.
 *
 * @param report - supplies pillar scores and findings to tally by severity
 * @returns Deterministic rows in findings DESC, pillar ASC order. Missing scores use A/100 and missing tallies use zero.
 */
function buildPillarRows(report: AnalysisReport): PillarRow[] {
  const scoreByPillar = new Map(report.score.pillars.map((entry) => [entry.pillar, entry] as const));
  const severityByPillar = countSeverityByPillar(report.findings);
  const rows: PillarRow[] = [...applicablePillarSet()].map((pillar) => buildPillarRow(pillar, scoreByPillar.get(pillar), severityByPillar.get(pillar)));
  rows.sort(comparePillarRows);
  return rows;
}

// Returns a map of severity counts by pillar from the report's findings for the stable Pillars table schema.
// A pillar with no findings has no map entry, so the row builder supplies its zero counts.
function countSeverityByPillar(findings: Finding[]): Map<Pillar, PillarSeverityCounts> {
  const severityByPillar = new Map<Pillar, PillarSeverityCounts>();
  for (const finding of findings) {
    const counts = severityByPillar.get(finding.pillar) ?? { advisory: 0, warning: 0, error: 0 };
    counts[finding.severity] += 1;
    severityByPillar.set(finding.pillar, counts);
  }
  return severityByPillar;
}

/**
 * Build the summary row for an applicable pillar. The row contract derives the total from the same tally as its severity columns.
 *
 * @param pillar - pillar to label in the summary
 * @param scoreEntry - score and penalty for that pillar, defaulting to 100 and 0 when absent
 * @param severities - reported findings by severity for that pillar, defaulting to zero counts when absent
 * @returns the applicable pillar's row with its grade, score, penalty, and finding counts
 */
function buildPillarRow(pillar: Pillar, scoreEntry: AnalysisReport["score"]["pillars"][number] | undefined, severities: PillarSeverityCounts | undefined): PillarRow {
  const score = scoreEntry?.score ?? 100;
  const counts = severities ?? { advisory: 0, warning: 0, error: 0 };
  return {
    pillar,
    grade: grade(score),
    score,
    penalty: scoreEntry?.penalty ?? 0,
    isApplicable: true,
    findings: counts.advisory + counts.warning + counts.error,
    advisory: counts.advisory,
    warning: counts.warning,
    error: counts.error,
  };
}

// Compares leftRow with rightRow for descending finding count, then ascending pillar name in the shared renderer order.
// Returns a negative number when leftRow sorts first, zero for equal keys, and a positive number when rightRow sorts first.
function comparePillarRows(leftRow: PillarRow, rightRow: PillarRow): number {
  if (leftRow.findings !== rightRow.findings) {
    return rightRow.findings - leftRow.findings;
  }
  return leftRow.pillar.localeCompare(rightRow.pillar);
}

// Pillar applicability comes from the rule catalogue. This keeps the cross-port human table stable:
// every pillar that could fire appears even when the current run produced no findings for it.
function applicablePillarSet(): Set<Pillar> {
  const pillars = new Set<Pillar>();
  for (const descriptor of ruleDescriptors()) {
    pillars.add(descriptor.pillar);
  }
  return pillars;
}

// Converts the supplied composite or pillar score to a letter grade using the stable 90, 80, 70 and 60 thresholds.
// Returns F below 60; changing a threshold changes grades only for scores that cross the revised boundary.
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
