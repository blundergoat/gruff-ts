/*
 * Shared pillar-row construction + grade helper. Lives in its own module so the text/markdown
 * renderers (`report-renderers.ts`), the HTML renderer (`report-html.ts`), and the score builder
 * (`scoring.ts`) can all source the same `buildPillarRows` and `grade` logic without forming a
 * dependency cycle between the renderer modules. Every row this module emits feeds the cross-port
 * `gruff.summary.v2` Pillars table contract, so the schema invariant - findings DESC, pillar ASC,
 * and a clean A/100 fallback per pillar - must stay byte-stable across runs.
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

/*
 * Builds the canonical cross-port pillar row list shared by `gruff.summary.v2` text, JSON, and
 * HTML renderers. The shape is intentionally a single deterministic list - one row per applicable
 * pillar even when the run has zero findings - because cross-port consumers diff this output
 * byte-for-byte and a missing row would read as a contract drift. Pillars without findings default
 * to a clean A/100 row to preserve that invariant. Sort order is `findings DESC, pillar ASC` to
 * keep the public Pillars-table contract deterministic across runs.
 */
function buildPillarRows(report: AnalysisReport): PillarRow[] {
  const scoreByPillar = new Map(report.score.pillars.map((entry) => [entry.pillar, entry] as const));
  const severityByPillar = countSeverityByPillar(report.findings);
  const rows: PillarRow[] = [...applicablePillarSet()].map((pillar) => buildPillarRow(pillar, scoreByPillar.get(pillar), severityByPillar.get(pillar)));
  rows.sort(comparePillarRows);
  return rows;
}

// Tallies advisory/warning/error counts per pillar from the live findings list. Returning a Map
// rather than mutating an accumulator keeps `buildPillarRows` linear and easy to read; this is
// the deterministic per-pillar tally feeding the public Pillars-table schema.
function countSeverityByPillar(findings: Finding[]): Map<Pillar, PillarSeverityCounts> {
  const severityByPillar = new Map<Pillar, PillarSeverityCounts>();
  for (const finding of findings) {
    const counts = severityByPillar.get(finding.pillar) ?? { advisory: 0, warning: 0, error: 0 };
    counts[finding.severity] += 1;
    severityByPillar.set(finding.pillar, counts);
  }
  return severityByPillar;
}

// Assembles one PillarRow from the optional analyser score entry and optional severity tally.
// Defaults preserve the clean A/100 row contract when a pillar produced no findings.
function buildPillarRow(pillar: Pillar, scoreEntry: AnalysisReport["score"]["pillars"][number] | undefined, severities: PillarSeverityCounts | undefined): PillarRow {
  const score = scoreEntry?.score ?? 100;
  const counts = severities ?? { advisory: 0, warning: 0, error: 0 };
  return {
    pillar,
    grade: grade(score),
    score,
    penalty: scoreEntry?.penalty ?? 0,
    isApplicable: true,
    findings: scoreEntry?.findings ?? 0,
    advisory: counts.advisory,
    warning: counts.warning,
    error: counts.error,
  };
}

// Findings DESC, then pillar ASC. Extracted so the cross-port sort contract lives in one place and
// any tweak (e.g. a stable secondary key) only has to land here.
function comparePillarRows(leftRow: PillarRow, rightRow: PillarRow): number {
  if (leftRow.findings !== rightRow.findings) {
    return rightRow.findings - leftRow.findings;
  }
  return leftRow.pillar.localeCompare(rightRow.pillar);
}

// Pillar applicability is sourced from the rule catalogue: a pillar is applicable when at least
// one rule declares it. This keeps the cross-port `gruff.summary.v2` contract stable - every
// pillar that *could* fire shows up even when the current run produced zero findings for it.
function applicablePillarSet(): Set<Pillar> {
  const pillars = new Set<Pillar>();
  for (const descriptor of ruleDescriptors()) {
    pillars.add(descriptor.pillar);
  }
  return pillars;
}

// Composite-score → letter grade conversion. 90/80/70/60 boundaries are part of the stable rule
// surface; changing them would shift every historical report grade and the headline on the dashboard.
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
