// Score, grade, and fail-on helpers derived from finding severities for reports and CLI exits.
import { grade } from "./pillar-summary.ts";
import type { AnalysisReport, FailThreshold, Finding, Pillar, Severity } from "./types.ts";

// Builds the per-pillar and per-file score breakdown that ships in `gruff.analysis.v1`. The composite
// score is the mean of pillar scores so adding a pillar shifts the headline number. `topOffenders` is
// the full file list sorted worst-first; renderers cap it themselves (HTML/hotspot keep their 10-row
// UX, summary honours `--top`). The field shape is part of the `gruff.analysis.v1` schema contract.
function scoreReport(findings: Finding[]): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const pillars = [...byPillar.entries()].map(([pillar, pillarFindings]) => {
    const penalty = pillarFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0);
    return { pillar, score: Math.max(0, 100 - penalty), penalty, findings: pillarFindings.length };
  });
  const composite = pillars.length === 0 ? 100 : pillars.reduce((sum, pillar) => sum + pillar.score, 0) / pillars.length;
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => ({
      filePath,
      score: Math.max(0, 100 - fileFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0)),
      findings: fileFindings.length,
    }))
    .sort((left, right) => left.score - right.score);
  return { composite, grade: grade(composite), pillars, topOffenders };
}

// Severity tallies emitted in the report summary. The four-key shape (advisory/warning/error/total)
// is part of the `gruff.analysis.v1` schema and consumers rely on `total` matching the array length.
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
  if (report.diagnostics.length > 0) {
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

export { scoreReport, summarize, exitFor };
