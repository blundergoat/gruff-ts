import { grade } from "./report-renderers.ts";
import type { AnalysisReport, FailThreshold, Finding, Pillar, Severity } from "./types.ts";

function scoreReport(findings: Finding[]): AnalysisReport["score"] {
  const byPillar = new Map<Pillar, Finding[]>();
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    byPillar.set(finding.pillar, [...(byPillar.get(finding.pillar) ?? []), finding]);
    byFile.set(finding.filePath, [...(byFile.get(finding.filePath) ?? []), finding]);
  }
  const pillars = [...byPillar.entries()].map(([pillar, pillarFindings]) => {
    const penalty = pillarFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0);
    return { pillar, score: Math.max(0, 100 - penalty), findings: pillarFindings.length };
  });
  const composite = pillars.length === 0 ? 100 : pillars.reduce((sum, pillar) => sum + pillar.score, 0) / pillars.length;
  const topOffenders = [...byFile.entries()]
    .map(([filePath, fileFindings]) => ({
      filePath,
      score: Math.max(0, 100 - fileFindings.reduce((sum, finding) => sum + severityPenalty(finding.severity), 0)),
      findings: fileFindings.length,
    }))
    .sort((left, right) => left.score - right.score)
    .slice(0, 10);
  return { composite, grade: grade(composite), pillars, topOffenders };
}

function summarize(findings: Finding[]) {
  return {
    advisory: findings.filter((finding) => finding.severity === "advisory").length,
    warning: findings.filter((finding) => finding.severity === "warning").length,
    error: findings.filter((finding) => finding.severity === "error").length,
    total: findings.length,
  };
}

function exitFor(report: AnalysisReport, failOn: FailThreshold): number {
  if (report.diagnostics.length > 0) {
    return 2;
  }
  return report.findings.some((finding) => thresholdTriggered(failOn, finding.severity)) ? 1 : 0;
}

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

function severityPenalty(severity: Severity): number {
  return severity === "error" ? 8 : severity === "warning" ? 4 : 1.5;
}

export { scoreReport, summarize, exitFor };
