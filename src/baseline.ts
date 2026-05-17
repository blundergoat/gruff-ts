import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { scoreReport } from "./scoring.ts";
import type { Finding, RunDiagnostic } from "./types.ts";

const DEFAULT_BASELINE = "gruff-baseline.json";

function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

function writeBaseline(path: string, findings: Finding[]): void {
  writeFileSync(
    path,
    JSON.stringify(
      {
        schemaVersion: "gruff.baseline.v1",
        generatedAt: new Date().toISOString(),
        entries: findings.map((finding) => ({
          fingerprint: finding.fingerprint,
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          line: finding.line,
          symbol: finding.symbol,
          message: finding.message,
        })),
      },
      null,
      2,
    ),
  );
}

function applyBaseline(path: string, findings: Finding[]): Finding[] {
  const baselineFile = JSON.parse(readFileSync(path, "utf8")) as { schemaVersion?: string; entries?: Array<{ fingerprint: string; ruleId: string; filePath: string }> };
  if (baselineFile.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  const keys = new Set((baselineFile.entries ?? []).map((entry) => [entry.fingerprint, entry.ruleId, entry.filePath].join("\0")));
  return findings.filter((finding) => !keys.has([finding.fingerprint, finding.ruleId, finding.filePath].join("\0")));
}

function recordHistory(projectRoot: string, historyFile: string, findings: Finding[], diagnostics: RunDiagnostic[]): void {
  const path = absolutize(projectRoot, historyFile);
  try {
    const entries = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as unknown[]) : [];
    entries.push({ recordedAt: new Date().toISOString(), findings: findings.length, score: scoreReport(findings).composite });
    writeFileSync(path, JSON.stringify(entries.slice(-100), null, 2));
  } catch (error) {
    diagnostics.push({ diagnosticType: "history-error", message: `Unable to write history file: ${String(error)}`, filePath: displayPath(projectRoot, path) });
  }
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = finding.ruleId === "docs.missing-public-doc" && finding.symbol ? [finding.ruleId, finding.filePath, finding.symbol].join("\0") : finding.fingerprint;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

export { DEFAULT_BASELINE, writeBaseline, applyBaseline, recordHistory, dedupeFindings };
