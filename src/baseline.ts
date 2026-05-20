// Baseline persistence helpers for stable suppression files and score history side effects.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { scoreReport } from "./scoring.ts";
import type { Finding, RunDiagnostic } from "./types.ts";

const DEFAULT_BASELINE = "gruff-baseline.json";

// Treats already-absolute paths as-is; otherwise anchors at the project root the CLI was launched against.
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Project-relative form with forward slashes — the report contract uses POSIX-style display paths on
// every platform. "" collapses to "." so the project root has a stable label in history entries.
function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

// `gruff.baseline.v1`: writes the fingerprint plus the identity tuple used by `applyBaseline`.
// `message` is persisted for human review; `applyBaseline` ignores it so cosmetic message changes
// do not invalidate baselines. Bump schema before adding required fields; persists to disk via writeFileSync.
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

// Suppresses any finding whose (fingerprint, ruleId, filePath) tuple appears in the baseline.
// Drift between versions would let stale suppressions leak in, so the operator must regenerate
// against the current CLI; reads the baseline file and throws on an unknown schema version.
function applyBaseline(path: string, findings: Finding[]): Finding[] {
  const baselineFile = JSON.parse(readFileSync(path, "utf8")) as { schemaVersion?: string; entries?: Array<{ fingerprint: string; ruleId: string; filePath: string }> };
  if (baselineFile.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  const keys = new Set((baselineFile.entries ?? []).map((entry) => [entry.fingerprint, entry.ruleId, entry.filePath].join("\0")));
  return findings.filter((finding) => !keys.has([finding.fingerprint, finding.ruleId, finding.filePath].join("\0")));
}

/*
 * Appends one row to the score-history JSON file and trims to the most recent 100 entries so the
 * dashboard sparkline never grows unbounded. The stable contract: writes via writeFileSync, and on
 * persistence failure it reports a `history-error` diagnostic and recovers — a flaky history file
 * must not fail the analysis run.
 */
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

// `docs.missing-public-doc` is keyed by (ruleId, filePath, symbol) instead of fingerprint because one
// file can legitimately surface multiple undocumented public symbols and they must each survive dedupe.
// All other rules collapse on their fingerprint, which already encodes the unique anchor.
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
