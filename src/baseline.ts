// Score-history side effects and the canonical finding order every report and baseline is built from.
//
// Baseline reading, writing, and matching live in `baseline-file.ts`; this module keeps the ordering and dedupe
// rules that decide which findings a run reports at all, and the history file the dashboard sparkline reads.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import { scoreReport } from "./scoring.ts";
import type { Finding, RunDiagnostic } from "./types.ts";

const DEFAULT_BASELINE = "gruff-baseline.json";

// Treats already-absolute paths as-is; otherwise anchors at the project root the CLI was launched against.
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Project-relative form with forward slashes - the report contract uses POSIX-style display paths on
// every platform. "" collapses to "." so the project root has a stable label in history entries.
function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

/*
 * Appends one row to the score-history JSON file and trims to the most recent 100 entries so the
 * dashboard sparkline never grows unbounded. The stable contract: writes via writeFileSync, and on
 * persistence failure it reports a `history-error` diagnostic and recovers - a flaky history file
 * must not fail the analysis run.
 */
function recordHistory(projectRoot: string, historyFile: string, findings: Finding[], evaluatedFiles: number, diagnostics: RunDiagnostic[]): void {
  const path = absolutize(projectRoot, historyFile);
  try {
    const entries = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as unknown[]) : [];
    entries.push({ recordedAt: new Date().toISOString(), findings: findings.length, score: scoreReport(findings, evaluatedFiles).composite });
    writeFileSync(path, JSON.stringify(entries.slice(-100), null, 2));
  } catch (error) {
    diagnostics.push({ diagnosticType: "history-error", message: `Unable to write history file: ${String(error)}`, filePath: displayPath(projectRoot, path) });
  }
}

// `docs.missing-public-doc` is keyed by (ruleId, filePath, symbol) instead of fingerprint because one
// file can legitimately surface multiple undocumented public symbols and they must each survive dedupe.
// All other rules collapse on their fingerprint, extended by the match column when one is present
// (ADR-017): two distinct secrets on one line share a line-keyed fingerprint, and without the column
// discriminator the second occurrence would be silently dropped from every report and the hook.
// The extended key is in-memory only - fingerprint values are unchanged, and `gruff.baseline.v3` matching
// reads the line-free identity rather than this key.
function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((finding) => {
    const key = dedupeKey(finding);
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

// Derives the in-memory dedupe key for one finding, so same-line occurrences with distinct
// columns survive dedupe as separate findings (ADR-017). Invariant: the key is never serialized
// and never feeds `applyBaseline` - fingerprint values and baseline matching stay byte-identical.
function dedupeKey(finding: Finding): string {
  // One file legitimately surfaces many undocumented public symbols; keep each per-symbol entry.
  if (finding.ruleId === "docs.missing-public-doc" && finding.symbol) {
    return [finding.ruleId, finding.filePath, finding.symbol].join("\0");
  }
  // Casing drift is scoped to a lexical owner. Preserve owner-distinct diagnostics in memory
  // without changing their public line-keyed fingerprints or baseline matching contract.
  if (finding.ruleId === "naming.inconsistent-casing" && typeof finding.metadata.ownerId === "string") {
    return [finding.fingerprint, finding.metadata.ownerId].join("\0");
  }
  // A column means the scanner pinpointed the occurrence; same-line occurrences stay distinct.
  if (finding.column !== undefined) {
    return [finding.fingerprint, String(finding.column)].join("\0");
  }
  return finding.fingerprint;
}

// Canonical finding ordering: (filePath, line, ruleId, message). The same tuple is part of the
// stable baseline matching contract, so changing the comparator would churn every existing baseline.
function sortedUniqueFindings(findings: Finding[]): Finding[] {
  findings.sort(
    (left, right) =>
      left.filePath.localeCompare(right.filePath) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId) ||
      left.message.localeCompare(right.message),
  );
  return dedupeFindings(findings);
}

export { DEFAULT_BASELINE, recordHistory, dedupeFindings, sortedUniqueFindings };
