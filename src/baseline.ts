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

/**
 * Writes a score-history row and keeps the latest 100 entries to bound the dashboard sparkline. An absent file starts a new history.
 * The stable contract is to report a history failure so that analysis can continue.
 *
 * @param projectRoot - base directory for resolving the history path and displaying it in a diagnostic
 * @param historyFile - JSON history destination
 * @param findings - run findings used for the count and score
 * @param evaluatedFiles - number of evaluated files used to calculate the score
 * @param diagnostics - run diagnostics array that receives a history-error if recording fails
 * @returns Nothing. It writes the updated history or appends a failure diagnostic.
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

// Returns the first finding per dedupe key in input order, preserving the original fingerprints.
// Only docs.missing-public-doc findings with a symbol use rule, path and symbol. Other keys use the fingerprint and any column.
// Columns preserve separate same-line matches. gruff.baseline.v3 uses line-free matching under the identity separation in ADR-017.
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

// Returns a stable in-memory dedupe key. Outside the per-symbol rule below, distinct columns keep same-line occurrences separate.
// When a finding has no column, its fingerprint alone groups duplicates outside the per-symbol rule.
// The key stays in memory as required by ADR-017. applyBaseline receives the deduplicated findings with their original fingerprints.
function dedupeKey(finding: Finding): string {
  // One file legitimately surfaces many undocumented public symbols; keep each per-symbol entry.
  if (finding.ruleId === "docs.missing-public-doc" && finding.symbol) {
    return [finding.ruleId, finding.filePath, finding.symbol].join("\0");
  }
  // A column means the scanner pinpointed the occurrence; same-line occurrences stay distinct.
  if (finding.column !== undefined) {
    return [finding.fingerprint, String(finding.column)].join("\0");
  }
  return finding.fingerprint;
}

// Sorts the caller's findings in place by path, line, rule and message to give reports a stable order. Missing lines sort as zero.
// Returns a new array with the first occurrence of each dedupe key in that order.
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
