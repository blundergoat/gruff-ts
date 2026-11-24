// File overview: Saves score history and keeps findings in a predictable order.
//
// A user who passes `--history-file` gets one score entry for a valid full scan, which the dashboard can plot.
// The ordering and duplicate checks also keep the reports and baseline comparisons stable between scans.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join, relative } from "node:path";
import type { AnalysisReport, Finding, RunDiagnostic } from "./types.ts";

const DEFAULT_BASELINE = "gruff-baseline.json";

/**
 * Resolves a path against the project root unless it is already absolute.
 *
 * @param projectRoot - base project directory the CLI was launched against
 * @param path - candidate path that may be relative or already absolute
 * @returns The unchanged absolute path, or `path` joined onto `projectRoot`.
 */
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

/**
 * Formats a path in project-relative POSIX form with forward slashes.
 * The report contract uses POSIX-style display paths on every platform; "" collapses to "." for a stable history label.
 *
 * @param projectRoot - base directory used to compute the relative path
 * @param path - target file or directory path to format
 * @returns The forward-slash relative path, or "." when `path` matches `projectRoot`.
 */
function displayPath(projectRoot: string, path: string): string {
  const relativePath = relative(projectRoot, path).replaceAll("\\", "/");
  return relativePath === "" ? "." : relativePath;
}

/**
 * Append the result of a valid full scan for the dashboard's score trend.
 * Invariant: keep the latest 100 entries. A missing history file starts a new trend.
 *
 * @param projectRoot - base directory for resolving the history path and displaying it in a diagnostic
 * @param historyFile - destination from `--history-file`. A missing file starts with no earlier score entries.
 * @param score - score for the same run. A null composite means no files could be scored.
 * @param findings - count of findings in that run
 * @param diagnostics - run diagnostics array that receives a history-error if recording fails
 * @returns Nothing. It writes the updated history or appends a failure diagnostic.
 */
function recordHistory(projectRoot: string, historyFile: string, score: AnalysisReport["score"], findings: number, diagnostics: RunDiagnostic[]): void {
  const path = absolutize(projectRoot, historyFile);
  try {
    // A first run has no history file to read, so the dashboard gets one point after this write.
    const entries = existsSync(path) ? (JSON.parse(readFileSync(path, "utf8")) as unknown[]) : [];
    entries.push({ recordedAt: new Date().toISOString(), findings, score: score.composite });
    writeFileSync(path, JSON.stringify(entries.slice(-100), null, 2));
  } catch (error) {
    // A read-only directory or a malformed existing history file adds a diagnostic to the scan report.
    diagnostics.push({ diagnosticType: "history-error", message: `Unable to write history file: ${String(error)}`, filePath: displayPath(projectRoot, path) });
  }
}

/**
 * Keeps the first finding per dedupe key in input order while preserving original fingerprints.
 * Only docs.missing-public-doc findings with a symbol key on rule, path, and symbol; others use fingerprint and column.
 * Columns preserve separate same-line matches, while gruff.baseline.v3 uses line-free matching per ADR-017.
 *
 * @param findings - candidate findings to deduplicate in their current order
 * @returns A filtered array containing the first occurrence of each dedupe key.
 */
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

/**
 * Builds a stable in-memory dedupe key for a finding, keeping distinct columns separate on the same line.
 * Outside docs.missing-public-doc with a symbol, findings without a column group by fingerprint alone.
 * The key stays in memory per ADR-017 so applyBaseline receives deduplicated findings with original fingerprints.
 *
 * @param finding - finding whose rule, path, symbol, fingerprint, and column determine the key
 * @returns The NUL-delimited in-memory dedupe key, or the bare fingerprint when no column or per-symbol key applies.
 */
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

/**
 * Sorts and mutates the caller's findings in place by path, line, rule, and message for a stable report order.
 * Missing lines sort as zero, then duplicates are removed while preserving the sorted order.
 *
 * @param findings - caller array sorted in place before deduplication
 * @returns A new array containing the first occurrence of each dedupe key in sorted order.
 */
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
