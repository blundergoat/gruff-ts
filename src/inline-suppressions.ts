// FAMILY-CONTRACT.md section 13c for gruff-ts: another tool's suppression comment, and one eval call under two rules.
import { readFileSync } from "node:fs";

import type { SourceFile } from "./discovery.ts";
import type { Finding, SuppressedFinding, SuppressionSummary } from "./types.ts";

// Reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
export const INLINE_SUPPRESSION_REASON = "Another tool's suppression comment names this check, so the finding is suppressed where it was written.";

// Reason on each repeated-claim audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
export const DUPLICATE_SUPPRESSION_REASON = "Another rule reports the same claim on this line, so the line reports it once.";

// eslint rules section 13c names for gruff-ts, each with the rule that makes the same claim.
const ESLINT_RULES: ReadonlyMap<string, string> = new Map([
  ["no-console", "waste.console-log"],
  ["eqeqeq", "modernisation.loose-equality"],
  ["no-eval", "security.eval-call"],
  ["no-new-func", "security.new-function"],
  ["no-unused-vars", "waste.unused-parameter"],
  ["@typescript-eslint/no-unused-vars", "waste.unused-parameter"],
]);

// biome rules section 13c names, each with the rule that makes the same claim.
const BIOME_RULES: ReadonlyMap<string, string> = new Map([
  ["lint/security/noGlobalEval", "security.eval-call"],
  ["lint/correctness/noUnusedImports", "waste.unused-import"],
]);

// zizmor audits section 13c names, each with the workflow rule that makes the same claim.
const ZIZMOR_AUDITS: ReadonlyMap<string, string> = new Map([
  ["unpinned-uses", "security.github-actions-unpinned-action"],
  ["dangerous-triggers", "security.github-actions-pull-request-target"],
]);

// Captures the rest of the line after either per-line eslint directive;
// isDisabledByEslint cuts its rule list at a ` --` reason or comment close.
const ESLINT_DIRECTIVE = /eslint-disable-(?:next-)?line\b([^\n]*)/g;

// Captures the category after biome's ignore comment, such as `lint/security/noGlobalEval`, up to its `:` explanation.
const BIOME_DIRECTIVE = /biome-ignore\s+([\w/]+)/g;

// Captures zizmor's audit list in `# zizmor: ignore[unpinned-uses]`.
const ZIZMOR_DIRECTIVE = /#\s*zizmor:\s*ignore\[([^\]]*)\]/g;

// Matches an `eval(` call, the call on which security.unsafe-deserialization repeats security.eval-call's claim.
const EVAL_CALL = /\beval\s*\(/;

/*
 * Applies FAMILY-CONTRACT.md section 13c after the sensitive exclusions and the test-path skip.
 *
 * A comment naming a check that makes a finding's claim suppresses it where it was written, on the reported line or
 * alone on the line above: eslint's next-line directive naming `no-console` above a `console.log` hides
 * waste.console-log there and nothing else. An `eval` call reported by both security.eval-call and security.unsafe-deserialization reports once,
 * as security.eval-call. Each removal is counted in one audit row per rule and file after the built-in rows, and kept so
 * SARIF can show it as suppressed.
 */
export function applyInlineSuppressions(
  findings: readonly Finding[],
  suppressions: readonly SuppressionSummary[],
  files: readonly SourceFile[],
): { findings: Finding[]; suppressions: SuppressionSummary[]; suppressed: SuppressedFinding[] } {
  const lines = sourceLineReader(files);
  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  // A finding leaves only when a comment on its line, or alone on the line above, names a check making its claim.
  for (const finding of findings) {
    if (isCoveredByComment(lines(finding.filePath), finding)) {
      suppressed.push({ finding, justification: INLINE_SUPPRESSION_REASON });
      continue;
    }
    kept.push(finding);
  }
  const merged = mergeRepeatedClaims(kept, lines);
  // Built-in rows number among themselves; section 13c's rows continue that numbering.
  const nextIndex = suppressions.filter((summary) => summary.source === "built-in").length;
  const inlineRows = auditRows(suppressed, "inline", INLINE_SUPPRESSION_REASON, nextIndex);
  const duplicateRows = auditRows(merged.removed, "duplicate", DUPLICATE_SUPPRESSION_REASON, nextIndex + inlineRows.length);
  return {
    findings: merged.kept,
    suppressions: [...suppressions, ...inlineRows, ...duplicateRows],
    suppressed: [...suppressed, ...merged.removed],
  };
}

// Reads each discovered file's lines once, on demand, by the display path a finding carries; an unreadable file has none.
function sourceLineReader(files: readonly SourceFile[]): (displayPath: string) => readonly string[] {
  const absolutePathByDisplayPath = new Map(files.map((file) => [file.displayPath, file.absolutePath]));
  const linesByDisplayPath = new Map<string, readonly string[]>();
  return (displayPath) => {
    const cached = linesByDisplayPath.get(displayPath);
    if (cached !== undefined) {
      return cached;
    }
    const absolutePath = absolutePathByDisplayPath.get(displayPath);
    let read: readonly string[] = [];
    try {
      read = absolutePath === undefined ? [] : readFileSync(absolutePath, "utf8").split(/\r?\n/);
    } catch {
      // A file that vanished since discovery has no comment to read, so nothing in it is suppressed.
      read = [];
    }
    linesByDisplayPath.set(displayPath, read);
    return read;
  };
}

// Reports whether the finding's line, or a comment-only line directly above it, names a check making its claim.
// Invariant: only those two lines are read, so a comment never reaches past the line below it.
function isCoveredByComment(lines: readonly string[], finding: Finding): boolean {
  const line = finding.line ?? 0;
  if (line < 1 || line > lines.length) {
    return false;
  }
  if (hasCoveringComment(lines[line - 1] ?? "", finding.ruleId)) {
    return true;
  }
  const above = (lines[line - 2] ?? "").trim();
  const isCommentOnly = above.startsWith("//") || above.startsWith("/*") || above.startsWith("*") || above.startsWith("#");
  return isCommentOnly && hasCoveringComment(above, finding.ruleId);
}

// Reports whether one line's eslint, biome or zizmor comment names a check making the rule's claim.
function hasCoveringComment(line: string, ruleId: string): boolean {
  return isDisabledByEslint(line, ruleId) || isIgnoredByBiome(line, ruleId) || isIgnoredByZizmor(line, ruleId);
}

// Reports whether eslint's per-line directive covers the rule; one naming no rule covers every eslint row, as eslint reads it.
function isDisabledByEslint(line: string, ruleId: string): boolean {
  for (const match of line.matchAll(ESLINT_DIRECTIVE)) {
    const listed = (match[1] ?? "").split(/\s--|\*\//)[0] ?? "";
    const names = listed.split(",").map((name) => name.trim()).filter((name) => name.length > 0);
    if (names.length === 0 ? [...ESLINT_RULES.values()].includes(ruleId) : names.some((name) => ESLINT_RULES.get(name) === ruleId)) {
      return true;
    }
  }
  return false;
}

// Reports whether biome's ignore comment covers the rule: a category names its rule or, like `lint/security`, the group
// holding it.
function isIgnoredByBiome(line: string, ruleId: string): boolean {
  for (const match of line.matchAll(BIOME_DIRECTIVE)) {
    const category = match[1] ?? "";
    for (const [biomeRule, gruffRule] of BIOME_RULES) {
      if (gruffRule === ruleId && (biomeRule === category || biomeRule.startsWith(`${category}/`))) {
        return true;
      }
    }
  }
  return false;
}

// Reports whether a `# zizmor: ignore[...]` names an audit mapped to the rule.
function isIgnoredByZizmor(line: string, ruleId: string): boolean {
  for (const match of line.matchAll(ZIZMOR_DIRECTIVE)) {
    if ((match[1] ?? "").split(",").some((audit) => ZIZMOR_AUDITS.get(audit.trim()) === ruleId)) {
      return true;
    }
  }
  return false;
}

// Merges security.unsafe-deserialization into security.eval-call on a line that calls `eval`.
// Invariant: each eval-call finding absorbs at most one repeat, so two calls on one line keep two findings.
function mergeRepeatedClaims(
  findings: readonly Finding[],
  lines: (displayPath: string) => readonly string[],
): { kept: Finding[]; removed: SuppressedFinding[] } {
  const evalCalls = new Map<string, number>();
  // Count the eval-call findings per file and line, so each merges at most one repeat.
  for (const finding of findings) {
    if (finding.ruleId === "security.eval-call") {
      const key = `${finding.filePath}\u0000${finding.line}`;
      evalCalls.set(key, (evalCalls.get(key) ?? 0) + 1);
    }
  }
  const kept: Finding[] = [];
  const removed: SuppressedFinding[] = [];
  for (const finding of findings) {
    const key = `${finding.filePath}\u0000${finding.line}`;
    const isRepeat = finding.ruleId === "security.unsafe-deserialization" && (evalCalls.get(key) ?? 0) > 0
      && EVAL_CALL.test(lines(finding.filePath)[(finding.line ?? 0) - 1] ?? "");
    if (isRepeat) {
      evalCalls.set(key, (evalCalls.get(key) ?? 0) - 1);
      removed.push({ finding, justification: DUPLICATE_SUPPRESSION_REASON });
      continue;
    }
    kept.push(finding);
  }
  return { kept, removed };
}

// Folds removed findings into one audit row per file and rule, in UTF-8 byte order of path and then rule.
// Invariant: the rows are deterministic, and their indexes run contiguously from firstIndex.
function auditRows(removed: readonly SuppressedFinding[], source: "inline" | "duplicate", reason: string, firstIndex: number): SuppressionSummary[] {
  const counts = new Map<string, { path: string; rule: string; count: number }>();
  for (const { finding } of removed) {
    const key = `${finding.filePath}\u0000${finding.ruleId}`;
    const row = counts.get(key) ?? { path: finding.filePath, rule: finding.ruleId, count: 0 };
    row.count += 1;
    counts.set(key, row);
  }
  const sorted = [...counts.values()].sort((left, right) => compareUtf8Bytes(left.path, right.path) || compareUtf8Bytes(left.rule, right.rule));
  return sorted.map((row, offset) => ({
    index: firstIndex + offset,
    rule: row.rule,
    paths: [row.path],
    symbol: null,
    reason,
    suppressed: row.count,
    source,
  }));
}

// Orders two strings by their UTF-8 bytes, the order every port publishes audit rows in.
function compareUtf8Bytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
