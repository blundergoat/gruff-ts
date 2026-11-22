// Applies supported ESLint, Biome, and zizmor inline suppressions to a user's scan.
//
// A developer can keep an existing tool directive where the corresponding Gruff finding appears.
// The report records each accepted suppression and combines duplicate findings about one call.
import { commentRecords } from "./comment-scanner.ts";
import { stripYamlComment } from "./config-parse.ts";
import type { SourceFile } from "./discovery.ts";
import type { Finding, SuppressedFinding, SuppressionSummary } from "./types.ts";

// Reason on each inline audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
export const INLINE_SUPPRESSION_REASON = "Another tool's suppression comment names this check, so the finding is suppressed where it was written.";

// Reason on each repeated-claim audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13c).
export const DUPLICATE_SUPPRESSION_REASON = "Another rule reports the same claim on this line, so the line reports it once.";

// eslint rules section 13c names for gruff-ts, each with the rule that makes the same claim.
const ESLINT_RULES: ReadonlyMap<string, string> = new Map([
  ["no-eval", "security.eval-call"],
  ["no-new-func", "security.new-function"],
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

// Reads the scope and listed rules from an ESLint per-line directive before its written reason.
const ESLINT_DIRECTIVE = /^\s*(?:\/\/|\/\*)?\s*eslint-disable-(next-)?line\b([^\n]*)/;

// Captures the category after biome's ignore comment, such as `lint/security/noGlobalEval`, up to its `:` explanation.
const BIOME_DIRECTIVE = /^\s*(?:\/\/|\/\*)?\s*biome-ignore\s+([\w/]+)/;

// Captures zizmor's audit list in `# zizmor: ignore[unpinned-uses]`.
const ZIZMOR_DIRECTIVE = /#\s*zizmor:\s*ignore\[([^\]]*)\]/g;

// Matches an `eval(` call, the call on which security.unsafe-deserialization repeats security.eval-call's claim.
const EVAL_CALL = /\beval\s*\(/;

// A parsed comment and whether the line contains only that comment.
interface InlineComment {
  text: string;
  standsAlone: boolean;
}

// The lines and indexed comment tokens from one already scanned source snapshot.
interface InlineSource {
  lines: string[];
  comments: Map<number, InlineComment[]>;
}

/*
 * Applies inline suppressions after sensitive exclusions and test-path skips, then combines overlapping findings.
 *
 * Invariant: the directive applies to the selected line only. For example, an ESLint next-line directive covers the line below.
 * The audit records each removed finding so SARIF can still show it as suppressed.
 */
export function applyInlineSuppressions(
  findings: readonly Finding[],
  suppressions: readonly SuppressionSummary[],
  sources: ReadonlyMap<string, { file: SourceFile; source: string }>,
): { findings: Finding[]; suppressions: SuppressionSummary[]; suppressed: SuppressedFinding[] } {
  const sourceCache = new Map<string, InlineSource>();
  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  // A finding leaves only when a comment on its line, or alone on the line above, names a check making its claim.
  for (const finding of findings) {
    let source = sourceCache.get(finding.filePath);
    const snapshot = sources.get(finding.filePath);
    // Use the scanned snapshot so an editor save during the run cannot move a directive onto a different finding.
    if (source === undefined && snapshot !== undefined) {
      source = collectInlineSource(snapshot.source, snapshot.file);
      sourceCache.set(finding.filePath, source);
    }
    // With no source snapshot or matching directive, leave the finding visible.
    if (source && isCoveredByComment(source.comments, finding)) {
      suppressed.push({ finding, justification: INLINE_SUPPRESSION_REASON });
      continue;
    }
    kept.push(finding);
  }
  // Without recorded source lines, there is nothing to check for an overlapping claim on that line.
  const merged = mergeRepeatedClaims(kept, (path) => sourceCache.get(path)?.lines ?? []);
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

// Finds actual directives in the scanned text so a string containing an example cannot hide a finding.
// An empty comment map means the user's file supplies no supported inline directives.
function collectInlineSource(source: string, file: SourceFile): InlineSource {
  const lines = source.split(/\r?\n/u);
  const comments = new Map<number, InlineComment[]>();
  // Most files contain no directive text. Their findings need no comment lookup.
  if (!/eslint-disable-|biome-ignore|zizmor:/u.test(source)) {
    return { lines, comments };
  }
  // Script comments can occur beside code or on their own line.
  if (file.isScript) {
    // Index each parsed comment by the line where the developer finished writing it.
    for (const comment of commentRecords(source)) {
      const startOfLine = source.lastIndexOf("\n", comment.startIndex - 1) + 1;
      const endOfComment = comment.kind === "block" ? comment.endIndex + 1 : comment.endIndex;
      const nextNewline = source.indexOf("\n", endOfComment);
      // A comment at end of file can still belong to the final line.
      const endOfLine = nextNewline < 0 ? source.length : nextNewline;
      const standsAlone = source.slice(startOfLine, comment.startIndex).trim().length === 0
        && source.slice(endOfComment, endOfLine).trim().length === 0;
      // A line can have multiple comments. Keep each one so a later directive does not erase an earlier one.
      const entries = comments.get(comment.endLine) ?? [];
      entries.push({ text: comment.text, standsAlone });
      comments.set(comment.endLine, entries);
    }
  // Workflow YAML can carry zizmor directives after a real comment marker.
  } else if (/\.ya?ml$/iu.test(file.displayPath)) {
    lines.forEach((line, index) => {
      const content = stripYamlComment(line);
      // A hash inside a quoted value remains part of the value.
      if (content.length !== line.length) {
        comments.set(index + 1, [{ text: line.slice(content.length), standsAlone: content.trim().length === 0 }]);
      }
    });
  }
  return { lines, comments };
}

// Reports whether the finding's line, or a comment-only line directly above it, names a check making its claim.
// Invariant: only those two lines are read, so a comment never reaches past the line below it.
function isCoveredByComment(comments: ReadonlyMap<number, InlineComment[]>, finding: Finding): boolean {
  // A finding with no line has no local directive to apply. Lines with no comments supply no matches.
  const line = finding.line ?? 0;
  return (comments.get(line) ?? []).some((comment) => hasCoveringComment(comment.text, finding.ruleId, false))
    || (comments.get(line - 1) ?? []).some((comment) => comment.standsAlone && hasCoveringComment(comment.text, finding.ruleId, true));
}

// Matches the developer's existing directive to the equivalent Gruff finding on the covered line.
function hasCoveringComment(line: string, ruleId: string, isPreviousLine: boolean): boolean {
  return isDisabledByEslint(line, ruleId, isPreviousLine) || isIgnoredByBiome(line, ruleId) || isIgnoredByZizmor(line, ruleId);
}

// Applies the developer's ESLint directive on its intended line. An empty rule list covers every supported ESLint rule.
function isDisabledByEslint(line: string, ruleId: string, isPreviousLine: boolean): boolean {
  const match = ESLINT_DIRECTIVE.exec(line);
  // A same-line directive applies there. A next-line directive applies only one line down.
  if (match === null || Boolean(match[1]) !== isPreviousLine) {
    return false;
  }
  // The developer's reason after "--" is free text and cannot add a rule to the exclusion list.
  const listed = (match[2] ?? "").split(/\s--|\*\//)[0] ?? "";
  const names = listed.split(",").map((name) => name.trim()).filter((name) => name.length > 0);
  return names.length === 0 ? [...ESLINT_RULES.values()].includes(ruleId) : names.some((name) => ESLINT_RULES.get(name) === ruleId);
}

// Applies a developer's Biome ignore to the matching Gruff rule when the comment names that rule or its group.
function isIgnoredByBiome(line: string, ruleId: string): boolean {
  const category = BIOME_DIRECTIVE.exec(line)?.[1];
  // Compare supported rule pairs so a group directive covers only the findings linked to that group.
  for (const [biomeRule, gruffRule] of BIOME_RULES) {
    // A missing Biome category leaves the finding visible. A group such as lint/security can cover multiple rules.
    if (category && gruffRule === ruleId && (biomeRule === category || biomeRule.startsWith(`${category}/`))) {
      return true;
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

// Returns kept findings and justified removals after checking for duplicate claims about eval calls.
// The lines callback supplies source by display path. A repeat stays in kept if its line is missing or fails the eval call pattern.
// Invariant: each security.eval-call finding stays in kept and can justify one security.unsafe-deserialization removal on its file and line.
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
// Each row carries the supplied source label and reason; no removed findings produces an empty list.
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

// Returns a negative, zero or positive number when left sorts before, equals or follows right by UTF-8 bytes for audit ordering.
function compareUtf8Bytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
