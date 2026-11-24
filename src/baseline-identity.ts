// The one line-free identity a baseline stores for a finding, ratified for the family in
// `contracts/core/finding-identity.v1.json`.
//
// When a user runs `gruff-ts analyse --generate-baseline`, every ordinary finding is named by this identity and
// nothing positional. On the next `analyse --baseline` a finding that moved lines still matches, while a new
// sibling of the same rule never inherits the review.
//
// Three decisions live here:
// - a symbol-bearing finding is named by its symbol plus a declaration ordinal, so two same-named functions stay apart;
// - a finding naming no symbol falls back to its message with measured values normalised, so a grown file keeps its review;
// - a sensitive finding receives no identity at all, because a stored identity is what would let a review hide a secret.
import { createHash } from "node:crypto";
import type { Finding } from "./types.ts";

// Token gruff-ts contributes to every identity, so the same rule on the same path never collides with another port's finding.
export const TOOL_LANGUAGE = "ts";

// Joins a symbol to its declaration ordinal; a symbol carrying it could forge another symbol's ordinal, so it gets no identity.
const ORDINAL_SEPARATOR = "#";

// Every number a message can state: a length, a count, a percentage, or a version, including groups such as 1,234 or 12.5.
const MEASURED_VALUE_PATTERN = /[0-9]+(?:[.,][0-9]+)*/gu;

// What every measured value becomes in a subject, so a file that grew from 1010 to 1200 lines keeps its reviewed identity.
const MEASURED_VALUE_PLACEHOLDER = "#";

// The pillar that marks a secret; the rule-id prefix is checked alongside it so a mis-tagged rule still cannot be baselined.
const SENSITIVE_PILLAR = "sensitive-data";

/*
 * One finding's durable name, plus the two facts matching needs alongside it.
 *
 * `declarationKey` is equal for two findings on one declaration; two different keys under one identity are a
 * collision, which the run reports by name and never hides.
 */
export interface FindingIdentity {
  identity: string;
  subject: string;
  declarationKey: string;
}

// One parsed declaration and the lines it covers, used to rank same-named declarations in one file.
export interface DeclarationSpan {
  name: string;
  startLine: number;
  endLine: number;
}

/*
 * Maps a finding to the line its declaration starts on and, when the parse is available, lists the start line of
 * every same-named declaration in its file.
 *
 * The list is what makes the ordinal count declarations rather than findings. Without it a clean earlier
 * declaration takes no slot, so the day it first warns it takes the later declaration's ordinal and stored review.
 * Stable contract: with the list present, a declaration's ordinal does not depend on which findings this run emitted.
 */
export interface DeclarationPositionResolver {
  (finding: Finding): number;
  sameNamedPositions?: (finding: Finding) => readonly number[];
}

/** Raised when a finding cannot be given a durable name, so the run reports a baseline failure instead of guessing. */
export class BaselineIdentityError extends Error {}

/**
 * Check baseline eligibility. Stable contract: sensitive findings receive no baseline identity, so a stored review cannot suppress them.
 * A matching sensitiveExclusions entry with a written reason can remove a finding before baseline application.
 *
 * @param finding - finding whose pillar and rule ID are checked against sensitive-data
 * @returns False for findings in the sensitive-data pillar or with a rule ID starting with sensitive-data followed by a dot; otherwise true.
 */
export function isBaselineEligible(finding: Finding): boolean {
  return finding.pillar !== SENSITIVE_PILLAR && !finding.ruleId.startsWith(`${SENSITIVE_PILLAR}.`);
}

/**
 * Normalise numeric sequences in a finding message to keep a symbol-less finding's subject stable as measurements change.
 * Changes to the surrounding text still affect the subject.
 *
 * @param message - finding message text whose numeric sequences are replaced
 * @returns The message with numeric sequences, including digits joined by periods or commas, replaced by #.
 */
export function normaliseMeasuredValues(message: string): string {
  return message.replace(MEASURED_VALUE_PATTERN, MEASURED_VALUE_PLACEHOLDER);
}

/**
 * Build a stable baseline subject. An ordinal distinguishes declarations with the same symbol so each can be reviewed independently.
 *
 * @param finding - supplies the symbol or, when there is no symbol, the message used for matching
 * @param ordinal - one-based declaration rank used when the symbol can be named
 * @returns The symbol with its ordinal or the normalised message. Undefined means a reserved separator or empty message prevents naming.
 * @throws {BaselineIdentityError} - a symbol without the reserved separator was given an ordinal that is not a positive integer.
 */
export function baselineSubject(finding: Finding, ordinal: number): string | undefined {
  const symbol = finding.symbol && finding.symbol.length > 0 ? finding.symbol : undefined;
  // Normalise measured values so changes to the measurement can preserve the file-level subject.
  if (symbol === undefined) {
    return finding.message.length === 0 ? undefined : normaliseMeasuredValues(finding.message);
  }
  // A symbol carrying the separator could pose as another symbol's ordinal, so it is left unnamed rather than hashed ambiguously.
  if (symbol.includes(ORDINAL_SEPARATOR)) {
    return undefined;
  }
  // Defaulting a missing ordinal to 1 would merge namesakes back together, the collision the ordinal exists to prevent.
  if (!Number.isInteger(ordinal) || ordinal < 1) {
    throw new BaselineIdentityError(`finding ${finding.ruleId} in ${finding.filePath} has symbol "${symbol}" without a declaration ordinal`);
  }
  return `${symbol}${ORDINAL_SEPARATOR}${ordinal}`;
}

/**
 * Compute the stable 16-character baseline digest for a finding identity.
 * The explicit language lets conformance tests compare the calculation with pinned identities for other ports.
 *
 * @param toolLanguage - writer language token included in the hash input
 * @param ruleId - finding rule identifier included in the digest input
 * @param path - finding file path included in the digest input
 * @param subject - finding identity subject included in the digest input
 * @returns The 16-character lowercase hex prefix of the SHA-256 digest over the null-joined inputs.
 */
export function computeIdentityFor(toolLanguage: string, ruleId: string, path: string, subject: string): string {
  return createHash("sha256").update([toolLanguage, ruleId, path, subject].join("\0")).digest("hex").slice(0, 16);
}

/**
 * Assign stable baseline identities through the same path for generation and matching, preserving names already assigned to the full scan.
 *
 * @param findings - findings to rank together or whose stored identities and subjects to reuse
 * @param declarationPosition - resolver for declaration ranking. Defaults to the finding's line position.
 * @returns One identity record per input finding in order. Ineligible findings and findings with no usable subject receive undefined.
 */
export function findingIdentities(findings: Finding[], declarationPosition: DeclarationPositionResolver = declarationPositionByLine): Array<FindingIdentity | undefined> {
  const ordinals = symbolOrdinals(findings, declarationPosition);
  return findings.map((finding, index) => {
    // Findings classified as sensitive get no baseline identity, so a stored review cannot suppress them.
    if (!isBaselineEligible(finding)) {
      return undefined;
    }
    // Reuse a name assigned across the full scan so a filtered consumer preserves the declaration's original ordinal.
    if (finding.baselineIdentity !== undefined && finding.baselineSubject !== undefined) {
      return { identity: finding.baselineIdentity, subject: finding.baselineSubject, declarationKey: storedDeclarationKey(finding, finding.baselineSubject) };
    }
    const subject = baselineSubject(finding, ordinals[index] ?? 0);
    // An unusable subject leaves the finding without a stable match key, so baseline matching cannot hide it.
    if (subject === undefined) {
      return undefined;
    }
    return {
      identity: computeIdentityFor(TOOL_LANGUAGE, finding.ruleId, finding.filePath, subject),
      subject,
      declarationKey: declarationKey(finding, declarationPosition),
    };
  });
}

/**
 * Rank same-named declarations within each file so stable baseline identities distinguish namesakes.
 *
 * @param findings - current findings whose file and symbol define each ranking group
 * @param declarationPosition - resolves declaration positions and can supply additional same-name positions
 * @returns One ordinal per finding in input order. Named declarations rank from one, and zero marks a finding with no eligible symbol.
 */
function symbolOrdinals(findings: Finding[], declarationPosition: DeclarationPositionResolver): number[] {
  const positionsBySymbol = new Map<string, Set<number>>();
  for (const finding of findings) {
    const symbol = namedSymbol(finding);
    if (symbol !== undefined) {
      const key = `${finding.filePath}\0${symbol}`;
      const positions = positionsBySymbol.get(key) ?? new Set<number>();
      positions.add(declarationPosition(finding));
      // Include any extra positions supplied by the resolver so declarations without findings can still reserve their slots.
      for (const position of declarationPosition.sameNamedPositions?.(finding) ?? []) {
        positions.add(position);
      }
      positionsBySymbol.set(key, positions);
    }
  }

  return findings.map((finding) => {
    const symbol = namedSymbol(finding);
    // With no eligible symbol, zero signals that there is no declaration rank to use.
    if (symbol === undefined) {
      return 0;
    }
    const positions = [...(positionsBySymbol.get(`${finding.filePath}\0${symbol}`) ?? new Set<number>())].sort((left, right) => left - right);
    return positions.indexOf(declarationPosition(finding)) + 1;
  });
}

/**
 * Build a stable collision key for the current finding, where distinct keys under the same baseline identity mark a collision.
 * Findings without an eligible symbol share a file-level key so repeated measurements can be matched by count.
 *
 * @param finding - finding whose symbol eligibility and position determine the collision key
 * @param declarationPosition - resolver returning the declaration position for a named finding
 * @returns The file-level key for findings without an eligible symbol, or a declaration key using the resolved position.
 */
function declarationKey(finding: Finding, declarationPosition: DeclarationPositionResolver): string {
  return namedSymbol(finding) === undefined ? "declaration:file" : `declaration:${declarationPosition(finding)}`;
}

/**
 * Build the stable collision key for a finding reusing its baseline identity to preserve grouping.
 *
 * @param finding - finding checked for an eligible symbol
 * @param subject - stored baseline subject used in the key for a named finding
 * @returns The file-level key when there is no eligible symbol, or a subject-scoped declaration key for a named finding.
 */
function storedDeclarationKey(finding: Finding, subject: string): string {
  return namedSymbol(finding) === undefined ? "declaration:file" : `declaration:subject:${subject}`;
}

/**
 * Extract the symbol used for stable declaration grouping, excluding findings ineligible for baseline matching.
 *
 * @param finding - finding checked for baseline eligibility and a non-empty symbol
 * @returns The non-empty symbol, or undefined when missing, empty, or ineligible (even when carrying a symbol) so it gets no rank.
 */
function namedSymbol(finding: Finding): string | undefined {
  if (!isBaselineEligible(finding)) {
    return undefined;
  }
  return finding.symbol && finding.symbol.length > 0 ? finding.symbol : undefined;
}

// Rules whose finding line anchors on a leading comment or tag above the callable declaration rather than inside its body span.
const DOCBLOCK_COMMENT_ANCHORED_RULES = new Set([
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.stale-param-tag",
]);

/**
 * Build a stable position resolver so moving a finding within a matched declaration preserves its position for ranking.
 *
 * @param spansByFile - parsed spans grouped by path for matching declarations and collecting same-name positions
 * @returns Resolver with same-name positions. Uses the matching span's start line or the finding's line, defaulting to 1 if unlocated.
 */
export function declarationPositionFromSpans(spansByFile: Map<string, DeclarationSpan[]>): DeclarationPositionResolver {
  /**
   * Resolve a stable declaration position for identity ranking, using the parsed span when it matches the finding.
   *
   * @param finding - occurrence whose path, line and final symbol segment locate its declaration
   * @returns The matching declaration's start line, or the finding's line when none matches. A missing finding line is treated as 1.
   */
  const resolver: DeclarationPositionResolver = (finding: Finding) => {
    const line = finding.line ?? 1;
    const symbol = namedSymbol(finding);
    // Without an eligible symbol there is no declaration to rank, so use the finding's line position.
    if (symbol === undefined) {
      return line;
    }
    const wanted = symbol.split(".").at(-1) ?? symbol;
    const fileSpans = spansByFile.get(finding.filePath) ?? [];
    // Docblock findings anchor on the leading comment above the declaration, so map them to the nearest same-named span at or after that line.
    if (DOCBLOCK_COMMENT_ANCHORED_RULES.has(finding.ruleId)) {
      const following = nearestSpanAtOrAfterLine(fileSpans, wanted, line);
      if (following !== undefined) {
        return following.startLine;
      }
    }
    const enclosing = fileSpans.find((span) => span.name === wanted && span.startLine <= line && line <= span.endLine);
    return enclosing?.startLine ?? line;
  };
  resolver.sameNamedPositions = (finding: Finding) => {
    const symbol = namedSymbol(finding);
    // With no eligible symbol there are no positions to add to ranking.
    // Qualified names rank from their findings alone because span names lack the class qualifier and could merge distinct methods.
    if (symbol === undefined || symbol.includes(".")) {
      return [];
    }
    return (spansByFile.get(finding.filePath) ?? []).filter((span) => span.name === symbol).map((span) => span.startLine);
  };
  return resolver;
}

/**
 * Finds the nearest same-named declaration span starting at or after a leading-comment finding line.
 *
 * @param spans - parsed declaration spans for the finding's file
 * @param wantedName - unqualified declaration symbol name being matched
 * @param line - one-based comment or tag line where the docblock finding is anchored
 * @returns The matching span with the smallest `startLine >= line`, or undefined when none follows.
 */
function nearestSpanAtOrAfterLine(spans: readonly DeclarationSpan[], wantedName: string, line: number): DeclarationSpan | undefined {
  let nearest: DeclarationSpan | undefined;
  for (const span of spans) {
    if (span.name !== wantedName || span.startLine < line) {
      continue;
    }
    if (nearest === undefined || span.startLine < nearest.startLine) {
      nearest = span;
    }
  }
  return nearest;
}

/**
 * Resolve a stable declaration position from the finding's own line when parsed declarations are unavailable.
 *
 * @param finding - finding whose line property supplies the fallback position
 * @returns The finding's line number, or 1 for unlocated findings.
 */
export function declarationPositionByLine(finding: Finding): number {
  return finding.line ?? 1;
}
