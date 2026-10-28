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

/*
 * Tells whether a finding may ever receive a baseline identity.
 *
 * A sensitive finding never does: it stays visible and blocking on every run until the user fixes it or excludes
 * it with a written reason under `sensitiveExclusions`.
 * Stable contract: a sensitive finding never receives an identity, which is what stops a stored review from hiding a secret.
 */
export function isBaselineEligible(finding: Finding): boolean {
  return finding.pillar !== SENSITIVE_PILLAR && !finding.ruleId.startsWith(`${SENSITIVE_PILLAR}.`);
}

/*
 * Replaces every measured value in a message with `#`, per the identity amendment of 2026-09-05.
 *
 * "File has 1010 lines" becomes "File has # lines", so growing the file does not re-key the finding; rewording it
 * still does, because the message is the only stable name a symbol-less finding has.
 *
 * Stable contract: the same message always normalises to the same subject, so the identity stays deterministic.
 */
export function normaliseMeasuredValues(message: string): string {
  return message.replace(MEASURED_VALUE_PATTERN, MEASURED_VALUE_PLACEHOLDER);
}

/*
 * Builds the identity subject: `symbol#ordinal` for a symbol-bearing finding, otherwise the normalised message.
 * The ordinal keeps two same-named functions apart; without it, reviewing one silently baselines the other.
 *
 * Returns undefined when the finding's own text makes it unnameable, which is a property of the scanned code and
 * not an error: a symbol already carrying the separator could pose as another symbol's ordinal, and a finding with
 * neither symbol nor message has nothing to be named by. Such a finding is reported without an identity, exactly as
 * a sensitive finding already is, rather than costing the caller its whole run.
 *
 * Still throws BaselineIdentityError for a missing or non-positive ordinal, because that is this module failing to
 * rank a symbol it accepted, not anything the scanned project did.
 *
 * Stable contract: one declaration always produces one subject, which is what a stored review is matched on.
 * @throws {BaselineIdentityError} when a symbol-bearing finding gets an ordinal that is not a positive integer.
 */
export function baselineSubject(finding: Finding, ordinal: number): string | undefined {
  const symbol = finding.symbol && finding.symbol.length > 0 ? finding.symbol : undefined;
  // A file-level finding has nothing but its message to name it, so its measurement is stripped before hashing.
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

/*
 * Hashes the ratified identity under an explicit tool language.
 * Conformance tests use it to reproduce the digests the family oracle pins for other ports, which is the only
 * proof the rule is one rule rather than five that happen to agree today.
 */
export function computeIdentityFor(toolLanguage: string, ruleId: string, path: string, subject: string): string {
  return createHash("sha256").update([toolLanguage, ruleId, path, subject].join("\0")).digest("hex").slice(0, 16);
}

/*
 * Names every eligible finding in one run, ranking same-named declarations as it goes.
 *
 * This is the single entry point baseline generation and matching both use, so a written identity and a matched
 * identity can never be computed two different ways. A sensitive finding maps to undefined and joins no group.
 * Stable contract: generation and matching call this one function, so a written identity and a matched identity cannot diverge.
 */
export function findingIdentities(findings: Finding[], declarationPosition: DeclarationPositionResolver = declarationPositionByLine): Array<FindingIdentity | undefined> {
  const ordinals = symbolOrdinals(findings, declarationPosition);
  return findings.map((finding, index) => {
    // A sensitive finding is skipped before any hashing, so no secret ever reaches a stored identity.
    if (!isBaselineEligible(finding)) {
      return undefined;
    }
    // The analyser names every finding once, over the whole scan. Reusing that name keeps one finding one identity
    // in every later consumer, which would otherwise re-rank only the subset it was handed (the inline-filtered
    // list, a hook view) and could give a declaration a different ordinal.
    if (finding.baselineIdentity !== undefined && finding.baselineSubject !== undefined) {
      return { identity: finding.baselineIdentity, subject: finding.baselineSubject, declarationKey: storedDeclarationKey(finding, finding.baselineSubject) };
    }
    const subject = baselineSubject(finding, ordinals[index] ?? 0);
    // A finding whose own text cannot name it joins a sensitive finding in carrying no identity: it is still
    // reported and scored, it simply can never be baselined, because there is nothing stable to match it on.
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

/*
 * Ranks each symbol-bearing finding's declaration among same-named declarations in its file.
 * Two findings on one declaration share a position and therefore an ordinal; a second declaration of that name
 * takes the next one, which is what stops one review from covering both.
 * Stable contract: the ordinal counts declarations, not lines, so it survives an edit that only moves the finding.
 */
function symbolOrdinals(findings: Finding[], declarationPosition: DeclarationPositionResolver): number[] {
  const positionsBySymbol = new Map<string, Set<number>>();
  for (const finding of findings) {
    const symbol = namedSymbol(finding);
    if (symbol !== undefined) {
      const key = `${finding.filePath}\0${symbol}`;
      const positions = positionsBySymbol.get(key) ?? new Set<number>();
      positions.add(declarationPosition(finding));
      // Every same-named declaration the parser saw takes a slot, whether or not it warned this run.
      for (const position of declarationPosition.sameNamedPositions?.(finding) ?? []) {
        positions.add(position);
      }
      positionsBySymbol.set(key, positions);
    }
  }

  return findings.map((finding) => {
    const symbol = namedSymbol(finding);
    // A symbol-less finding is named by its message, so it needs no ordinal and takes the sentinel zero.
    if (symbol === undefined) {
      return 0;
    }
    const positions = [...(positionsBySymbol.get(`${finding.filePath}\0${symbol}`) ?? new Set<number>())].sort((left, right) => left - right);
    return positions.indexOf(declarationPosition(finding)) + 1;
  });
}

/*
 * Names the declaration a finding sits on, for collision detection only.
 * A file-level finding names no declaration at all, so every symbol-less occurrence shares one key and is matched
 * by count; keying them by message would report two measurements of one file as an unresolvable collision.
 * Stable contract: equal keys under one identity are an ordinary count; different keys are the collision the run reports.
 */
function declarationKey(finding: Finding, declarationPosition: DeclarationPositionResolver): string {
  return namedSymbol(finding) === undefined ? "declaration:file" : `declaration:${declarationPosition(finding)}`;
}

// The same key for a reused identity: its subject already names one declaration, and no position is re-derived.
// Stable contract: two findings carrying one stored subject share a key, so they are counted, never reported as a collision.
function storedDeclarationKey(finding: Finding, subject: string): string {
  return namedSymbol(finding) === undefined ? "declaration:file" : `declaration:subject:${subject}`;
}

// Reads a finding's symbol only when it actually names one, so an empty string never becomes a declaration.
// Stable contract: an empty symbol reads as no symbol at all, so a blank string never becomes a declaration.
function namedSymbol(finding: Finding): string | undefined {
  if (!isBaselineEligible(finding)) {
    return undefined;
  }
  return finding.symbol && finding.symbol.length > 0 ? finding.symbol : undefined;
}

/*
 * Builds the resolver that maps a finding to the line its declaration begins on, from this run's parsed blocks.
 * The ordinal then counts declarations rather than lines: inserting code above a function moves its line and not
 * its ordinal, which is the whole point of a line-free identity.
 * Stable contract: the position is the declaration's own start line, so the resulting identity is deterministic across runs.
 */
export function declarationPositionFromSpans(spansByFile: Map<string, DeclarationSpan[]>): DeclarationPositionResolver {
  /**
   * Places one finding on the declaration that encloses it.
   * Stable contract: the position is a declaration start line, so the identity it feeds is deterministic across runs.
   * @param finding - the finding to place; its symbol's last segment picks the declaration name
   * @returns the enclosing same-named declaration's start line, or the finding's own line when none encloses it
   */
  const resolver: DeclarationPositionResolver = (finding: Finding) => {
    const line = finding.line ?? 1;
    const symbol = namedSymbol(finding);
    // Without a symbol there is no declaration to rank, and every symbol-less finding of one file shares a key anyway.
    if (symbol === undefined) {
      return line;
    }
    const wanted = symbol.split(".").at(-1) ?? symbol;
    const enclosing = (spansByFile.get(finding.filePath) ?? []).find((span) => span.name === wanted && span.startLine <= line && line <= span.endLine);
    return enclosing?.startLine ?? line;
  };
  resolver.sameNamedPositions = (finding: Finding) => {
    const symbol = namedSymbol(finding);
    // A qualified symbol such as `Widget.process` keeps ranking among its findings: spans carry only the short name,
    // so counting every `process` in the file would merge two classes' methods into one sequence.
    if (symbol === undefined || symbol.includes(".")) {
      return [];
    }
    return (spansByFile.get(finding.filePath) ?? []).filter((span) => span.name === symbol).map((span) => span.startLine);
  };
  return resolver;
}

// Ranks a symbol on its own line when no parsed declarations are available, as a direct API call has.
// Stable contract: without parsed declarations the finding's own line is the position, which keeps a direct API call deterministic.
export function declarationPositionByLine(finding: Finding): number {
  return finding.line ?? 1;
}
