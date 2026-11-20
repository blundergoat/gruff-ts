// Type-safety and reliability rule packs: TS directive rationales, non-null assertions, double
// casts, exported `any`, async forEach, non-Error throws, useless catches,
// swallowed catches. Each rule emits findings in the stable, deterministic per-line/per-source order.
import { hasSuppressionRationale } from "./comment-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Check a TypeScript line for directive rationale, non-null assertions, double casts, and exported any in that stable order.
// Use file and lineNumber for location, line for comments, codeLine for code, and sourceLines for preceding comments when supplied.
// trackingTokens can add accepted rationale patterns. Returns nothing and appends matches to the supplied findings array.
export function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[], sourceLines: readonly string[] = [], trackingTokens: readonly RegExp[] = []): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings, sourceLines, trackingTokens);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, line, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
}

// Returns nothing. Checks codeLine for async forEach callbacks and non-Error throws and appends any findings.
// file supplies the reported path and lineNumber its one-based line; checks run in that order for stable emission.
export function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
}

/*
 * Flag catches that only rethrow their untyped identifier binding because they add no handling. Wrapped rethrows do not match.
 * Returns nothing. Appends a stable waste.useless-catch finding for each match.
 * file supplies the path; source supplies catch text and line offsets; findings receives each match.
 */
export function analyseUselessCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{\s*throw\s+\1\s*;?\s*\}/g)) {
    const binding = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "waste.useless-catch",
        message: `catch block only rethrows \`${binding}\` without adding handling.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "maintainability",
        confidence: "high",
        remediation: "Remove the catch block or add meaningful handling.",
        metadata: { binding },
      }),
    );
  }
}

/**
 * Flag empty or comment-only catches because a discarded error can hide a failure unless the comment explains the ignore.
 *
 * @param file - Source file supplying the display path for each finding.
 * @param rawSource - Original source used to read catch comments and locate matches.
 * @param codeSource - Corresponding code text used to locate catches and check their bodies.
 * @param findings - Caller-owned array that receives stable waste.swallowed-catch findings.
 * @param trackingTokens - Extra patterns for rationale references. Omit to use the built-in heuristic alone.
 * @returns Nothing. Appends a finding for each matching catch without a recognised rationale.
 */
export function analyseSwallowedCatches(file: SourceFile, rawSource: string, codeSource: string, findings: Finding[], trackingTokens: readonly RegExp[] = []): void {
  for (const match of codeSource.matchAll(/\bcatch\s*(?:\(([^)]*)\))?\s*\{([\s\S]*?)\}/g)) {
    const body = match[2] ?? "";
    const rawBody = rawCatchBody(rawSource, codeSource, match);
    if (!isSwallowedCatchBody(body) || hasIntentionalCatchRationale(rawBody, trackingTokens)) {
      continue;
    }
    const binding = (match[1] ?? "").trim();
    findings.push(
      makeFinding({
        ruleId: "waste.swallowed-catch",
        message: "catch block swallows an error without rethrowing, returning, or reporting it.",
        filePath: file.displayPath,
        line: byteLine(rawSource, match.index ?? 0),
        severity: "warning",
        pillar: "maintainability",
        confidence: "medium",
        remediation: "Handle the error explicitly, rethrow it, or document an intentional ignore path.",
        metadata: { ...(binding ? { binding } : {}) },
      }),
    );
  }
}

// Maps a catch-body match from masked code back to raw source so rationale comments remain visible.
// rawSource and codeSource must share offsets, and match selects the catch.
// An invalid brace range or empty body returns empty text, leaving no rationale to inspect.
function rawCatchBody(rawSource: string, codeSource: string, match: RegExpMatchArray): string {
  const start = match.index ?? 0;
  const openBrace = codeSource.indexOf("{", start);
  const closeBrace = start + (match[0]?.length ?? 0) - 1;
  return openBrace === -1 || closeBrace <= openBrace ? "" : rawSource.slice(openBrace + 1, closeBrace);
}

// Checks the catch body's comments for signs of intent, using trackingTokens to recognise tracking references.
// Returns true for a rationale match, at least two words or a recognised intent marker. Blank text and TODO, FIXME or XXX return false.
// A bare /* silent */ has one word, so it needs a rationale match to qualify.
function hasIntentionalCatchRationale(body: string, trackingTokens: readonly RegExp[]): boolean {
  const commentText = (body.match(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g) ?? []).map((comment) => comment.replace(/^\/\/+|^\/\*+|\*+\/$/g, "")).join(" ");
  if (commentText.trim() === "" || /\b(?:TODO|FIXME|XXX)\b/.test(commentText)) {
    return false;
  }
  const words = commentText.match(/[A-Za-z][A-Za-z'-]*/g) ?? [];
  return hasSuppressionRationale(commentText, trackingTokens) || words.length >= 2 || /\b(?:ignored?|no-?op|cleanup|teardown|best[- ]effort|non[- ]fatal|optional)\b/i.test(commentText);
}

/**
 * Flag @ts-ignore and @ts-expect-error without a recognised reason on the line or in the line comments directly above it.
 *
 * @param file - Source file supplying the display path for the finding.
 * @param line - Raw source line to check for a directive and its suffix rationale.
 * @param lineNumber - Source line used to locate the directive and look up preceding comments.
 * @param findings - Caller-owned array that receives the stable modernisation.ts-comment-without-rationale finding.
 * @param sourceLines - Raw file lines used to check comments immediately above the directive.
 * @param trackingTokens - Additional patterns accepted as tracking references in the rationale.
 * @returns Nothing. Appends a finding only when a directive lacks a recognised rationale.
 */
function pushTsDirectiveFinding(file: SourceFile, line: string, lineNumber: number, findings: Finding[], sourceLines: readonly string[], trackingTokens: readonly RegExp[]): void {
  const directive = tsDirectiveWithoutRationale(line, trackingTokens);
  // A recognised rationale in the contiguous line comments above the directive suppresses this finding.
  if (!directive || hasDirectiveRationale(lineCommentsAbove(sourceLines, lineNumber - 1), trackingTokens)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "modernisation.ts-comment-without-rationale",
      message: `${directive.directive} suppresses TypeScript without a nearby rationale.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "modernisation",
      confidence: "medium",
      remediation: "Add a short reason on the directive line or in the `//` comment lines directly above it, or remove the suppression.",
      metadata: { directive: directive.directive },
    }),
  );
}

// Scan codeLine for identifier and dotted-property assertions at recognised boundaries to avoid reading != as an assertion.
// Use file and lineNumber for location. Returns nothing and appends a stable modernisation.non-null-assertion finding to findings per match.
function pushNonNullAssertionFindings(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  for (const match of codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)!(?=\.|\[|\)|,|;|\s+(?:as|in|instanceof)\b|\s*$)/g)) {
    const expression = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "modernisation.non-null-assertion",
        message: `Non-null assertion on \`${expression}\` bypasses TypeScript's null checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        symbol: expression,
        remediation: "Narrow the value with a guard or handle the null/undefined case explicitly.",
        metadata: { expression },
      }),
    );
  }
}

// Scan codeLine for double casts through unknown or any. Use rawLine for rationale and file and lineNumber for the finding location.
// A recognised rationale lowers a match to advisory to preserve visibility for documented boundary casts. Other matches are warnings.
// Returns nothing and appends a modernisation.double-cast finding with stable metadata to findings for each match.
function pushDoubleCastFindings(file: SourceFile, rawLine: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  for (const match of codeLine.matchAll(/\bas\s+(unknown|any)\s+as\s+([^;,\n]+)/g)) {
    const sourceType = match[1] ?? "";
    const targetType = (match[2] ?? "").trim().replace(/[.)]+$/, "");
    const hasRationale = hasDoubleCastTrustBoundaryRationale(rawLine);
    findings.push(
      makeFinding({
        ruleId: "modernisation.double-cast",
        message: `Double cast through \`${sourceType}\` bypasses structural type checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: hasRationale ? "advisory" : "warning",
        pillar: "modernisation",
        confidence: "medium",
        remediation: "Prefer a typed parser, type guard, or narrower assertion at the trust boundary.",
        metadata: { sourceType, targetType, ...(hasRationale ? { rationale: "trust-boundary" } : {}) },
      }),
    );
  }
}

// Accepts only inline comments that name the trust boundary or validation reason for the cast.
function hasDoubleCastTrustBoundaryRationale(rawLine: string): boolean {
  return (
    /(?:\/\/|\/\*)/.test(rawLine) &&
    /\b(?:trust boundary|external input|wire format|parser boundary|TS2352|unknown hop|validated|narrowed|type guard|schema)\b/i.test(rawLine)
  );
}

/**
 * Flag possible exported uses of any. Emit one finding per matching line to avoid repeating the same declaration.
 *
 * @param file - Source file supplying the display path for the finding.
 * @param codeLine - Code to check for a named export declaration and an any token on the same line.
 * @param lineNumber - Source line attached to the result.
 * @param findings - Caller-owned array that receives the stable waste.exported-any finding on a match.
 * @returns Nothing. Appends at most one finding and leaves the array alone when no export matches.
 */
function pushExportedAnyFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const exportedAny = exportedAnySymbol(codeLine);
  if (!exportedAny) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "waste.exported-any",
      message: `Exported API \`${exportedAny}\` exposes \`any\` in its public contract.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "maintainability",
      confidence: "medium",
      symbol: exportedAny,
      remediation: "Use a named interface, unknown plus validation, or a precise generic type.",
      metadata: { symbolName: exportedAny },
    }),
  );
}

// Scan codeLine for async forEach callbacks because forEach does not await them and their rejections can go unhandled.
// Use file and lineNumber to locate the result. Returns nothing and appends a stable security.async-foreach finding to findings on a match.
function pushAsyncForEachFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  if (!/\.forEach\s*\(\s*async\b/.test(codeLine)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.async-foreach",
      message: "async callbacks passed to forEach are not awaited by the caller.",
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      remediation: "Use for...of with await, Promise.all, or an explicit queue.",
      metadata: { callName: "forEach" },
    }),
  );
}

/**
 * Flag literal non-Error throw candidates because these values lack the usual Error stack and subclass contract.
 *
 * @param file - Source file supplying the display path for the finding.
 * @param codeLine - Code checked for a literal-looking thrown expression.
 * @param lineNumber - One-based source line attached to the finding.
 * @param findings - Accumulator for security.throw-non-error findings.
 * @returns Nothing. Appends one finding on a match and leaves the accumulator unchanged otherwise.
 */
function pushNonErrorThrowFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const thrown = nonErrorThrowExpression(codeLine);
  if (!thrown) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.throw-non-error",
      message: "Throwing non-Error values loses stack and error-shape information.",
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      remediation: "Throw an Error subclass with a clear message and structured properties.",
      metadata: { expression: thrown },
    }),
  );
}

// Return a directive-name object for an @ts-ignore or @ts-expect-error in line without an accepted suffix rationale. Return undefined otherwise.
// Three runs of at least three ASCII letters or a built-in rationale marker qualify.
// trackingTokens adds accepted rationale patterns; testing a stateful pattern may change its lastIndex.
function tsDirectiveWithoutRationale(line: string, trackingTokens: readonly RegExp[]): { directive: string } | undefined {
  const match = line.match(/@ts-(ignore|expect-error)\b(.*)$/);
  if (!match?.[1]) {
    return undefined;
  }
  const rationale = match[2] ?? "";
  if (hasDirectiveRationale(rationale, trackingTokens)) {
    return undefined;
  }
  return { directive: `@ts-${match[1]}` };
}

// Return whether directiveSuffix has a rationale marker or at least three runs of three or more ASCII letters after separator trimming.
// trackingTokens adds accepted rationale patterns; testing a stateful pattern may change its lastIndex.
function hasDirectiveRationale(directiveSuffix: string, trackingTokens: readonly RegExp[]): boolean {
  const cleaned = directiveSuffix.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return hasSuppressionRationale(cleaned, trackingTokens) || words.length >= 3;
}

// Joins consecutive line comments above the target in source order so a rationale can sit above the directive.
// lines supplies source text; index is the target's zero-based position. Return empty text when no preceding comments exist.
function lineCommentsAbove(lines: readonly string[], index: number): string {
  const texts: string[] = [];
  for (let current = index - 1; current >= 0; current -= 1) {
    const trimmed = (lines[current] ?? "").trim();
    if (!trimmed.startsWith("//")) {
      break;
    }
    texts.unshift(trimmed.replace(/^\/\/+\s*/, ""));
  }
  return texts.join(" ");
}

// Return an export declaration's name from codeLine only when it also contains any; return undefined when no such match exists.
// This line scan does not establish whether any belongs to the public type.
function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

// Allow `throw new XxxError(...)` and `throw e` (bare identifier - usually a rethrow), reject literals.
// Returns a truncated preview because the full expression can be arbitrarily long.
function nonErrorThrowExpression(codeLine: string): string | undefined {
  const match = codeLine.match(/\bthrow\s+(.+?);?$/);
  const expression = (match?.[1] ?? "").trim();
  if (!expression) {
    return undefined;
  }
  if (/^(?:new\s+[A-Za-z_$][A-Za-z0-9_$]*Error\b|[A-Za-z_$][A-Za-z0-9_$]*)/.test(expression)) {
    return undefined;
  }
  return /^(?:["'`]|\d|\{|\[|true\b|false\b|null\b|undefined\b)/.test(expression) ? expression.slice(0, 40) : undefined;
}

// Return true when body is empty after removing line and block comments and whitespace. A catch body holding only a
// throwaway placeholder comment reads as a deliberate swallow but documents nothing about the
// recovery path - that is still the rule's signal.
function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}
