// Type-safety and reliability rule packs: TS directive rationales, non-null assertions, double
// casts, exported `any`, async forEach, non-Error throws, useless catches,
// swallowed catches. Each rule emits findings in the stable, deterministic per-line/per-source order.
import { hasSuppressionRationale } from "./comment-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

/**
 * Check a TypeScript line for directive rationale, non-null assertions, double casts, and exported any in that stable order.
 *
 * @param file - Source file supplying the location path for emitted findings.
 * @param line - Raw source line inspected for directive and cast rationale comments.
 * @param codeLine - Stripped code text checked for assertions, double casts, and exported any.
 * @param lineNumber - One-based line number used for finding locations and preceding comment lookup.
 * @param findings - Caller-owned array that receives appended findings.
 * @param sourceLines - Raw file lines used to inspect preceding comments when supplied.
 * @param trackingTokens - Extra patterns that add accepted rationale tokens.
 * @returns Nothing. Appends matching findings to the supplied findings array.
 */
export function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[], sourceLines: readonly string[] = [], trackingTokens: readonly RegExp[] = []): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings, sourceLines, trackingTokens);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, line, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
}

/**
 * Check a code line for async forEach callbacks and non-Error throws in order for stable emission.
 *
 * @param file - Source file supplying the reported display path.
 * @param codeLine - Stripped code line scanned for async forEach and non-Error throws.
 * @param lineNumber - One-based line number attached to any emitted finding.
 * @param findings - Caller-owned array that receives appended findings.
 * @returns Nothing. Appends matching findings to findings.
 */
export function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
}

/**
 * Flag catches that only rethrow their untyped identifier binding because they add no handling; wrapped rethrows do not match.
 *
 * @param file - Source file supplying the display path for each finding.
 * @param source - Source text scanned for catch text and byte-line offsets.
 * @param findings - Caller-owned array that receives a stable waste.useless-catch finding for each match.
 * @returns Nothing. Appends a stable waste.useless-catch finding for each match.
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

/**
 * Map a catch-body match from masked code back to raw source so rationale comments remain visible.
 *
 * @param rawSource - Original source text that must share offsets with codeSource.
 * @param codeSource - Masked code text that must share offsets with rawSource.
 * @param match - Regex match selecting the catch block whose braces bound the body.
 * @returns Raw catch body slice, or empty text when the brace range is invalid or empty.
 */
function rawCatchBody(rawSource: string, codeSource: string, match: RegExpMatchArray): string {
  const start = match.index ?? 0;
  const openBrace = codeSource.indexOf("{", start);
  const closeBrace = start + (match[0]?.length ?? 0) - 1;
  return openBrace === -1 || closeBrace <= openBrace ? "" : rawSource.slice(openBrace + 1, closeBrace);
}

/**
 * Check a catch body's comments for signs of intent; a bare one-word block comment needs a rationale match to qualify.
 *
 * @param body - Raw catch body whose line and block comments are inspected for intent.
 * @param trackingTokens - Extra patterns used to recognise tracking references in comment text.
 * @returns True for a rationale match, at least two words, or a recognised intent marker; false for blank text or TODO/FIXME/XXX.
 */
function hasIntentionalCatchRationale(body: string, trackingTokens: readonly RegExp[]): boolean {
  const commentText = (body.match(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g) ?? []).map((comment) => comment.replace(/^\/\/+|^\/\*+|\*+\/$/g, "")).join(" ");
  // Reject placeholder markers regardless of letter case so `// todo: retry later` never counts as an intentional catch rationale.
  if (commentText.trim() === "" || /\b(?:TODO|FIXME|XXX)\b/i.test(commentText)) {
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

/**
 * Scan codeLine for identifier and dotted-property assertions at recognised boundaries to avoid reading != as an assertion.
 *
 * @param file - Source file supplying the display path for each finding.
 * @param codeLine - Code text scanned for non-null assertion operators.
 * @param lineNumber - One-based line number used for each finding location.
 * @param findings - Caller-owned array receiving a stable modernisation.non-null-assertion finding per match.
 * @returns Nothing. Appends a stable modernisation.non-null-assertion finding to findings per match.
 */
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

/**
 * Scan codeLine for double casts through unknown or any; a recognised rationale lowers severity to advisory to preserve visibility.
 *
 * @param file - Source file supplying the display path for each finding.
 * @param rawLine - Raw source line inspected for an inline trust-boundary rationale comment.
 * @param codeLine - Stripped code text scanned for double casts through unknown or any.
 * @param lineNumber - One-based line number used for the finding location.
 * @param findings - Caller-owned array receiving a modernisation.double-cast finding with stable metadata per match.
 * @returns Nothing. Appends a modernisation.double-cast finding with stable metadata for each match.
 */
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

/**
 * Accept only inline comments that name the trust boundary or validation reason for a double cast.
 *
 * @param rawLine - Raw source line checked for an inline comment and trust-boundary rationale keyword.
 * @returns True when rawLine contains a comment marker and a recognised trust-boundary or validation term.
 */
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

/**
 * Scan codeLine for async forEach callbacks because forEach does not await them and their rejections can go unhandled.
 *
 * @param file - Source file supplying the display path for the finding.
 * @param codeLine - Stripped code line checked for an async callback passed to forEach.
 * @param lineNumber - One-based line number used to locate the result.
 * @param findings - Caller-owned array receiving a stable security.async-foreach finding on a match.
 * @returns Nothing. Appends a stable security.async-foreach finding to findings on a match.
 */
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

/**
 * Detect @ts-ignore or @ts-expect-error in line without an accepted suffix rationale.
 *
 * @param line - Raw source line checked for a TypeScript suppression directive and trailing rationale.
 * @param trackingTokens - Extra accepted rationale patterns; testing a stateful pattern may change its lastIndex.
 * @returns Directive-name object when a directive lacks an accepted suffix rationale, or undefined otherwise.
 */
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

/**
 * Check whether directiveSuffix has a rationale marker or at least three runs of three or more ASCII letters after separator trimming.
 *
 * @param directiveSuffix - Text following the TypeScript suppression directive on the same line.
 * @param trackingTokens - Extra accepted rationale patterns; testing a stateful pattern may change its lastIndex.
 * @returns True when the trimmed suffix matches a rationale marker or has at least three three-letter words.
 */
function hasDirectiveRationale(directiveSuffix: string, trackingTokens: readonly RegExp[]): boolean {
  const cleaned = directiveSuffix.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return hasSuppressionRationale(cleaned, trackingTokens) || words.length >= 3;
}

/**
 * Join consecutive prose line comments above the target in source order so a rationale can sit above a TypeScript directive.
 * Skips lint and TypeScript directive-only lines so an adjacent linter suppression comment never substitutes for a rationale.
 *
 * @param lines - Source file lines searched backwards from the target line.
 * @param index - Zero-based position of the target line.
 * @returns Joined preceding prose comment text in source order, or empty text when no qualifying comments exist.
 */
function lineCommentsAbove(lines: readonly string[], index: number): string {
  const texts: string[] = [];
  for (let current = index - 1; current >= 0; current -= 1) {
    const trimmed = (lines[current] ?? "").trim();
    if (!trimmed.startsWith("//")) {
      break;
    }
    const body = trimmed.replace(/^\/\/+\s*/, "");
    // Another tool's suppression directive (ESLint, Biome, or TypeScript) explains nothing on its own; skip it and keep checking above.
    if (/^(?:eslint-disable(?:-(?:next-)?line)?|biome-ignore|@ts-(?:expect-error|ignore|nocheck))\b/i.test(body)) {
      continue;
    }
    texts.unshift(body);
  }
  return texts.join(" ");
}

/**
 * Extract an export declaration's name from codeLine only when it also contains any; does not establish whether any is in the public type.
 *
 * @param codeLine - Stripped code line checked for both an export declaration and an any token.
 * @returns Exported symbol name when both match, or undefined when no such match exists.
 */
function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

/**
 * Extract literal non-Error throw expressions while allowing `throw new XxxError(...)` and bare identifier throws.
 *
 * @param codeLine - Stripped code line inspected for a thrown expression.
 * @returns Truncated expression preview up to 40 characters because the full expression can be arbitrarily long, or undefined.
 */
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

/**
 * Check whether body is empty after removing line and block comments and whitespace, treating placeholder-only comments as swallowed.
 *
 * @param body - Catch block body text stripped of comments and whitespace to check for meaningful statements.
 * @returns True when body contains no meaningful code after stripping comments and whitespace.
 */
function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}
