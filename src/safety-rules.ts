// Type-safety and reliability rule packs: TS directive rationales, non-null assertions, double
// casts, exported `any`, async forEach, floating promises, non-Error throws, useless catches,
// swallowed catches. Each rule emits findings in the stable, deterministic per-line/per-source order.
import { hasSuppressionRationale } from "./comment-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Four-rule TypeScript safety pass: directive comment, non-null assertion, double cast, exported any.
// Stable, deterministic ordering keeps the per-line findings in a known sequence.
export function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
}

// Three reliability rules per line: async-forEach, floating-promise, non-Error throw. Order is
// the stable contract - reshuffling shifts per-block emission and churns baselines.
export function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushFloatingPromiseFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
}

/*
 * `catch (e) { throw e; }` patterns. The backreference enforces "same binding name" so a real
 * `catch (e) { throw new Wrapped(e); }` does not trip. Reports the stable `waste.useless-catch` finding.
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

/*
 * Empty / comment-only catch bodies. Strips comments before testing, because a catch body with
 * only `// intentional` is still a swallowed catch but a real `console.error` is not. Reports
 * the stable `waste.swallowed-catch` finding.
 */
export function analyseSwallowedCatches(file: SourceFile, rawSource: string, codeSource: string, findings: Finding[]): void {
  for (const match of codeSource.matchAll(/\bcatch\s*(?:\(([^)]*)\))?\s*\{([\s\S]*?)\}/g)) {
    const body = match[2] ?? "";
    const rawBody = rawCatchBody(rawSource, codeSource, match);
    if (!isSwallowedCatchBody(body) || hasIntentionalCatchRationale(rawBody)) {
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
function rawCatchBody(rawSource: string, codeSource: string, match: RegExpMatchArray): string {
  const start = match.index ?? 0;
  const openBrace = codeSource.indexOf("{", start);
  const closeBrace = start + (match[0]?.length ?? 0) - 1;
  return openBrace === -1 || closeBrace <= openBrace ? "" : rawSource.slice(openBrace + 1, closeBrace);
}

// Comment-only catches are acceptable when the comment gives a rationale such as "already closed",
// "cache write failure is non-fatal", or "composition continues"; placeholders still surface.
function hasIntentionalCatchRationale(body: string): boolean {
  return (
    /(?:\/\/|\/\*)/.test(body) &&
    (hasSuppressionRationale(body) ||
      /\b(?:already (?:closed|dead|gone)|optional|best effort|missing|unreadable|not a directory|doesn't exist|not available|non-fatal|cache write failure|composition continues|try next location|server unavailable|must not affect|explicit launch|malformed messages|template missing|sets [A-Za-z_$][A-Za-z0-9_$]* = false|skip agents? that fail)\b/i.test(body))
  );
}

/*
 * `@ts-ignore` / `@ts-expect-error` without an explanatory note. `tsDirectiveWithoutRationale`
 * applies the rationale heuristic. Reports the stable `modernisation.ts-comment-without-rationale`
 * finding.
 */
function pushTsDirectiveFinding(file: SourceFile, line: string, lineNumber: number, findings: Finding[]): void {
  const directive = tsDirectiveWithoutRationale(line);
  if (!directive) {
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
      remediation: "Add a short reason after the directive or remove the suppression.",
      metadata: { directive: directive.directive },
    }),
  );
}

// Walks every `foo.bar!` non-null assertion on the line. The lookahead enforces a real expression
// boundary so `!=` doesn't get misread. Reports `modernisation.non-null-assertion` with stable metadata.
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

// `as unknown as Foo` and `as any as Foo` double-cast patterns. Both source and target types are
// captured in stable metadata so reviewers can see what's being coerced. Reports `modernisation.double-cast`.
function pushDoubleCastFindings(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  for (const match of codeLine.matchAll(/\bas\s+(unknown|any)\s+as\s+([^;,\n]+)/g)) {
    const sourceType = match[1] ?? "";
    const targetType = (match[2] ?? "").trim().replace(/[.)]+$/, "");
    findings.push(
      makeFinding({
        ruleId: "modernisation.double-cast",
        message: `Double cast through \`${sourceType}\` bypasses structural type checks.`,
        filePath: file.displayPath,
        line: lineNumber,
        severity: "warning",
        pillar: "modernisation",
        confidence: "medium",
        remediation: "Prefer a typed parser, type guard, or narrower assertion at the trust boundary.",
        metadata: { sourceType, targetType },
      }),
    );
  }
}

/*
 * `any` in an exported declaration's public surface. Only one finding per line because a single
 * `export` with multiple any-typed fields is one design problem, not many. Reports the stable
 * `waste.exported-any` finding.
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

// `arr.forEach(async …)` is a near-universal anti-pattern: the array iterator does not await the
// returned promise, so errors swallow silently. Reports the stable `security.async-foreach` finding.
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

/*
 * A promise-shaped call started as a bare statement, with no `await`, `return`, `void`, or chain.
 * Such promises lose their reject path - exceptions land in an unhandled-rejection. Reports
 * the stable `security.floating-promise` finding.
 */
function pushFloatingPromiseFinding(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  const floating = floatingPromiseCall(codeLine);
  if (!floating) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "security.floating-promise",
      message: `Promise-like call \`${floating}\` is started without await, return, or void.`,
      filePath: file.displayPath,
      line: lineNumber,
      severity: "warning",
      pillar: "security",
      confidence: "medium",
      symbol: floating,
      remediation: "Await it, return it, or prefix with void when fire-and-forget is intentional.",
      metadata: { callName: floating },
    }),
  );
}

/*
 * `throw "string"` / `throw { …object }` / `throw 42`. JavaScript permits it but the stack trace
 * is missing and the caller can't pattern-match an Error subclass. Reports the stable
 * `security.throw-non-error` finding.
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

// Returns the directive name only when the suffix following a TypeScript suppression directive
// has no meaningful rationale. Heuristic is intentionally lenient - three real words usually means
// the maintainer wrote a reason.
function tsDirectiveWithoutRationale(line: string): { directive: string } | undefined {
  const match = line.match(/@ts-(ignore|expect-error)\b(.*)$/);
  if (!match?.[1]) {
    return undefined;
  }
  const rationale = match[2] ?? "";
  if (hasDirectiveRationale(rationale)) {
    return undefined;
  }
  return { directive: `@ts-${match[1]}` };
}

// Two-way pass: an explicit suppression rationale token (tracking URL / issue ID / owner / date)
// or at least three real English-shaped words. The disjunction keeps maintainers from having to
// remember a specific format.
function hasDirectiveRationale(directiveSuffix: string): boolean {
  const cleaned = directiveSuffix.replace(/^[-:\s]+/, "").trim();
  const words = cleaned.match(/[A-Za-z]{3,}/g) ?? [];
  return hasSuppressionRationale(cleaned) || words.length >= 3;
}

// Two-shot scan: line must have both `export` and `any` before the regex is invoked, because the
// regex is expensive and most lines do not have both.
function exportedAnySymbol(codeLine: string): string | undefined {
  if (!/\bexport\b/.test(codeLine) || !/\bany\b/.test(codeLine)) {
    return undefined;
  }
  const match = codeLine.match(/\bexport\s+(?:async\s+)?(?:function|const|let|var|class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)/);
  return match?.[1];
}

// Two predicates compose: must be a bare statement (not handled), and must be a promise-shaped
// call. Returning undefined keeps the per-line emission stable when either gate fails.
function floatingPromiseCall(codeLine: string): string | undefined {
  const trimmed = codeLine.trim();
  if (isHandledPromiseStatement(trimmed)) {
    return undefined;
  }
  const callName = leadingCallName(trimmed);
  if (!callName) {
    return undefined;
  }
  return isPromiseLikeCall(callName) ? callName : undefined;
}

// Five "this is intentional" forms: await, return, void, throw, yield, or a binding. Any one keeps
// the line out of floating-promise reporting.
function isHandledPromiseStatement(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || /^(?:await|return|void|throw|yield)\b/.test(trimmedLine) || /^(?:const|let|var)\s+/.test(trimmedLine);
}

// Picks the dotted callable name at the start of the line. Empty string for non-call statements
// signals "not a candidate" to the caller without throwing.
function leadingCallName(trimmedLine: string): string {
  const match = trimmedLine.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/);
  return match?.[1] ?? "";
}

// Heuristic: `fetch`, anything ending in `Async`, or anything ending in `Promise`. False positives
// are tolerated because the rule's remediation ("await or void it") is also the universal best practice.
function isPromiseLikeCall(callName: string): boolean {
  const localName = callName.split(".").at(-1) ?? callName;
  return callName === "fetch" || /(?:Async|Promise)$/.test(localName);
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

// Strips both line and block comments before testing for emptiness. A catch body holding only a
// throwaway placeholder comment reads as a deliberate swallow but documents nothing about the
// recovery path - that is still the rule's signal.
function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}
