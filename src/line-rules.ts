// Runs per-line and multi-line catch checks over each TypeScript or JavaScript source file during analysis.
//
// Evaluates enabled line-level rule families in a fixed order so finding lists stay deterministic across runs:
// - security and modernisation regex passes, type-safety checks, reliability checks, and variable naming;
// - dead-code passes (`analyseUnusedImports`, `analyseUnreachable`) are scheduled separately by `analyser.ts`.
import { createRequire } from "node:module";
import { ruleEnabled, ruleSeverity } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { finding } from "./findings-helpers.ts";
import { pushIdentifierQualityAt, pushShortVariableAt } from "./naming-pushers.ts";
import { codeLineFlags, type ParsedScript } from "./parsed-script.ts";
import { ruleDescriptors } from "./rules.ts";
import { analyseReliabilityLine, analyseSwallowedCatches, analyseTypeSafetyLine, analyseUselessCatches } from "./safety-rules.ts";
import { analyseSecurityFlowLine } from "./security-flow-rules.ts";
import { codeLineForMatching } from "./source-text.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

// TypeScript is CommonJS at runtime; literal guards only walk the shared parse (ADR-012).
const require = createRequire(import.meta.url);
const typescriptSyntax = require("typescript") as typeof import("typescript");

type TsSourceFile = import("typescript").SourceFile;
type TsNode = import("typescript").Node;

// Descriptor for one regex-backed line rule. `pattern` is the cheap test and `globalPattern`
// (optional) is used when the rule needs all matches for emission, not just the first hit.
interface LineRuleCheck {
  ruleId: string;
  pattern: RegExp;
  globalPattern?: RegExp;
  message: string;
  severity: Severity;
  pillar: Pillar;
}

/*
 * Per-line scratch state shared across every line rule in a single pass. `codeLine` is the
 * comment-masked variant - checks that must stay stable against literal content operate on it.
 */
interface LineRuleContext {
  file: SourceFile;
  line: string;
  codeLine: string;
  // Full masked source as one array per line, indexed 0-based. Exposed so per-line rules that need
  // forward look-ahead (for-of body brace-balancing in `pushVariableNameFindings`) can scan beyond
  // the current line without re-splitting the source.
  codeLines: readonly string[];
  // The raw source lines, so a directive's rationale can be read from the comment lines above it.
  sourceLines: readonly string[];
  // One flag per line, true where it carries code; the for-of body span counts only these lines.
  isCodeLine: readonly boolean[];
  lineNumber: number;
  config: Config;
  findings: Finding[];
  // 1-based lines whose only `.innerHTML =` assignments take a plain string or a template without substitutions.
  fixedInnerHtmlLines: ReadonlySet<number>;
  // 1-based lines whose eval calls all take one fixed string or substitution-free template.
  fixedEvalLines: ReadonlySet<number>;
  codeChecks: LineRuleCheck[];
  literalChecks: LineRuleCheck[];
  variables: RegExp;
  gates: LineRuleGates;
}

const CODE_LINE_CHECKS = codeLineChecks();
const LITERAL_LINE_CHECKS = literalLineChecks();
const VARIABLE_DECLARATIONS = /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g;

// Per-file rule-family switches. They avoid re-running helpers when every rule they emit is disabled.
interface LineRuleGates {
  shouldRunTypeSafety: boolean;
  shouldRunReliability: boolean;
  shouldRunStringTimer: boolean;
  shouldRunSecurityFlow: boolean;
  shouldRunVariableNaming: boolean;
  shouldRunUselessCatch: boolean;
  shouldRunSwallowedCatch: boolean;
}

const TYPE_SAFETY_RULE_IDS = [
  "modernisation.double-cast",
  "modernisation.non-null-assertion",
  "modernisation.ts-comment-without-rationale",
  "waste.exported-any",
] as const;

const RELIABILITY_RULE_IDS = [
  "security.async-foreach",
  "security.throw-non-error",
] as const;

const SECURITY_FLOW_LINE_RULE_IDS = [
  "security.dynamic-regexp",
  "security.open-redirect-candidate",
  "security.path-traversal-candidate",
  "security.ssrf-candidate",
] as const;

const VARIABLE_NAMING_RULE_IDS = [
  "naming.identifier-quality",
  "naming.short-variable",
] as const;

/**
 * Run per-line checks and multi-line catch detectors when their rules are enabled.
 * The analyser schedules analyseUnusedImports and analyseUnreachable separately to preserve stable finding order.
 *
 * @param file - Source file used to attribute findings.
 * @param source - Original source text used by literal and catch checks.
 * @param codeSource - Masked source text used for code matching.
 * @param config - Rule switches and tracking tokens for the enabled checks.
 * @param findings - Collector for line and catch findings.
 * @param parsed - Optional syntax tree. Literal guards use text behavior when the parse is absent or has diagnostics.
 * @returns Nothing. Appends findings and resets the shared variable matcher before checking each line.
 */
export function analyseLineRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  const syntax = parsed?.diagnostics.length === 0 ? parsed.sourceFile : undefined;
  const sourceLines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const gates: LineRuleGates = {
    shouldRunTypeSafety: TYPE_SAFETY_RULE_IDS.some((ruleId) => ruleEnabled(config, ruleId)),
    shouldRunReliability: RELIABILITY_RULE_IDS.some((ruleId) => ruleEnabled(config, ruleId)),
    shouldRunStringTimer: ruleEnabled(config, "security.string-timer"),
    shouldRunSecurityFlow: SECURITY_FLOW_LINE_RULE_IDS.some((ruleId) => ruleEnabled(config, ruleId)),
    shouldRunVariableNaming: VARIABLE_NAMING_RULE_IDS.some((ruleId) => ruleEnabled(config, ruleId)),
    shouldRunUselessCatch: ruleEnabled(config, "waste.useless-catch"),
    shouldRunSwallowedCatch: ruleEnabled(config, "waste.swallowed-catch"),
  };
  const context: LineRuleContext = {
    file,
    line: "",
    codeLine: "",
    codeLines,
    sourceLines,
    isCodeLine: gates.shouldRunVariableNaming ? codeLineFlags(source, parsed) : [],
    lineNumber: 0,
    config,
    findings,
    fixedInnerHtmlLines: ruleEnabled(config, "security.inner-html") ? fixedInnerHtmlAssignmentLines(sourceLines, syntax) : new Set(),
    fixedEvalLines: ruleEnabled(config, "security.eval-call") ? fixedEvalCallLines(syntax) : new Set(),
    codeChecks: CODE_LINE_CHECKS.filter((check) => ruleEnabled(config, check.ruleId)),
    literalChecks: LITERAL_LINE_CHECKS.filter((check) => ruleEnabled(config, check.ruleId)),
    variables: VARIABLE_DECLARATIONS,
    gates,
  };
  sourceLines.forEach((line, index) => {
    context.line = line;
    context.codeLine = codeLines[index] ?? codeLineForMatching(line);
    context.lineNumber = index + 1;
    context.variables.lastIndex = 0;
    analyseLineRuleContext(context);
  });

  if (gates.shouldRunUselessCatch) {
    analyseUselessCatches(file, codeSource, findings);
  }
  if (gates.shouldRunSwallowedCatch) {
    analyseSwallowedCatches(file, source, codeSource, findings, config.trackingTokens);
  }
}

/**
 * Runs per-line checks using the current line and rule gates in the supplied context.
 *
 * @param context - Per-line scratch state holding the current line, rule gates, and findings array.
 * @returns Nothing. Appends matches to the context's findings in stable order so that emission is repeatable.
 */
function analyseLineRuleContext(context: LineRuleContext): void {
  if (context.gates.shouldRunTypeSafety) {
    analyseTypeSafetyLine(context.file, context.line, context.codeLine, context.lineNumber, context.findings, context.sourceLines, context.config.trackingTokens);
  }
  if (context.gates.shouldRunReliability) {
    analyseReliabilityLine(context.file, context.codeLine, context.lineNumber, context.findings);
  }
  if (context.gates.shouldRunStringTimer) {
    pushStringTimerFinding(context);
  }
  if (context.gates.shouldRunSecurityFlow) {
    analyseSecurityFlowLine(context.file, context.codeLine, context.lineNumber, context.findings);
  }
  pushPatternCheckFindings(context);
  if (context.gates.shouldRunVariableNaming) {
    pushVariableNameFindings(context);
  }
}

// Each pattern check's advice is its catalogue remediation, carried on the finding so every output shows it.
const PATTERN_CHECK_REMEDIATION = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor.remediation]));

/**
 * Code-shape rules that must match against the masked code without comment or literal noise.
 *
 * @returns The eval, Function-constructor, innerHTML, and document.write security checks.
 */
function codeLineChecks(): LineRuleCheck[] {
  return [
    { ruleId: "security.eval-call", pattern: /\beval\s*\(/, message: "eval() executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.new-function", pattern: /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, message: "Function constructor executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.inner-html", pattern: /\.innerHTML\s*=(?!\s*(?:""|''))|\bdangerouslySetInnerHTML\b/, message: "HTML injection sink can introduce XSS.", severity: "warning", pillar: "security" },
    { ruleId: "security.document-write", pattern: /\bdocument\.write\s*\(/, message: "document.write() can introduce injection risks.", severity: "warning", pillar: "security" },
  ];
}

/**
 * Rules that need to see the raw line including literals, such as "javascript:" URLs and "md5" matches.
 * Global patterns are generated via withGlobalPattern so global-match operations stay safe.
 *
 * @returns Security, maintainability, and modernisation line checks with global patterns attached.
 */
function literalLineChecks(): LineRuleCheck[] {
  const checks: LineRuleCheck[] = [
    { ruleId: "security.weak-crypto", pattern: /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']|\bcreateHmac\s*\(\s*["']md5["']|\bcreateCipher\s*\(|\b(?:secureProtocol|minVersion|maxVersion)\s*:\s*["'](?:SSLv2_method|SSLv3_method|TLSv1(?:_method)?|TLSv1\.1)["']/i, message: "Weak cryptographic primitive is used.", severity: "warning", pillar: "security" },
    { ruleId: "security.disabled-tls-verification", pattern: /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']|\brejectUnauthorized\s*:\s*false\b/i, message: "TLS certificate verification is disabled.", severity: "error", pillar: "security" },
    { ruleId: "security.javascript-url", pattern: /["'`]\s*javascript\s*:(?!\s+URL\b)/i, message: "javascript: URL literal can execute script.", severity: "error", pillar: "security" },
    { ruleId: "security.sql-concatenation", pattern: /\b(?:query|execute|raw|prepare)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, message: "SQL text is composed with runtime string interpolation.", severity: "warning", pillar: "security" },
    { ruleId: "modernisation.date-now-candidate", pattern: /\bnew\s+Date\s*\(\s*\)\s*\.getTime\s*\(\s*\)|\bNumber\s*\(\s*new\s+Date\s*\(\s*\)\s*\)/, message: "Current-time expression can use Date.now().", severity: "advisory", pillar: "modernisation" },
    { ruleId: "waste.any-type", pattern: /:\s*any\b|as\s+any\b/, message: "any weakens TypeScript's type guarantees.", severity: "warning", pillar: "maintainability" },
    { ruleId: "modernisation.var-declaration", pattern: /\bvar\s+[A-Za-z_$]/, message: "var declaration should usually be let or const.", severity: "advisory", pillar: "modernisation" },
  ];
  return checks.map(withGlobalPattern);
}

/**
 * Copies the supplied line check with a global pattern so that scans can advance past rejected matches.
 * Reuses an already-global pattern; otherwise adds the g flag to a copy and keeps the original pattern on the check.
 *
 * @param check - Line rule descriptor whose pattern is copied or reused as a global regular expression.
 * @returns Copy of the check with `globalPattern` populated.
 */
function withGlobalPattern(check: LineRuleCheck): LineRuleCheck {
  return {
    ...check,
    globalPattern: check.pattern.flags.includes("g") ? check.pattern : new RegExp(check.pattern.source, `${check.pattern.flags}g`),
  };
}

/**
 * Flags candidate browser timer calls with string callbacks and execScript calls with string arguments.
 *
 * @param context - supplies the masked line to check, its report location, and the findings array to update
 * @returns - returns nothing. Appends a stable security.string-timer finding when the line matches.
 */
function pushStringTimerFinding(context: LineRuleContext): void {
  if (stringTimerCandidate(context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.string-timer", message: "Timer callback is provided as a string.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

/**
 * Runs enabled code and literal checks for the current line, skipping exempt eval, innerHTML, and literal matches.
 * Literal checks reset and advance shared regex state so that scanning can continue past masked or exempt match starts.
 *
 * @param context - Per-line state providing enabled checks, the raw and masked lines, and the findings target.
 * @returns Nothing. Appends one stable finding per matched rule to `context.findings` using configured or default severity.
 */
function pushPatternCheckFindings(context: LineRuleContext): void {
  for (const check of context.codeChecks) {
    if (check.ruleId === "security.eval-call" && context.fixedEvalLines.has(context.lineNumber)) {
      continue;
    }
    if (check.ruleId === "security.inner-html" && isFixedInnerHtmlLine(context)) {
      continue;
    }
    if (check.pattern.test(context.codeLine)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: ruleSeverity(context.config, check.ruleId, check.severity), pillar: check.pillar, remediation: PATTERN_CHECK_REMEDIATION.get(check.ruleId) }));
    }
  }
  for (const check of context.literalChecks) {
    const isExemptMatch = literalCheckExemption(check.ruleId, context);
    if (rawPatternStartsInCode(context.line, context.codeLine, check.globalPattern ?? check.pattern, isExemptMatch)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: ruleSeverity(context.config, check.ruleId, check.severity), pillar: check.pillar, remediation: PATTERN_CHECK_REMEDIATION.get(check.ruleId) }));
    }
  }
}

/**
 * Selects a match-index exemption predicate for the current line when the rule supports exemptions.
 * TLS matches are exempt inside recognized deep-equality assertions; JavaScript URL literals next to equality operators are exempt.
 *
 * @param ruleId - Rule identifier being evaluated on the current line.
 * @param context - Per-line state supplying masked lines, raw line text, and line number.
 * @returns Predicate testing whether a match at a column index is exempt, or undefined when the rule has no exemption.
 */
function literalCheckExemption(ruleId: string, context: LineRuleContext): ((index: number) => boolean) | undefined {
  // Only inert `rejectUnauthorized: false` config literals inside deep-equality assertions are exempt; live env assignments stay flagged.
  if (ruleId === "security.disabled-tls-verification") {
    return (index: number) => /^rejectUnauthorized\s*:\s*false\b/i.test(context.line.slice(index))
      && isInsideDeepEqualityAssertion(context.codeLines, context.lineNumber - 1, index);
  }
  if (ruleId === "security.javascript-url") {
    return (index: number) => isComparisonOperandLiteral(context.line, index);
  }
  return undefined;
}

/**
 * Checks whether the raw source line has an equality or inequality operator beside the literal starting at index.
 * This lets the URL rule exempt defensive checks such as `href === 'javascript:void(0)'`.
 *
 * @param rawLine - Unmasked source line containing the matched literal.
 * @param index - Zero-based column where the opening quote of the literal starts.
 * @returns True when an equality or inequality operator precedes or follows the literal; otherwise false.
 */
function isComparisonOperandLiteral(rawLine: string, index: number): boolean {
  if (/[=!]==?\s*$/.test(rawLine.slice(0, index))) {
    return true;
  }
  const quote = rawLine[index] ?? "";
  let position = index + 1;
  // Skip escaped quotes so the operator check on the right starts after the whole literal.
  while (position < rawLine.length && rawLine[position] !== quote) {
    position += rawLine[position] === "\\" ? 2 : 1;
  }
  return /^\s*[=!]==?(?!=)/.test(rawLine.slice(position + 1));
}

/**
 * Collects 1-based lines where every identifier or dot-property eval call has one string or substitution-free template argument.
 * A recognized eval call with any other argument shape prevents the line exemption even when a fixed call shares that line.
 *
 * @param syntax - Clean TypeScript syntax tree, or undefined to preserve text-based checks on missing or incompatible parses.
 * @returns 1-based line numbers eligible for eval exemption, or empty when syntax is undefined or uses non-LF line breaks.
 */
function fixedEvalCallLines(syntax: TsSourceFile | undefined): Set<number> {
  const fixed = new Set<number>();
  const dynamic = new Set<number>();
  // Keep text fallback when parser line boundaries differ from the LF-based finding locations.
  if (syntax === undefined || /\r(?!\n)|[\u2028\u2029]/.test(syntax.text)) {
    return fixed;
  }
  /**
   * Records fixed and dynamic eval calls in the supplied syntax subtree so a literal call cannot hide a dynamic call on the same line.
   *
   * @param node - AST node to inspect and traverse recursively.
   * @returns Nothing. Adds each matching line number to the applicable enclosing `fixed` or `dynamic` set.
   */
  const visit = (node: TsNode): void => {
    if (typescriptSyntax.isCallExpression(node)) {
      const callee = node.expression;
      const name = typescriptSyntax.isIdentifier(callee) ? callee
        : typescriptSyntax.isPropertyAccessExpression(callee) ? callee.name : undefined;
      if (name?.text === "eval") {
        const line = syntax.getLineAndCharacterOfPosition(name.getStart(syntax)).line + 1;
        const argument = node.arguments[0];
        const isFixed = node.arguments.length === 1 && argument !== undefined
          && (typescriptSyntax.isStringLiteral(argument) || typescriptSyntax.isNoSubstitutionTemplateLiteral(argument));
        (isFixed ? fixed : dynamic).add(line);
      }
    }
    node.forEachChild(visit);
  };
  syntax.forEachChild(visit);
  return new Set([...fixed].filter((line) => !dynamic.has(line)));
}

/**
 * Determines whether the current line in context can skip security.inner-html.
 * The line must be in the fixed-assignment set, and any `dangerouslySetInnerHTML` in the masked line keeps the rule active.
 *
 * @param context - Per-line state supplying the line number, masked code line, and precomputed fixed innerHTML lines.
 * @returns True when the line is in `fixedInnerHtmlLines` and does not mention `dangerouslySetInnerHTML`.
 */
function isFixedInnerHtmlLine(context: LineRuleContext): boolean {
  return context.fixedInnerHtmlLines.has(context.lineNumber) && !context.codeLine.includes("dangerouslySetInnerHTML");
}

/**
 * Finds 1-based lines of fixed innerHTML writes using plain equals and a string or substitution-free template literal.
 * Compound writes prevent the exemption; without syntax, falls back to sourceLines because masking would hide the literal text.
 *
 * @param sourceLines - Raw source lines inspected when no clean syntax tree is available.
 * @param syntax - Clean TypeScript syntax tree, or undefined when falling back to single-line literal matching.
 * @returns 1-based line numbers whose only recognized innerHTML writes assign fixed literals.
 */
function fixedInnerHtmlAssignmentLines(sourceLines: readonly string[], syntax: TsSourceFile | undefined): Set<number> {
  const fixed = new Set<number>();
  // Keep text fallback when no clean parse exists or parser line boundaries differ from LF-split finding locations.
  if (syntax === undefined || /\r(?!\n)|[\u2028\u2029]/.test(syntax.text)) {
    sourceLines.forEach((line, index) => {
      if (/^[^]*?\.innerHTML\s*=\s*(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\$]|\\.|\$(?!\{))*`)\s*;?\s*(?:\/\/.*)?$/.test(line)
        && line.split(".innerHTML").length === 2) {
        fixed.add(index + 1);
      }
    });
    return fixed;
  }
  const dynamic = new Set<number>();
  const { EqualsToken, FirstCompoundAssignment, LastCompoundAssignment } = typescriptSyntax.SyntaxKind;
  /**
   * Visits a syntax node and its descendants to record innerHTML assignment lines in the shared fixed or dynamic sets.
   * Compound assignments remain dynamic because they depend on existing markup or an unmodelled operation.
   *
   * @param node - AST node to inspect and traverse recursively.
   * @returns Nothing. Adds each innerHTML assignment line number to `fixed` or `dynamic`.
   */
  const visit = (node: TsNode): void => {
    const operator = typescriptSyntax.isBinaryExpression(node) ? node.operatorToken.kind : undefined;
    const isAssignment = operator === EqualsToken
      || (operator !== undefined && operator >= FirstCompoundAssignment && operator <= LastCompoundAssignment);
    if (isAssignment && typescriptSyntax.isBinaryExpression(node)
      && typescriptSyntax.isPropertyAccessExpression(node.left) && node.left.name.text === "innerHTML") {
      const line = syntax.getLineAndCharacterOfPosition(node.left.name.getStart(syntax)).line + 1;
      const isFixed = operator === EqualsToken
        && (typescriptSyntax.isStringLiteral(node.right) || typescriptSyntax.isNoSubstitutionTemplateLiteral(node.right));
      (isFixed ? fixed : dynamic).add(line);
    }
    node.forEachChild(visit);
  };
  syntax.forEachChild(visit);
  return new Set([...fixed].filter((line) => !dynamic.has(line)));
}

// Deep-equality assertions whose arguments are expected values: chai's `.to.deep.equal`, jest and vitest's `toEqual`,
// and node's `assert.deepStrictEqual`. The named set is deliberately closed; any other call stays reportable.
const DEEP_EQUALITY_ASSERTION_CALLEE = /(?:\.to\.deep\.equal|\.toEqual|\bassert\.deepStrictEqual)\s*$/;
// How far back the enclosing-call search walks. An expected object literal longer than this is reported, not guessed.
const ENCLOSING_CALL_SEARCH_LINES = 200;

/**
 * Check call context for expected values because rejectUnauthorized: false in an assertion configures nothing.
 * The check applies in any file, and a real agent call nested inside an assertion remains reportable.
 *
 * @param codeLines - Masked source lines searched backward for the enclosing call.
 * @param lineIndex - Zero-based line containing the value under review.
 * @param column - Zero-based position where the backward search begins on that line.
 * @returns True if the first unmatched opening parenthesis in the search window belongs to a recognized assertion, otherwise false.
 */
function isInsideDeepEqualityAssertion(codeLines: readonly string[], lineIndex: number, column: number): boolean {
  let unclosedCalls = 0;
  const firstLine = Math.max(0, lineIndex - ENCLOSING_CALL_SEARCH_LINES);
  for (let index = lineIndex; index >= firstLine; index -= 1) {
    const codeLine = codeLines[index] ?? "";
    for (let position = (index === lineIndex ? column : codeLine.length) - 1; position >= 0; position -= 1) {
      if (codeLine[position] === ")") {
        unclosedCalls += 1;
      } else if (codeLine[position] === "(") {
        if (unclosedCalls === 0) {
          const calleeText = codeLine.slice(0, position).trim() === "" ? (codeLines[index - 1] ?? "") : codeLine.slice(0, position);
          return DEEP_EQUALITY_ASSERTION_CALLEE.test(calleeText);
        }
        unclosedCalls -= 1;
      }
    }
  }
  return false;
}

/**
 * Checks the current code line for short or generic variable names in declarations and destructuring.
 * A for-of binding skips the short-name check when its body scan counts at most 10 code lines because compact loop names are idiomatic.
 *
 * @param context - Per-line state holding the current masked line, line array, code-line flags, and findings array.
 * @returns Nothing. Appends variable naming findings to `context.findings`.
 */
function pushVariableNameFindings(context: LineRuleContext): void {
  for (const match of context.codeLine.matchAll(context.variables)) {
    const name = match[1] ?? "";
    const matchText = match[0] ?? "";
    const headerTail = context.codeLine.slice((match.index ?? 0) + matchText.length);
    const isForOfHeader = matchText.startsWith("for") && /^\s+of\b/.test(headerTail);
    const loopBodyLineCount = isForOfHeader ? forOfBodyLineSpan(context.codeLines, context.isCodeLine, context.lineNumber - 1) : undefined;
    pushShortVariableFinding(context, name, loopBodyLineCount);
    pushIdentifierQualityFinding(context, name);
  }
  for (const name of destructuredLocalNames(context.codeLine)) {
    pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
  }
}

/**
 * Counts the code-line span of a for-of body starting at the opener line using masked lines so string braces are ignored.
 * Capped at a 50-line scan window because malformed input must not stall the walker and avoid false exemptions on unclosed loops.
 *
 * @param codeLines - Comment-and-literal-masked source lines scanned for brace balance.
 * @param isCodeLine - Per-line flags counting only non-empty code lines inside the brace span.
 * @param openerLineIndex - Zero-based index of the line containing the for-of header.
 * @returns 1 for brace-less single statements, the inclusive code-line count from `{` to `}`, or Infinity if unclosed within 50 lines.
 */
function forOfBodyLineSpan(codeLines: readonly string[], isCodeLine: readonly boolean[], openerLineIndex: number): number {
  const maxLines = 50;
  const end = Math.min(codeLines.length, openerLineIndex + maxLines);
  let state: ForOfBraceScanState = { depth: 0, bodyOpenerLine: -1 };
  for (let i = openerLineIndex; i < end; i += 1) {
    state = advanceForOfBraceScan(state, codeLines[i] ?? "", i);
    if (state.bodyOpenerLine !== -1 && state.depth <= 0) {
      return isCodeLine.slice(state.bodyOpenerLine, i + 1).filter(Boolean).length;
    }
  }
  return state.bodyOpenerLine === -1 ? 1 : Infinity;
}

// Working state for the per-line brace scan. Returning a fresh value each line keeps the outer
// loop's npath low and the transition rules explicit.
interface ForOfBraceScanState {
  depth: number;
  bodyOpenerLine: number;
}

/**
 * Computes the next brace-scan state from the current line and prior state so the caller can measure the loop body.
 * Does not mutate the supplied state; `bodyOpenerLine` stays -1 until the first opening brace is seen.
 *
 * @param state - Prior brace-nesting depth and opener line index.
 * @param line - Masked source line scanned for opening and closing braces.
 * @param lineIndex - Zero-based index of the current line.
 * @returns Fresh brace-scan state with updated depth and opener line index.
 */
function advanceForOfBraceScan(state: ForOfBraceScanState, line: string, lineIndex: number): ForOfBraceScanState {
  const opens = (line.match(/\{/g) ?? []).length;
  const closes = (line.match(/\}/g) ?? []).length;
  const bodyOpenerLine = opens > 0 && state.bodyOpenerLine === -1 ? lineIndex : state.bodyOpenerLine;
  return { depth: state.depth + opens - closes, bodyOpenerLine };
}

/**
 * Extracts candidate local names from a shallow scan of const or let object destructuring for naming rules.
 * Splits at every comma, strips any default suffix, and yields the alias or plain identifier for each matching fragment.
 *
 * @param codeLine - Masked source line inspected for object destructuring bindings.
 * @returns Candidate bound local identifier names, or empty when no bindings match.
 */
function destructuredLocalNames(codeLine: string): string[] {
  const names: string[] = [];
  for (const block of codeLine.matchAll(/\b(?:const|let)\s+\{([^}]+)\}\s*=/g)) {
    const inner = block[1] ?? "";
    for (const part of inner.split(",")) {
      const trimmed = part.trim().replace(/\s*=[^,]*$/, "");
      const aliased = trimmed.match(/[A-Za-z_$][A-Za-z0-9_$]*\s*:\s*([A-Za-z_$][A-Za-z0-9_$]*)/);
      const plain = trimmed.match(/^([A-Za-z_$][A-Za-z0-9_$]*)$/);
      const name = aliased?.[1] ?? plain?.[1];
      if (name) {
        names.push(name);
      }
    }
  }
  return names;
}

/**
 * Checks a declared identifier against the short-variable rule using the current context's file, line, and configuration.
 *
 * @param context - Per-line state supplying file metadata, line number, config, and findings array.
 * @param name - Declared variable identifier to evaluate.
 * @param loopBodyLineCount - Optional for-of body code-line count; undefined disables the short-body exemption.
 * @returns Nothing. Appends any stable finding to `context.findings` with the declaration surface.
 */
function pushShortVariableFinding(context: LineRuleContext, name: string, loopBodyLineCount?: number): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration", loopBodyLineCount);
}

/**
 * Checks a declared identifier for low-information names using the current context's file, line, and configuration.
 *
 * @param context - Per-line state supplying file metadata, line number, config, and findings array.
 * @param name - Declared variable identifier to evaluate.
 * @returns Nothing. Appends any stable `naming.identifier-quality` finding to `context.findings` with the declaration surface.
 */
function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/**
 * Tests whether a global pattern matches rawLine at a non-whitespace character in codeLine unless exempted.
 * Resets and mutates `pattern.lastIndex`, and advances past rejected empty matches to avoid repeating the same match.
 *
 * @param rawLine - Unmasked source line searched for pattern matches.
 * @param codeLine - Masked source line used to verify the match start is not blanked out.
 * @param pattern - Regular expression that must have the global flag for stateful scanning.
 * @param isExemptMatch - Optional predicate taking match index to exempt rule-specific hits; omitting it disables exemptions.
 * @returns True on the first non-exempt match starting on a non-whitespace `codeLine` character; otherwise false.
 */
function rawPatternStartsInCode(rawLine: string, codeLine: string, pattern: RegExp, isExemptMatch?: (index: number) => boolean): boolean {
  const globalPattern = pattern;
  let match: RegExpExecArray | null;
  globalPattern.lastIndex = 0;
  while ((match = globalPattern["exec"](rawLine)) !== null) {
    const index = match.index ?? 0;
    if (isNonWhitespaceCharacter(codeLine[index] ?? "") && !isExemptMatch?.(index)) {
      return true;
    }
    if (match[0] === "") {
      globalPattern.lastIndex += 1;
    }
  }
  return false;
}

/**
 * Checks whether a single character is non-empty and not a space, tab, carriage return, or newline for masked match-start checks.
 *
 * @param character - Single character or empty value from the masked code line at a match start.
 * @returns True when `character` is non-empty and not space, tab, CR, or LF; otherwise false.
 */
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

/**
 * Checks whether codeLine contains a call prefix for setTimeout, setInterval, or execScript followed by an opening quote or backtick.
 * Matches bare calls and calls through window, self, or globalThis so browser string-to-code evaluation can be reported.
 *
 * @param codeLine - Masked source line inspected for string-callback timer or execScript calls.
 * @returns True when a bare or global-object timer or execScript call starts with a quote or backtick; otherwise false.
 */
function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}
