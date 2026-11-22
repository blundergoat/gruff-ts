// Per-line and per-source line rules: security/modernisation regex passes, type-safety
// (ts-comment, non-null, double-cast, exported-any), reliability (async-forEach,
// non-Error throw, useless/swallowed catches), and the naming-pusher fanout used by both line
// detection and the block-rule parameter pass. Dead-code rules (unused imports, unreachable) are
// invoked by the cli orchestrator before/after this module so the stable per-line emission order
// stays a single contract.
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

// Runs per-line checks using the current line and rule gates in the supplied context.
// Returns nothing and appends matches to the context's findings in stable order so that emission is repeatable.
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

// Code-shape rules: those that must match against the masked code (no comment or literal noise).
// Returns the eval, Function-constructor, innerHTML and document.write security checks.
function codeLineChecks(): LineRuleCheck[] {
  return [
    { ruleId: "security.eval-call", pattern: /\beval\s*\(/, message: "eval() executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.new-function", pattern: /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, message: "Function constructor executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.inner-html", pattern: /\.innerHTML\s*=(?!\s*(?:""|''))|\bdangerouslySetInnerHTML\b/, message: "HTML injection sink can introduce XSS.", severity: "warning", pillar: "security" },
    { ruleId: "security.document-write", pattern: /\bdocument\.write\s*\(/, message: "document.write() can introduce injection risks.", severity: "warning", pillar: "security" },
  ];
}

// Rules that need to see the raw line including literals (e.g., "javascript:" URL detection,
// "md5" weak-crypto match). Global patterns are auto-generated so global-match operations stay
// safe - see withGlobalPattern.
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

// Returns a copy of the supplied line check with a global pattern so that scans can advance past rejected matches.
// Reuses an already-global pattern. Otherwise it adds the g flag to a copy and keeps the original pattern on the check.
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

// Runs context's enabled checks for the current line, skipping exempt eval, innerHTML and literal matches.
// Returns nothing. Appends one stable finding per matched rule to context.findings, using configured severity or the rule default.
// Literal checks reset and advance shared regex state so that scanning can continue past masked or exempt match starts.
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

// Returns a match-index predicate for ruleId using the current line in context, or undefined when the rule has no exemption.
// TLS matches are exempt when the nearest unmatched opening parenthesis within the lookback belongs to a recognized deep-equality assertion.
// JavaScript URL literals next to equality or inequality operators are exempt.
function literalCheckExemption(ruleId: string, context: LineRuleContext): ((index: number) => boolean) | undefined {
  if (ruleId === "security.disabled-tls-verification") {
    return (index: number) => isInsideDeepEqualityAssertion(context.codeLines, context.lineNumber - 1, index);
  }
  if (ruleId === "security.javascript-url") {
    return (index: number) => isComparisonOperandLiteral(context.line, index);
  }
  return undefined;
}

// Returns true when the raw source line has an equality or inequality operator beside the literal that starts at index.
// This lets the URL rule exempt defensive checks such as href === 'javascript:void(0)'.
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

// Returns 1-based lines where every identifier or dot-property eval call has exactly one string or substitution-free template argument.
// syntax supplies the clean parse; undefined or incompatible line separators returns an empty set and preserves text checks.
// A recognized eval call with any other argument shape prevents the line exemption even when a fixed call shares that line.
function fixedEvalCallLines(syntax: TsSourceFile | undefined): Set<number> {
  const fixed = new Set<number>();
  const dynamic = new Set<number>();
  // Keep text fallback when parser line boundaries differ from the LF-based finding locations.
  if (syntax === undefined || /\r(?!\n)|[\u2028\u2029]/.test(syntax.text)) {
    return fixed;
  }
  // Records fixed and dynamic eval calls in the supplied syntax subtree so a literal call cannot hide a dynamic call on the same line.
  // Returns nothing and adds each matching line number to the applicable enclosing set.
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

// Returns whether the current line in context can skip security.inner-html. The line must be in the fixed-assignment set.
// Any occurrence of the text dangerouslySetInnerHTML in the masked line keeps the rule active there.
function isFixedInnerHtmlLine(context: LineRuleContext): boolean {
  return context.fixedInnerHtmlLines.has(context.lineNumber) && !context.codeLine.includes("dangerouslySetInnerHTML");
}

// Returns 1-based lines of fixed innerHTML writes. With clean syntax, every recognized write on the line must use plain equals and a literal.
// A string or substitution-free template qualifies, including a multiline template. Compound writes prevent the line exemption.
// Without syntax, checks sourceLines for one .innerHTML occurrence and a single-line literal because masking would hide the literal text.
function fixedInnerHtmlAssignmentLines(sourceLines: readonly string[], syntax: TsSourceFile | undefined): Set<number> {
  const fixed = new Set<number>();
  if (syntax === undefined) {
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
  // Returns nothing. Visits node and its descendants to add innerHTML assignment lines to the shared fixed or dynamic sets.
  // Compound assignments remain dynamic because they depend on existing markup or an unmodelled operation.
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

// Checks the context's current code line for short or generic variable names in declarations and destructuring.
// A for-of binding skips the short-name check when its body scan counts at most 10 code lines because compact loop names are idiomatic.
// Returns nothing and appends findings to the context's array. Other headers such as for (const k in obj) get the usual checks.
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

/*
 * Counts the line span of a for-of body starting at the opener line index. Brace-less
 * single-statement bodies return 1 because the body is trivially short. When the opener has `{`,
 * brace-balance tracking finds the matching `}` and returns the number of code lines (per `isCodeLine`) from `{` to `}`
 * inclusive. The walker uses the masked codeLines so braces inside string literals are blanked
 * out; this avoids the false "balanced" claim a raw-source walker would make on template strings.
 * A 50-line scan window guards against unterminated scans because malformed input must not stall
 * the whole-file walker; an unbalanced result returns Infinity so a long-but-unclosed for-of
 * still fires the rule rather than getting silently exempted.
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

// Returns the next brace-scan state from the current line and prior state so the caller can measure the loop body.
// lineIndex is zero-based; bodyOpenerLine stays -1 until the first opening brace, and the supplied state is not mutated.
function advanceForOfBraceScan(state: ForOfBraceScanState, line: string, lineIndex: number): ForOfBraceScanState {
  const opens = (line.match(/\{/g) ?? []).length;
  const closes = (line.match(/\}/g) ?? []).length;
  const bodyOpenerLine = opens > 0 && state.bodyOpenerLine === -1 ? lineIndex : state.bodyOpenerLine;
  return { depth: state.depth + opens - closes, bodyOpenerLine };
}

// Returns candidate local names from a shallow scan of const or let object destructuring in codeLine for the naming rules.
// Splits at every comma, including commas inside defaults. Each fragment yields its alias or plain name after any default suffix is stripped.
// Fragments without a name match are skipped. No matches yield an empty array.
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

// Checks declaration name against the short-variable rule using context's file, line and configuration.
// Returns nothing. Appends any stable finding to context.findings with the declaration surface.
// loopBodyLineCount is the for-of body's code-line count; undefined disables its short-body exemption.
function pushShortVariableFinding(context: LineRuleContext, name: string, loopBodyLineCount?: number): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration", loopBodyLineCount);
}

// Checks declaration name for low-information identifiers using context's file, line and configuration.
// Returns nothing. Appends any stable naming.identifier-quality finding to context.findings with the declaration surface.
function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

// Returns true for a rawLine match starting on a codeLine character other than space, tab, CR or LF unless isExemptMatch returns true.
// pattern must be global; scanning resets and mutates its lastIndex. No accepted match returns false.
// Omitting isExemptMatch disables rule-specific exemptions. Rejected empty matches advance the cursor to avoid repeating the same match.
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

// Returns whether character is non-empty and is not a space, tab, carriage return or newline, for masked match-start checks.
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

// Returns whether codeLine matches a call prefix for setTimeout, setInterval or execScript followed by an opening quote or backtick.
// Matches bare calls and calls through window, self or globalThis so browser string-to-code evaluation can be reported.
function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}
