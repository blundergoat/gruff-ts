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

// TypeScript is CommonJS at runtime; the inner-html guard only walks the shared parse (ADR-012).
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

/*
 * Per-line rule pipeline plus the two multi-line catch detectors. Excludes analyseUnusedImports
 * and analyseUnreachable so the dead-code module can own them; the orchestrator in cli.ts wraps
 * this call with those rules to preserve the stable, deterministic emission order.
 * A parse without errors lets inner-html read an assignment's right-hand side; an error-recovered tree is
 * ignored, so that rule keeps its text behavior.
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

// All per-line checks for a single line in their stable, deterministic emission order. Each helper
// either no-ops (rule skipped or no match) or appends to `findings`.
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
// Targets the eval / new-Function / innerHTML / document.write family of security/waste signals.
function codeLineChecks(): LineRuleCheck[] {
  return [
    { ruleId: "security.eval-call", pattern: /\beval\s*\(/, message: "eval() executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.new-function", pattern: /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, message: "Function constructor executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.inner-html", pattern: /\.innerHTML\s*=(?!\s*(?:""|''))|\bdangerouslySetInnerHTML\b/, message: "HTML injection sink can introduce XSS.", severity: "warning", pillar: "security" },
    { ruleId: "security.document-write", pattern: /\bdocument\.write\s*\(/, message: "document.write() can introduce injection risks.", severity: "warning", pillar: "security" },
  ];
}

// Rules that need to see the raw line including literals (e.g., `"javascript:"` URL detection,
// `"md5"` weak-crypto match). Global patterns are auto-generated so global-match operations stay
// safe - see `withGlobalPattern`.
function literalLineChecks(): LineRuleCheck[] {
  const checks: LineRuleCheck[] = [
    { ruleId: "security.weak-crypto", pattern: /\bcreateHash\s*\(\s*["'](?:md5|sha1)["']|\bcreateHmac\s*\(\s*["']md5["']|\bcreateCipher\s*\(|\b(?:secureProtocol|minVersion|maxVersion)\s*:\s*["'](?:SSLv2_method|SSLv3_method|TLSv1(?:_method)?|TLSv1\.1)["']/i, message: "Weak cryptographic primitive is used.", severity: "warning", pillar: "security" },
    { ruleId: "security.disabled-tls-verification", pattern: /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']|\brejectUnauthorized\s*:\s*false\b/i, message: "TLS certificate verification is disabled.", severity: "error", pillar: "security" },
    { ruleId: "security.javascript-url", pattern: /["'`]\s*javascript\s*:(?!\s+URL\b)/i, message: "javascript: URL literal can execute script.", severity: "error", pillar: "security" },
    { ruleId: "security.sql-concatenation", pattern: /\b(?:query|execute|raw|prepare)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, message: "SQL text is composed with runtime string interpolation.", severity: "warning", pillar: "security" },
    { ruleId: "modernisation.date-now-candidate", pattern: /\bnew\s+Date\s*\(\s*\)\s*\.getTime\s*\(\s*\)|\bNumber\s*\(\s*new\s+Date\s*\(\s*\)\s*\)/, message: "Current-time expression can use Date.now().", severity: "advisory", pillar: "modernisation" },
    { ruleId: "modernisation.object-spread-candidate", pattern: /\bObject\.assign\s*\(\s*\{\s*\}\s*,/, message: "Object.assign clone can usually use object spread.", severity: "advisory", pillar: "modernisation" },
    { ruleId: "waste.any-type", pattern: /:\s*any\b|as\s+any\b/, message: "any weakens TypeScript's type guarantees.", severity: "warning", pillar: "maintainability" },
    { ruleId: "modernisation.var-declaration", pattern: /\bvar\s+[A-Za-z_$]/, message: "var declaration should usually be let or const.", severity: "advisory", pillar: "modernisation" },
  ];
  return checks.map(withGlobalPattern);
}

// Returns a new check whose `globalPattern` has the `g` flag, leaving the original `pattern`
// untouched. Required because `pattern.exec` stateful iteration would corrupt callers that share
// a check across multiple files.
function withGlobalPattern(check: LineRuleCheck): LineRuleCheck {
  return {
    ...check,
    globalPattern: check.pattern.flags.includes("g") ? check.pattern : new RegExp(check.pattern.source, `${check.pattern.flags}g`),
  };
}

/*
 * `setTimeout("alert(1)", …)` and friends evaluate the string as code, an `eval`-equivalent.
 * Reports the stable `security.string-timer` finding when a literal string callback is detected.
 */
function pushStringTimerFinding(context: LineRuleContext): void {
  if (stringTimerCandidate(context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.string-timer", message: "Timer callback is provided as a string.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

// Runs the descriptor-driven line checks split into code-shape vs literal-aware. Literal checks use
// `rawPatternStartsInCode` to confirm a match starts in real code, not inside a comment. Each finding's
// severity is resolved through `ruleSeverity`, so a project's per-rule `severity:` override applies.
// Reports each matching rule's stable, line-anchored finding; the descriptor severity is the default.
function pushPatternCheckFindings(context: LineRuleContext): void {
  for (const check of context.codeChecks) {
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

// Rule-specific exemptions for a literal-check match whose surrounding code shows it is not the defect: a TLS option
// inside a deep-equality assertion, and a `javascript:` literal that a comparison only tests against.
function literalCheckExemption(ruleId: string, context: LineRuleContext): ((index: number) => boolean) | undefined {
  if (ruleId === "security.disabled-tls-verification") {
    return (index: number) => isInsideDeepEqualityAssertion(context.codeLines, context.lineNumber - 1, index);
  }
  if (ruleId === "security.javascript-url") {
    return (index: number) => isComparisonOperandLiteral(context.line, index);
  }
  return undefined;
}

// True when the string literal opening at `index` is an operand of `==`, `===`, `!=` or `!==`, as in
// `if (href === 'javascript:void(0)')`: a defensive check reads the literal and never navigates to it.
function isComparisonOperandLiteral(rawLine: string, index: number): boolean {
  if (/[=!]==?\s*$/.test(rawLine.slice(0, index))) {
    return true;
  }
  const quote = rawLine[index] ?? "";
  let position = index + 1;
  // Find the literal's closing quote, stepping over escaped characters.
  while (position < rawLine.length && rawLine[position] !== quote) {
    position += rawLine[position] === "\\" ? 2 : 1;
  }
  return /^\s*[=!]==?(?!=)/.test(rawLine.slice(position + 1));
}

// A line is exempt from `security.inner-html` only when every `.innerHTML =` on it is a fixed literal and it has no
// `dangerouslySetInnerHTML`, which the same descriptor reports.
function isFixedInnerHtmlLine(context: LineRuleContext): boolean {
  return context.fixedInnerHtmlLines.has(context.lineNumber) && !context.codeLine.includes("dangerouslySetInnerHTML");
}

// Lines whose `.innerHTML =` assignments all take a plain string or a template without `${`. A clean parse decides
// on the right-hand node, so a multi-line static template qualifies; an error-recovered parse falls back to a
// single-line test on the raw text, because the masked code line blanks the literal it would need to read.
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
  // Sorts each innerHTML assignment's line into fixed or dynamic. Only a plain `=` can be fixed: `+=` appends to existing
  // markup, and the other compound assignments are not modelled, so they stay reportable.
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

/*
 * True when masked position `column` on line `lineIndex` sits directly inside the argument list of a deep-equality
 * assertion call: `expect(options).to.deep.equal({ rejectUnauthorized: false })` compares an expected value and
 * configures nothing, while `new https.Agent({ rejectUnauthorized: false })` really disables verification. This is a
 * call-context test, not a path gate, so the same assertion outside a test file is exempt too and a real agent inside
 * a test file still reports. Only the innermost unclosed call counts, so an agent built inside an assertion reports.
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

// Per-line variable-name pass that runs short/identifier-quality checks on both
// regular `const`/`let` declarations and destructured names. Reports any findings produced.
// Single-character for-of bindings whose body is ≤ 10 lines are idiomatic (e.g. `for (const f of
// files) { write(f); }`) and skip the short-variable check; longer bodies still flag. The
// exemption is gated on a real `of` token after the binding so C-style `for (let i = 0; …)` and
// `for (const k in obj)` headers stay covered by the rule.
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

// Per-line brace-balance update. Records the first line that introduced a `{` so the caller can
// compute the body span when the balancing `}` lands.
function advanceForOfBraceScan(state: ForOfBraceScanState, line: string, lineIndex: number): ForOfBraceScanState {
  const opens = (line.match(/\{/g) ?? []).length;
  const closes = (line.match(/\}/g) ?? []).length;
  const bodyOpenerLine = opens > 0 && state.bodyOpenerLine === -1 ? lineIndex : state.bodyOpenerLine;
  return { depth: state.depth + opens - closes, bodyOpenerLine };
}

// Walks `const { foo, bar: alias } = ...` patterns. Aliased names (the part after `:`) become the
// local binding; defaults are stripped. Required because the naming rules check the local name only.
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

// Thin wrapper that fills in `"declaration"` for the surface field. Same back-end as parameter
// and destructure callers, which use their own surface labels. `loopBodyLineCount` is forwarded so
// the underlying rule can apply the for-of short-body exemption when the declaration came from a
// `for (const X of …)` head.
function pushShortVariableFinding(context: LineRuleContext, name: string, loopBodyLineCount?: number): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration", loopBodyLineCount);
}

// Thin wrapper that fills in `"declaration"` for the surface field; parameter and destructure
// callers use their own surface labels via the underlying `pushIdentifierQualityAt`.
function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

// True iff the pattern matches somewhere on the raw line *and* the match's start position falls on
// a code character in `codeLine`. Required for literal-rule checks where the raw line is needed to
// see the literal content, but the match must still begin in executable code (not inside a comment).
// `isExemptMatch`, when a rule supplies one, sets aside a code match whose surrounding call says it is not the defect.
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

// Used by `rawPatternStartsInCode` to confirm a position holds executable code rather than the
// space character produced by `maskNonCode`.
function isNonWhitespaceCharacter(character: string): boolean {
  return character !== "" && character !== " " && character !== "\t" && character !== "\r" && character !== "\n";
}

// Two cases: a bare `setTimeout("…")` call, or one accessed via window/self/globalThis. Both
// invoke `eval`-equivalent string-to-code semantics in browsers.
function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}
