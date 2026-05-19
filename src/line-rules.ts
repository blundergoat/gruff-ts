// Per-line and per-source line rules: security/modernisation regex passes, type-safety
// (ts-comment, non-null, double-cast, exported-any), reliability (async-forEach, floating-promise,
// non-Error throw, useless/swallowed catches), and the naming-pusher fanout used by both line
// detection and the block-rule parameter pass. Dead-code rules (unused imports, unreachable) are
// invoked by the cli orchestrator before/after this module so the stable per-line emission order
// stays a single contract.
import { hasSuppressionRationale } from "./comment-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { escapeRegex, finding, isCommentedOutCode } from "./findings-helpers.ts";
import { isTestPath } from "./project-rules.ts";
import { codeLineForMatching } from "./source-text.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

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
 * comment-masked variant — checks that must stay stable against literal content operate on it.
 */
interface LineRuleContext {
  file: SourceFile;
  line: string;
  codeLine: string;
  lineNumber: number;
  config: Config;
  findings: Finding[];
  codeChecks: LineRuleCheck[];
  literalChecks: LineRuleCheck[];
  variables: RegExp;
}

/**
 * Tag carried in every naming-rule finding's metadata so consumers can distinguish a flagged
 * declaration, parameter, destructured binding, or interface field without re-parsing the source.
 */
export type NamingSurface = "declaration" | "parameter" | "destructure" | "interface-field";

/*
 * Per-line rule pipeline plus the two multi-line catch detectors. Excludes analyseUnusedImports
 * and analyseUnreachable so the dead-code module can own them; the orchestrator in cli.ts wraps
 * this call with those rules to preserve the stable, deterministic emission order.
 */
export function analyseLineRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  const sourceLines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const sharedContext = {
    file,
    config,
    findings,
    codeChecks: codeLineChecks(),
    literalChecks: literalLineChecks(),
    variables: /\b(?:const|let|for\s*\(\s*const|for\s*\(\s*let)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g,
  };
  sourceLines.forEach((line, index) => {
    analyseLineRuleContext({ ...sharedContext, line, codeLine: codeLines[index] ?? codeLineForMatching(line), lineNumber: index + 1 });
  });

  analyseUselessCatches(file, codeSource, findings);
  analyseSwallowedCatches(file, codeSource, findings);
}

// All per-line checks for a single line in their stable, deterministic emission order. Each helper
// either no-ops (rule skipped or no match) or appends to `findings`.
function analyseLineRuleContext(context: LineRuleContext): void {
  analyseTypeSafetyLine(context.file, context.line, context.codeLine, context.lineNumber, context.findings);
  analyseReliabilityLine(context.file, context.codeLine, context.lineNumber, context.findings);
  pushCommentedOutCodeFinding(context);
  pushBooleanPrefixFinding(context);
  pushHungarianNotationFindings(context);
  pushOptionalChainingFindings(context);
  pushNullishCoalescingFindings(context);
  pushLooseEqualityFinding(context);
  pushStringTimerFinding(context);
  pushProcessExecFinding(context);
  pushPatternCheckFindings(context);
  pushVariableNameFindings(context);
}

// Code-shape rules: those that must match against the masked code (no comment or literal noise).
// Targets the eval / new-Function / Math.random / innerHTML / proto-access family of security/waste signals.
function codeLineChecks(): LineRuleCheck[] {
  return [
    { ruleId: "security.eval-call", pattern: /\beval\s*\(/, message: "eval() executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.new-function", pattern: /\bnew\s+Function\s*\(|(?:^|[=(:,])\s*Function\s*\(/, message: "Function constructor executes dynamic code.", severity: "error", pillar: "security" },
    { ruleId: "security.insecure-random", pattern: /\bMath\.random\s*\(/, message: "Math.random() is not suitable for security-sensitive randomness.", severity: "warning", pillar: "security" },
    { ruleId: "security.inner-html", pattern: /\.innerHTML\s*=|\bdangerouslySetInnerHTML\b/, message: "HTML injection sink can introduce XSS.", severity: "warning", pillar: "security" },
    { ruleId: "security.proto-access", pattern: /\.__proto__\b/, message: "Direct __proto__ access can enable prototype pollution.", severity: "warning", pillar: "security" },
    { ruleId: "security.document-write", pattern: /\bdocument\.write\s*\(/, message: "document.write() can introduce injection risks.", severity: "warning", pillar: "security" },
    { ruleId: "waste.redundant-boolean-cast", pattern: /\b(?:if|while)\s*\(\s*(?:!!\s*[A-Za-z_$][A-Za-z0-9_$.]*|Boolean\s*\()/, message: "Condition contains a redundant boolean cast.", severity: "advisory", pillar: "waste" },
  ];
}

// Rules that need to see the raw line including literals (e.g., `"javascript:"` URL detection,
// `"md5"` weak-crypto match). Global patterns are auto-generated so global-match operations stay
// safe — see `withGlobalPattern`.
function literalLineChecks(): LineRuleCheck[] {
  const checks: LineRuleCheck[] = [
    { ruleId: "security.weak-crypto", pattern: /\b(?:createHash|createHmac)\s*\(\s*["'](?:md5|sha1)["']|\bcreateCipher\s*\(|\b(?:secureProtocol|minVersion|maxVersion)\s*:\s*["'](?:SSLv2_method|SSLv3_method|TLSv1(?:_method)?|TLSv1\.1)["']/i, message: "Weak cryptographic primitive is used.", severity: "warning", pillar: "security" },
    { ruleId: "security.disabled-tls-verification", pattern: /\b(?:process\.env\.)?NODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*["']0["']|\brejectUnauthorized\s*:\s*false\b/i, message: "TLS certificate verification is disabled.", severity: "error", pillar: "security" },
    { ruleId: "security.javascript-url", pattern: /["'`]\s*javascript\s*:(?!\s+URL\b)/i, message: "javascript: URL literal can execute script.", severity: "error", pillar: "security" },
    { ruleId: "security.proto-access", pattern: /\[\s*["']__proto__["']\s*\]/, message: "Direct __proto__ access can enable prototype pollution.", severity: "warning", pillar: "security" },
    { ruleId: "security.sql-concatenation", pattern: /\b(?:query|execute|raw)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*\$\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+)/i, message: "SQL text is composed with runtime string interpolation.", severity: "warning", pillar: "security" },
    { ruleId: "modernisation.date-now-candidate", pattern: /\bnew\s+Date\s*\(\s*\)\s*\.getTime\s*\(\s*\)|\bNumber\s*\(\s*new\s+Date\s*\(\s*\)\s*\)/, message: "Current-time expression can use Date.now().", severity: "advisory", pillar: "modernisation" },
    { ruleId: "modernisation.object-spread-candidate", pattern: /\bObject\.assign\s*\(\s*\{\s*\}\s*,/, message: "Object.assign clone can usually use object spread.", severity: "advisory", pillar: "modernisation" },
    { ruleId: "waste.console-log", pattern: /\bconsole\.(log|debug)\s*\(/, message: "console logging is committed in source.", severity: "advisory", pillar: "waste" },
    { ruleId: "waste.any-type", pattern: /:\s*any\b|as\s+any\b/, message: "any weakens TypeScript's type guarantees.", severity: "warning", pillar: "waste" },
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
 * Targets `// const x = …;`-style commented-out code. The detector is intentionally conservative
 * because clever false positives drown the rule. Reports the stable `waste.commented-out-code` finding.
 */
function pushCommentedOutCodeFinding(context: LineRuleContext): void {
  if (isCommentedOutCode(context.line)) {
    context.findings.push(finding({ ruleId: "waste.commented-out-code", message: "Comment appears to contain disabled source code.", file: context.file, line: context.lineNumber, severity: "advisory", pillar: "waste" }));
  }
}

// Detects typed boolean declarations (or those with a literal true/false initializer) and runs
// the boolean-prefix and negative-boolean checks. Surface is fixed to "declaration".
function pushBooleanPrefixFinding(context: LineRuleContext): void {
  const booleanDeclaration = context.codeLine.match(/\b(?:const|let|var|public|private|protected)\s+([A-Za-z_$][A-Za-z0-9_$]*)\??(?:\s*:\s*boolean|\s*=\s*(?:true|false)\b)/);
  const name = booleanDeclaration?.[1] ?? "";
  if (!name) {
    return;
  }
  pushBooleanPrefixAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
  pushNegativeBooleanAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Negative-framed booleans (disableX, noX, preventX, …) read as double negations at call sites.
 * `negativeBooleanAllowed` is the user-curated exemption list. Reports the stable
 * `naming.negative-boolean` finding.
 */
export function pushNegativeBooleanAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (!/^(?:disable|no|not|prevent|skip|disallow)[A-Z]/.test(name)) {
    return;
  }
  if (config.negativeBooleanAllowed.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.negative-boolean",
      message: `Boolean identifier \`${name}\` is framed as a negation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Invert the framing so callers do not read a double negation.",
      metadata: { identifierName: name, surface },
    }),
  );
}

/*
 * Booleans should announce their boolean-ness with an `is`/`has`/`can`/… prefix. The accepted set
 * lives in `config.booleanPrefixes` so projects can tune it. Reports the stable
 * `naming.boolean-prefix` finding.
 */
export function pushBooleanPrefixAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (hasBooleanPrefix(name, config.booleanPrefixes)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.boolean-prefix",
      message: `Boolean identifier \`${name}\` should use an intent-revealing prefix.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a prefix such as is, has, can, should, or will.",
      metadata: { identifierName: name, surface },
    }),
  );
}

// Walks all `strFoo` / `intBar` / `arrBaz` identifiers on the line. The prefix regex is
// auto-generated from `config.hungarianPrefixes`. Reports `naming.hungarian-notation`.
function pushHungarianNotationFindings(context: LineRuleContext): void {
  const regex = hungarianPrefixRegex(context.config.hungarianPrefixes);
  if (regex === null) {
    return;
  }
  for (const hungarian of context.codeLine.matchAll(regex)) {
    const name = hungarian[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "naming.hungarian-notation",
        message: `Identifier \`${name}\` uses type-style Hungarian notation.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "naming",
        confidence: "medium",
        symbol: name,
        remediation: "Name the domain concept instead of the storage type.",
        metadata: { identifierName: name },
      }),
    );
  }
}

// Detects `foo && foo.bar` patterns where `foo?.bar` would say the same thing. Backreference
// in the regex enforces identical identifiers on both sides. Reports `modernisation.optional-chaining-candidate`.
function pushOptionalChainingFindings(context: LineRuleContext): void {
  for (const optional of context.codeLine.matchAll(/\b([A-Za-z_$][A-Za-z0-9_$]*)\s*&&\s*\1\.[A-Za-z_$][A-Za-z0-9_$]*/g)) {
    const name = optional[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "modernisation.optional-chaining-candidate",
        message: `Guarded property access on \`${name}\` can usually use optional chaining.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Use optional chaining for the guarded property access.",
      }),
    );
  }
}

// Targets `x || defaultValue` patterns where the fallback is a literal — `??` would preserve
// legitimately-falsy values (0, "", false). Reports `modernisation.nullish-coalescing-candidate`.
function pushNullishCoalescingFindings(context: LineRuleContext): void {
  for (const fallback of context.codeLine.matchAll(/=\s*([A-Za-z_$][A-Za-z0-9_$.]*)\s*\|\|\s*(["'`]\s*["'`]|\d+|true|false)/g)) {
    const name = fallback[1] ?? "";
    context.findings.push(
      makeFinding({
        ruleId: "modernisation.nullish-coalescing-candidate",
        message: `Fallback for \`${name}\` can usually use nullish coalescing to preserve falsy values.`,
        filePath: context.file.displayPath,
        line: context.lineNumber,
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Use ?? when only null or undefined should trigger the fallback.",
      }),
    );
  }
}

/*
 * Loose `==` / `!=` against non-null operands. The `looseEqualityOperator` helper excludes intentional
 * `x == null` checks (which legitimately match null and undefined). Reports the stable
 * `modernisation.loose-equality` finding.
 */
function pushLooseEqualityFinding(context: LineRuleContext): void {
  const looseOperator = looseEqualityOperator(context.codeLine);
  if (looseOperator) {
    context.findings.push(finding({ ruleId: "modernisation.loose-equality", message: `Loose equality operator ${looseOperator} may coerce values.`, file: context.file, line: context.lineNumber, severity: "advisory", pillar: "modernisation" }));
  }
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

/*
 * `exec` / `execSync` / `spawn` with potentially user-influenced arguments. The local-harness
 * escape hatch keeps gruff's own test process invocations quiet. Reports the stable
 * `security.process-exec` finding.
 */
function pushProcessExecFinding(context: LineRuleContext): void {
  if (processExecCandidate(context.codeLine) && !isFixedLocalProcessHarness(context.file, context.line, context.codeLine)) {
    context.findings.push(finding({ ruleId: "security.process-exec", message: "Child-process execution is used; validate arguments are not user-controlled.", file: context.file, line: context.lineNumber, severity: "warning", pillar: "security" }));
  }
}

// Runs the descriptor-driven line checks split into code-shape vs literal-aware. Literal checks
// use `rawPatternStartsInCode` to confirm the match starts in real code, not inside a comment.
// Reports each matching rule's stable line-anchored finding.
function pushPatternCheckFindings(context: LineRuleContext): void {
  for (const check of context.codeChecks) {
    if (check.pattern.test(context.codeLine)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: check.severity, pillar: check.pillar }));
    }
  }
  for (const check of context.literalChecks) {
    if (rawPatternStartsInCode(context.line, context.codeLine, check.globalPattern ?? check.pattern)) {
      context.findings.push(finding({ ruleId: check.ruleId, message: check.message, file: context.file, line: context.lineNumber, severity: check.severity, pillar: check.pillar }));
    }
  }
}

// Per-line variable-name pass that runs short/identifier-quality/abbreviation checks on both
// regular `const`/`let` declarations and destructured names. Reports any findings produced.
function pushVariableNameFindings(context: LineRuleContext): void {
  for (const match of context.codeLine.matchAll(context.variables)) {
    const name = match[1] ?? "";
    pushShortVariableFinding(context, name);
    pushIdentifierQualityFinding(context, name);
    pushAbbreviationAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
  }
  for (const name of destructuredLocalNames(context.codeLine)) {
    pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
    pushAbbreviationAt(context.file, context.lineNumber, name, context.config, context.findings, "destructure");
  }
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
// and destructure callers, which use their own surface labels.
function pushShortVariableFinding(context: LineRuleContext, name: string): void {
  pushShortVariableAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Allows the standard `i`, `j`, `k` loop counters and anything on `acceptedAbbreviations`. Reports
 * `naming.short-variable` for any other one or two character name as a stable advisory finding.
 */
export function pushShortVariableAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (name.length > 2 || ["i", "j", "k"].includes(name) || config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.short-variable",
      message: `Variable \`${name}\` is too short to explain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a name that describes the domain role.",
      metadata: { surface },
    }),
  );
}

// Thin wrapper that fills in `"declaration"` for the surface field; parameter and destructure
// callers use their own surface labels via the underlying `pushIdentifierQualityAt`.
function pushIdentifierQualityFinding(context: LineRuleContext, name: string): void {
  pushIdentifierQualityAt(context.file, context.lineNumber, name, context.config, context.findings, "declaration");
}

/*
 * Reports `naming.identifier-quality` when a name resolves to a generic variant via
 * `identifierQualityVariant` (placeholder names from config, or built-in low-info forms like `data`).
 * The stable `variant` metadata lets downstream tools group by category.
 */
export function pushIdentifierQualityAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  const variant = identifierQualityVariant(name, config.placeholderNames);
  if (!variant) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.identifier-quality",
      message: `Identifier \`${name}\` is a ${variant} name that does not explain domain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use an identifier that names the domain role.",
      metadata: { identifierName: name, variant, surface },
    }),
  );
}

/*
 * Reports `naming.abbreviation` when the name is on `abbreviationDenylist` and not on the user's
 * `acceptedAbbreviations` allowlist. `surface` distinguishes parameter / variable / interface-field
 * — same stable rule contract, different metadata, so consumers can filter on origin.
 */
export function pushAbbreviationAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (config.rules.get("naming.abbreviation")?.enabled !== true) {
    return;
  }
  if (config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  if (!config.abbreviationDenylist.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.abbreviation",
      message: `Identifier \`${name}\` uses an opaque abbreviation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use the full domain term or add the abbreviation to allowlists.acceptedAbbreviations.",
      metadata: { identifierName: name, surface },
    }),
  );
}

// True iff the pattern matches somewhere on the raw line *and* the match's start position falls on
// a code character in `codeLine`. Required for literal-rule checks where the raw line is needed to
// see the literal content, but the match must still begin in executable code (not inside a comment).
function rawPatternStartsInCode(rawLine: string, codeLine: string, pattern: RegExp): boolean {
  const globalPattern = pattern;
  let match: RegExpExecArray | null;
  globalPattern.lastIndex = 0;
  while ((match = globalPattern["exec"](rawLine)) !== null) {
    const index = match.index ?? 0;
    if (isNonWhitespaceCharacter(codeLine[index] ?? "")) {
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

// Returns the loose operator (`==` or `!=`) when present and not part of `===`/`!==`/null check.
// Used by the modernisation rule; sufficient context lookback keeps `x == null` quiet.
function looseEqualityOperator(codeLine: string): string | undefined {
  for (const match of codeLine.matchAll(/[=!]=/g)) {
    const index = match.index ?? 0;
    const operator = match[0] ?? "";
    if (!isLooseEqualityCandidate(codeLine, index, operator)) {
      continue;
    }
    return operator;
  }
  return undefined;
}

// Two-pass filter: reject `===`/`!==` (strict equality) and reject `x == null` (intentional double-test).
function isLooseEqualityCandidate(codeLine: string, index: number, operator: string): boolean {
  return !isStrictEqualityOperator(codeLine, index, operator) && !isNullEqualityComparison(codeLine, index, operator);
}

// Looks one char before and after — `===` shows up as `==` plus a trailing `=`. The leading `!` /
// `=` check catches `!==` and `===` from either side.
function isStrictEqualityOperator(codeLine: string, index: number, operator: string): boolean {
  const before = codeLine[index - 1] ?? "";
  const after = codeLine[index + operator.length] ?? "";
  return before === "=" || before === "!" || after === "=";
}

// `x == null` matches both null and undefined and is a documented idiom — exempting it is the
// rule's intentional false-positive escape hatch. 24-character lookback window is large enough to
// span `someObject.field == null` without matching unrelated tokens.
function isNullEqualityComparison(codeLine: string, index: number, operator: string): boolean {
  const left = codeLine.slice(Math.max(0, index - 24), index).trimEnd();
  const right = codeLine.slice(index + operator.length, Math.min(codeLine.length, index + operator.length + 24)).trimStart();
  return /\bnull$/.test(left) || /^null\b/.test(right);
}

// Two cases: a bare `setTimeout("…")` call, or one accessed via window/self/globalThis. Both
// invoke `eval`-equivalent string-to-code semantics in browsers.
function stringTimerCandidate(codeLine: string): boolean {
  return (
    /(?:^|[^.\w$])(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine) ||
    /\b(?:window|self|globalThis)\.(?:setTimeout|setInterval|execScript)\s*\(\s*["'`]/.test(codeLine)
  );
}

// Triggers on any `exec`, `spawn`, or `execFile` call. Conservative on purpose — pairs with
// `isFixedLocalProcessHarness` which carves out the safe local-harness case.
function processExecCandidate(codeLine: string): boolean {
  return /\b(?:exec|spawn|execFile)\s*\(/.test(codeLine);
}

// False-positive escape hatch for gruff's own tests: spawning a literal relative path with an array
// of args (the safe `spawn("./bin", ["…"])` form) inside a test file does not need to be flagged.
function isFixedLocalProcessHarness(file: SourceFile, rawLine: string, codeLine: string): boolean {
  return isTestPath(file.displayPath) && /\b(?:spawn|execFile)\s*\(/.test(codeLine) && /\b(?:spawn|execFile)\s*\(\s*["']\.{1,2}\/[^"']*["']\s*,\s*\[/.test(rawLine);
}

// Four-rule TypeScript safety pass: directive comment, non-null assertion, double cast, exported any.
// Stable, deterministic ordering keeps the per-line findings in a known sequence.
function analyseTypeSafetyLine(file: SourceFile, line: string, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushTsDirectiveFinding(file, line, lineNumber, findings);
  pushNonNullAssertionFindings(file, codeLine, lineNumber, findings);
  pushDoubleCastFindings(file, codeLine, lineNumber, findings);
  pushExportedAnyFinding(file, codeLine, lineNumber, findings);
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
      pillar: "waste",
      confidence: "medium",
      symbol: exportedAny,
      remediation: "Use a named interface, unknown plus validation, or a precise generic type.",
      metadata: { symbolName: exportedAny },
    }),
  );
}

// Three reliability rules per line: async-forEach, floating-promise, non-Error throw. Order is
// the stable contract — reshuffling shifts per-block emission and churns baselines.
function analyseReliabilityLine(file: SourceFile, codeLine: string, lineNumber: number, findings: Finding[]): void {
  pushAsyncForEachFinding(file, codeLine, lineNumber, findings);
  pushFloatingPromiseFinding(file, codeLine, lineNumber, findings);
  pushNonErrorThrowFinding(file, codeLine, lineNumber, findings);
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
 * Such promises lose their reject path — exceptions land in an unhandled-rejection. Reports
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

/*
 * `catch (e) { throw e; }` patterns. The backreference enforces "same binding name" so a real
 * `catch (e) { throw new Wrapped(e); }` does not trip. Reports the stable `waste.useless-catch` finding.
 */
function analyseUselessCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)\s*\{\s*throw\s+\1\s*;?\s*\}/g)) {
    const binding = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "waste.useless-catch",
        message: `catch block only rethrows \`${binding}\` without adding handling.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "waste",
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
function analyseSwallowedCatches(file: SourceFile, source: string, findings: Finding[]): void {
  for (const match of source.matchAll(/\bcatch\s*(?:\(([^)]*)\))?\s*\{([\s\S]*?)\}/g)) {
    const body = match[2] ?? "";
    if (!isSwallowedCatchBody(body)) {
      continue;
    }
    const binding = (match[1] ?? "").trim();
    findings.push(
      makeFinding({
        ruleId: "waste.swallowed-catch",
        message: "catch block swallows an error without rethrowing, returning, or reporting it.",
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "warning",
        pillar: "waste",
        confidence: "medium",
        remediation: "Handle the error explicitly, rethrow it, or document an intentional ignore path.",
        metadata: { ...(binding ? { binding } : {}) },
      }),
    );
  }
}

// Returns the directive name only when the suffix following a TypeScript suppression directive
// has no meaningful rationale. Heuristic is intentionally lenient — three real words usually means
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

// Allow `throw new XxxError(...)` and `throw e` (bare identifier — usually a rethrow), reject literals.
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
// recovery path — that is still the rule's signal.
function isSwallowedCatchBody(body: string): boolean {
  const meaningful = body
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return meaningful === "";
}

// Returns `"generic"` for low-information names from the configured set, `"numbered"` for
// `foo1` / `bar2` style trailing-digit identifiers, or undefined when the name is acceptable.
// The variant string lands in finding metadata so consumers can split the two failure modes.
function identifierQualityVariant(name: string, placeholderNames: Set<string>): string | undefined {
  if (placeholderNames.has(name.toLowerCase())) {
    return "generic";
  }
  if (/^[A-Za-z_$]+[0-9]+$/.test(name)) {
    return "numbered";
  }
  return undefined;
}

const BOOLEAN_PREFIX_REGEX_CACHE = new WeakMap<Set<string>, RegExp | null>();
const HUNGARIAN_PREFIX_REGEX_CACHE = new WeakMap<Set<string>, RegExp | null>();

// Tests the cached prefix regex from `booleanPrefixRegex`. A null regex (empty prefix set) is
// treated as "no rule configured" so the boolean-prefix check fires only when configured.
function hasBooleanPrefix(name: string, prefixes: Set<string>): boolean {
  const regex = booleanPrefixRegex(prefixes);
  return regex !== null && regex.test(name);
}

// Cached per prefix Set via a WeakMap so each rule pass reuses the compiled regex instead of
// rebuilding it for every identifier. The trailing `[A-Z_]` requirement keeps single-letter
// names like `is` from falsely matching the prefix-followed-by-name pattern.
function booleanPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (BOOLEAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return BOOLEAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const escaped = [...prefixes].map(escapeRegex);
  const regex = prefixes.size === 0 ? null : new RegExp(`^(?:${escaped.join("|")})[A-Z_]`);
  BOOLEAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}

// Counterpart to `booleanPrefixRegex` for the `naming.hungarian-notation` rule. Returns a global
// regex (callers iterate matches) anchored to declaration keywords + visibility modifiers, so a
// reference to `IUser` inside a comment is not flagged — the regex is part of the stable contract.
function hungarianPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (HUNGARIAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return HUNGARIAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const escapedPrefixes = [...prefixes].map(escapeRegex);
  const regex = prefixes.size === 0 ? null : new RegExp(`\\b(?:const|let|var|public|private|protected)\\s+((?:${escapedPrefixes.join("|")})[A-Z][A-Za-z0-9_$]*)`, "g");
  HUNGARIAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}
