// Finds function and test blocks that developers see in Gruff's source findings.

// Block rules cover size, documentation, parameters, returns and assertion presence.
// Finding helpers keep each warning anchored to the declaration the developer can edit.
import { ruleSeverity, threshold } from "./config.ts";
import { hasLeadingCommentBeforeLines } from "./comment-scanner.ts";
import { baseComplexityMetrics, complexityMetrics as measureComplexity, type ComplexityMetrics } from "./complexity-metrics.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { ruleDescriptors } from "./rules.ts";
import { escapeRegex, isGenericName, lineOffset, parameterNames, parameterParts } from "./findings-helpers.ts";
import { bandedFields, GROUP_PARAMETERS, LOWER_BAND_FUNCTION, LOWER_BAND_PARAMETER, SIMPLIFY_PATH, SPLIT_FUNCTION } from "./limit-band.ts";
import { callableMatchPoints, codeLineFlags, measuredOnlyCallablePoints, type CallableMatchPoint, type ParsedScript } from "./parsed-script.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

// Describe one callable that block rules can locate in a developer's scan report.
//
// Raw and masked bodies let each rule inspect the right text without another parse.
// Missing optional fields identify legacy text spans rather than shared syntax nodes.
export interface FunctionBlock {
  name: string;
  params: string;
  // AST parameter count; absent only for legacy regex-derived blocks.
  parameterCount?: number;
  // Shared syntax metric; absent only for legacy regex span probes.
  complexityMetrics?: ComplexityMetrics;
  // AST-known body presence; absent only for legacy regex-derived blocks.
  hasBody?: boolean;
  // Shared callable node for structure checks; legacy text probes leave it absent.
  callableNode?: import("typescript").Node;
  // AST-known `override` modifier; absent for legacy regex-derived blocks, which keep name findings.
  isOverride?: boolean;
  startLine: number;
  // Raw span from the first JSDoc or decorator line to the closing line; it places findings and changed regions.
  lineCount: number;
  // Code lines in that span, with JSDoc, comments, blank lines and decorators free; every length threshold reads this.
  codeLineCount: number;
  body: string;
  codeBody: string;
  isPublic: boolean;
  // True for exported/re-exported module APIs; unlike `isPublic`, class modifiers do not qualify.
  // This selects warning-tier API docs while internal helpers remain advisory.
  isExported: boolean;
  isTest: boolean;
  hasLeadingComment: boolean;
  declarationLine: number;
}

// Carry the lines and export names needed to discover report blocks in one scanned file.
//
// Patterns are shared across files so each block uses the same supported callable forms.
// Re-exported names keep an earlier local declaration on the public-documentation path.
interface FunctionBlockScan {
  lines: string[];
  codeLines: string[];
  // One flag per line, true where the line carries code (`codeLineFlags` in parsed-script.ts).
  isCodeLine: boolean[];
  patterns: RegExp[];
  reExportedNames: ReadonlySet<string>;
}

const FUNCTION_BLOCK_PATTERNS = functionBlockPatterns();

// Test findings carry the catalogue's advice in JSON as well as hook output.
const TEST_QUALITY_ADVICE = new Map(ruleDescriptors()
  .filter((descriptor) => descriptor.pillar === "test-quality")
  .map((descriptor) => [descriptor.ruleId, descriptor.remediation]));

// Track an opened callable body while discovering the span used by scan rules.
//
// Brace depth applies only after an opening brace has been seen.
// An unopened state cannot end a block or absorb its following declaration.
interface FunctionBodyScanState {
  depth: number;
  hasSeenOpen: boolean;
}

// Share one callable's body, settings and complexity result across its scan rules.
//
// Findings must accumulate in the fixed rule order used by report consumers.
// Legacy spans use base complexity when no parsed metric is available.
export interface BlockRuleContext {
  file: SourceFile;
  block: FunctionBlock;
  config: Config;
  findings: Finding[];
  complexityMetrics: ComplexityMetrics;
  // Retained alias used by the generic-parameter naming gate.
  cyclomatic: number;
  functionBody: string;
}

// Carry the rule and callable location needed to construct one scan warning.
//
// The block supplies the line and symbol a developer uses to find the declaration.
// Severity and pillar keep the result in the caller's selected report category.
export interface BlockFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  block: FunctionBlock;
  severity: Severity;
  pillar: Pillar;
}

// Carry a block warning together with the rule's measurements or other metadata.
//
// Use it when consumers need thresholds or measurements alongside the editable source location.
// Measurements travel with the warning; finding identifiers are computed separately.
// Contract: metadata and any remediation reach the finding unchanged, so a band's advice and key stay together.
export interface BlockFindingWithMetadataArgs extends BlockFindingArgs {
  metadata: Record<string, unknown>;
  // The band's advice on a size or complexity finding; other block rules leave it out.
  remediation?: string;
}

// Build a high-confidence warning at the callable's line and symbol, preserving its stable finding anchor.
// Use the metadata variant when the rule needs measurements or medium confidence.
export function blockFinding(args: BlockFindingArgs): Finding {
  const endLine = args.block.startLine + args.block.lineCount - 1;
  const remediation = TEST_QUALITY_ADVICE.get(args.ruleId);
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, endLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name, ...(remediation === undefined ? {} : { remediation }) });
}

// Build a medium-confidence warning with measurements at the callable's stable source anchor.
// Measurements accompany the callable's line and symbol without changing its fingerprint.
export function blockFindingWithMetadata(args: BlockFindingWithMetadataArgs): Finding {
  const remediation = args.remediation ?? TEST_QUALITY_ADVICE.get(args.ruleId);
  return makeFinding({
    ruleId: args.ruleId,
    message: args.message,
    filePath: args.file.displayPath,
    line: args.block.startLine,
    endLine: args.block.startLine + args.block.lineCount - 1,
    severity: args.severity,
    pillar: args.pillar,
    confidence: "medium",
    symbol: args.block.name,
    ...(remediation === undefined ? {} : { remediation }),
    metadata: args.metadata,
  });
}

// Threads one parsed complexity result and body through each block rule.
// Legacy span-only callers receive base complexity because no extra parse is allowed; this preserves the report invariant.
export function blockRuleContext(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): BlockRuleContext {
  // A regex-only caller has no shared syntax node, so it receives the neutral base measurement.
  const sharedComplexityMetrics = block.complexityMetrics ?? baseComplexityMetrics();
  return {
    file,
    block,
    config,
    findings,
    complexityMetrics: sharedComplexityMetrics,
    cyclomatic: sharedComplexityMetrics.cyclomatic,
    functionBody: functionBodyContent(block.codeBody),
  };
}

// Run block rules in the fixed order expected by scan consumers and stable finding identities.
export function analyseBlockRules(context: BlockRuleContext): void {
  analyseBlockMeasures(context);
  pushGenericFunctionFinding(context);
  pushMissingFunctionDocFinding(context);
  pushEmptyFunctionFinding(context);
  pushUnusedParameterFindings(context);
  pushRedundantVariableFindings(context);
  pushUselessReturnFindings(context);
}

// Run the size and complexity rules alone, in the order `analyseBlockRules` runs them. Callables that only these rules
// measure use this entry, so the documentation and naming rules never see them (FAMILY-CONTRACT.md section 12, search
// `four more function forms`).
export function analyseBlockMeasures(context: BlockRuleContext): void {
  pushFunctionLengthFinding(context);
  pushParameterCountFinding(context);
  pushCyclomaticFinding(context);
  pushCognitiveFinding(context);
}

// Reports a size finding when the scanned function exceeds the configured line limit, which defaults to 200.
function pushFunctionLengthFinding(context: BlockRuleContext): void {
  const functionLengthThreshold = threshold(context.config, "size.function-length", 200);
  // Show a size warning only when this function exceeds the user's configured line limit.
  if (context.block.codeLineCount > functionLengthThreshold) {
    const band = bandedFields(context.block.codeLineCount, functionLengthThreshold, ruleSeverity(context.config, "size.function-length", "warning"), LOWER_BAND_FUNCTION, SPLIT_FUNCTION);
    context.findings.push(blockFindingWithMetadata({
      ruleId: "size.function-length",
      message: `Function \`${context.block.name}\` has ${context.block.codeLineCount} lines, above the threshold of ${functionLengthThreshold}.`,
      file: context.file,
      block: context.block,
      severity: band.severity,
      pillar: "size",
      remediation: band.remediation,
      metadata: { lines: context.block.codeLineCount, threshold: functionLengthThreshold, limitBand: band.limitBand },
    }));
  }
}

// Warn when declared inputs exceed the configured limit, using parsed counts when available.
// Legacy text spans use the comma-based fallback; the default limit is seven.
function pushParameterCountFinding(context: BlockRuleContext): void {
  const params = context.block.parameterCount ?? context.block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
  const parameterCountThreshold = threshold(context.config, "size.parameter-count", 7);
  // Show a parameter-count warning when the declared inputs exceed the configured limit.
  if (params > parameterCountThreshold) {
    const band = bandedFields(params, parameterCountThreshold, ruleSeverity(context.config, "size.parameter-count", "warning"), LOWER_BAND_PARAMETER, GROUP_PARAMETERS);
    context.findings.push(blockFindingWithMetadata({
      ruleId: "size.parameter-count",
      message: `Function \`${context.block.name}\` declares ${params} parameters.`,
      file: context.file,
      block: context.block,
      severity: band.severity,
      pillar: "size",
      remediation: band.remediation,
      metadata: { parameters: params, threshold: parameterCountThreshold, limitBand: band.limitBand },
    }));
  }
}

// Default threshold 15.
// Reports the shared syntax-node decision count to CLI and JSON users.
function pushCyclomaticFinding(context: BlockRuleContext): void {
  const cyclomaticThreshold = threshold(context.config, "complexity.cyclomatic", 15);
  // Show the shared decision count when it exceeds the user's complexity limit.
  if (context.cyclomatic > cyclomaticThreshold) {
    const band = bandedFields(context.cyclomatic, cyclomaticThreshold, ruleSeverity(context.config, "complexity.cyclomatic", "warning"), LOWER_BAND_FUNCTION, SIMPLIFY_PATH);
    context.findings.push(blockFindingWithMetadata({
      ruleId: "complexity.cyclomatic",
      message: `Function \`${context.block.name}\` has cyclomatic complexity ${context.cyclomatic}.`,
      file: context.file,
      block: context.block,
      severity: band.severity,
      pillar: "complexity",
      remediation: band.remediation,
      metadata: { complexity: context.cyclomatic, threshold: cyclomaticThreshold, breakdown: context.complexityMetrics.breakdown, limitBand: band.limitBand },
    }));
  }
}

// Default threshold 15.
// Reports decisions plus shared control-flow nesting to CLI and JSON users.
function pushCognitiveFinding(context: BlockRuleContext): void {
  const cognitive = context.complexityMetrics.cognitive;
  const cognitiveThreshold = threshold(context.config, "complexity.cognitive", 15);
  // Show a complexity warning when decisions and nesting exceed the configured limit.
  if (cognitive > cognitiveThreshold) {
    const band = bandedFields(cognitive, cognitiveThreshold, ruleSeverity(context.config, "complexity.cognitive", "warning"), LOWER_BAND_FUNCTION, SIMPLIFY_PATH);
    context.findings.push(blockFindingWithMetadata({
      ruleId: "complexity.cognitive",
      message: `Function \`${context.block.name}\` has cognitive complexity ${cognitive}.`,
      file: context.file,
      block: context.block,
      severity: band.severity,
      pillar: "complexity",
      remediation: band.remediation,
      metadata: { complexity: cognitive, threshold: cognitiveThreshold, breakdown: context.complexityMetrics.breakdown, limitBand: band.limitBand },
    }));
  }
}

// Reports advice on configured generic names; inherited override names retain the base declaration's warning.
function pushGenericFunctionFinding(context: BlockRuleContext): void {
  // A configured generic name needs advice unless the method inherits its name through override.
  if (context.block.isOverride !== true && isGenericName(context.block.name, context.config.bannedGenericNames)) {
    context.findings.push(blockFinding({ ruleId: "naming.generic-function", message: `Function \`${context.block.name}\` is too generic to explain intent.`, file: context.file, block: context.block, severity: "advisory", pillar: "naming" }));
  }
}

// Reports warnings for missing public descriptions and advice for missing internal descriptions.
// Test titles and existing leading comments already explain the callable.
function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  // A test title or an existing leading description already explains this callable, so no missing-doc warning is needed.
  if (context.block.isTest || context.block.hasLeadingComment) {
    return;
  }
  const ruleId = context.block.isExported ? "docs.missing-exported-function-doc" : "docs.missing-internal-function-doc";
  const severity = context.block.isExported ? "warning" : "advisory";
  const audience = context.block.isExported ? "exported" : "internal";
  context.findings.push(blockFinding({ ruleId, message: `${audience === "exported" ? "Exported" : "Internal"} function \`${context.block.name}\` is missing a leading maintainer comment.`, file: context.file, block: context.block, severity, pillar: "documentation" }));
}

// Reports advice about implementations with no executable body; declarations and documented empty test doubles stay quiet.
function pushEmptyFunctionFinding(context: BlockRuleContext): void {
  // Type declarations have no implementation to evaluate for an empty-body warning.
  if (isBodyLessDeclaration(context.block) || isDeclarationFile(context.file)) {
    return;
  }
  // A body with no executable work needs an advisory unless its test-double role is documented.
  if (isEmptyFunctionBody(context.block.codeBody)) {
    // A documented empty test double satisfies the fixture's interface without needing executable work.
    if (isDocumentedEmptyTestDouble(context)) {
      return;
    }
    context.findings.push(blockFinding({ ruleId: "waste.empty-function", message: `Function \`${context.block.name}\` has no executable body.`, file: context.file, block: context.block, severity: "advisory", pillar: "maintainability" }));
  }
}

// Empty test doubles can be required by external interfaces when the body carries a rationale.
function isDocumentedEmptyTestDouble(context: BlockRuleContext): boolean {
  return isTestOrFixturePath(context.file.displayPath) && hasEmptyTestDoubleRationale(context.block.body);
}

// Test and fixture paths are the only places where empty protocol stubs are normal.
function isTestOrFixturePath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|tests?|spec|__fixtures__|fixtures?|testdata)\//.test(path) || /\.(?:test|spec)\.[cm]?[tj]sx?$/.test(path);
}

// Requires an explicit no-op/stub/fake rationale so real empty implementations still surface.
function hasEmptyTestDoubleRationale(source: string): boolean {
  return /(?:\/\/|\/\*)/.test(source) && /\b(?:intentional no-op|test double|stub|fake|interface contract)\b/i.test(source);
}

// `_`-prefixed parameters are exempted (the standard "intentionally unused" convention).
// Reports `waste.unused-parameter` for parameter names that never appear in the callable body.
function pushUnusedParameterFindings(context: BlockRuleContext): void {
  // Signature-only declarations have no parameter use to evaluate.
  if (isBodyLessDeclaration(context.block) || isDeclarationFile(context.file)) {
    return;
  }
  const parameters = parameterNames(context.block.params);
  // Check each declared input for evidence that the implementation uses it.
  for (const parameter of parameters) {
    // Used inputs stay quiet; only an unreferenced parameter contributes this warning.
    if (!isUnusedParameter(context, parameter, parameters)) {
      continue;
    }
    context.findings.push(unusedParameterFinding(context, parameter.name));
  }
}

// Keep signatures out of empty-body and unused-parameter warnings.
// Prefer the shared syntax result; legacy spans inspect their first meaningful line.
function isBodyLessDeclaration(block: FunctionBlock): boolean {
  // The shared parse already knows; the text walk below only covers legacy regex-derived blocks, and it misreads a multi-line signature whose first
  // line stops at the open paren.
  if (block.hasBody !== undefined) {
    return !block.hasBody;
  }
  // Inspect the legacy text span for its first meaningful declaration line.
  for (const rawLine of block.codeBody.split("\n")) {
    const trimmed = rawLine.trim();
    // Blank lines and comments describe the declaration but cannot establish an executable body.
    if (trimmed === "" || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      continue;
    }
    return /\)[^{;]*;\s*$/.test(trimmed);
  }
  return false;
}

// Keep declaration-file signatures out of warnings that require an executable implementation.
function isDeclarationFile(file: SourceFile): boolean {
  return file.displayPath.endsWith(".d.ts");
}

// Check body references, template uses and sibling defaults before warning about an unused input.
// Intentional unused names and constructor properties stay quiet.
function isUnusedParameter(context: BlockRuleContext, parameter: { name: string; isParameterProperty: boolean }, parameters: ReadonlyArray<{ name: string; raw: string }>): boolean {
  // An intentional unused name or constructor property keeps the parameter out of this advisory.
  if (parameter.name.startsWith("_") || parameter.isParameterProperty) {
    return false;
  }
  const reference = new RegExp(`\\b${escapeRegex(parameter.name)}\\b`);
  // A body reference shows the input is used, so the developer receives no unused-parameter warning.
  if (reference.test(context.functionBody)) {
    return false;
  }
  // A sibling's default value may use this input even when the body does not.
  if (parameters.some((sibling) => sibling.name !== parameter.name && reference.test(parameterParts(sibling.raw).initializer))) {
    return false;
  }
  return !new RegExp(`\\$\\{[^}]*\\b${escapeRegex(parameter.name)}\\b[^}]*\\}`).test(context.block.body);
}

// Build an unused-input advisory at the callable's stable declaration anchor so the developer can review the parameter.
function unusedParameterFinding(context: BlockRuleContext, parameterName: string): Finding {
  return makeFinding({
    ruleId: "waste.unused-parameter",
    message: `Parameter \`${parameterName}\` does not appear to be used.`,
    filePath: context.file.displayPath,
    line: context.block.startLine,
    severity: "advisory",
    pillar: "maintainability",
    confidence: "medium",
    symbol: context.block.name,
    remediation: "Remove the parameter or prefix it with _ if it is intentionally unused.",
    metadata: { parameter: parameterName },
  });
}

// Targets `const x = expr; return x;` patterns.
// The detector walks the function source once and reports each variable whose only use is the trailing return as `waste.redundant-variable`.
function pushRedundantVariableFindings(context: BlockRuleContext): void {
  // Each immediate temporary-to-return pattern gets its own editable source location.
  for (const redundant of redundantVariableReturns(context.block.codeBody)) {
    context.findings.push(
      makeFinding({
        ruleId: "waste.redundant-variable",
        message: `Variable \`${redundant.name}\` is returned immediately after assignment.`,
        filePath: context.file.displayPath,
        line: context.block.startLine + redundant.lineOffset,
        severity: "advisory",
        pillar: "maintainability",
        confidence: "medium",
        symbol: redundant.name,
        remediation: "Return the expression directly.",
        metadata: { variable: redundant.name },
      }),
    );
  }
}

// Caller adds the block's start line to the relative offset so the finding anchors at the actual trailing statement.
// Reports `waste.useless-return` when the final statement is a redundant bare exit.
function pushUselessReturnFindings(context: BlockRuleContext): void {
  // Each unnecessary terminal bare return gets a source location the developer can remove.
  for (const lineOffset of terminalBareReturnLines(context.block.codeBody)) {
    context.findings.push(
      makeFinding({
        ruleId: "waste.useless-return",
        message: `Function \`${context.block.name}\` ends with a redundant bare return.`,
        filePath: context.file.displayPath,
        line: context.block.startLine + lineOffset,
        severity: "advisory",
        pillar: "maintainability",
        confidence: "medium",
        symbol: context.block.name,
        remediation: "Remove the final return statement.",
      }),
    );
  }
}

// Strips line and block comments before measuring - a body containing only documentation is still considered empty for the `waste.empty-function`
// check, since no executable statements run.
function isEmptyFunctionBody(source: string): boolean {
  const body = functionBodyContent(source)
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return body === "";
}

// Extract a brace body or expression-arrow body for downstream scan checks.
// An empty result means no inspectable body was found.
export function functionBodyContent(source: string): string {
  const start = functionBlockBrace(source);
  const end = source.lastIndexOf("}");
  // Without a complete brace body, use the expression-arrow text; no arrow means there is no body to inspect.
  if (start === -1 || end <= start) {
    const arrow = source.indexOf("=>");
    return arrow === -1 ? "" : source.slice(arrow + 2).replace(/;?\s*$/, "");
  }
  return source.slice(start + 1, end);
}

// Find the callable's body opener while skipping template interpolation braces.
// Return -1 for an expression body so block rules use their expression fallback.
function functionBlockBrace(source: string): number {
  // Look for a real body opener so template interpolation cannot shift the warning's block range.
  for (let index = source.indexOf("{"); index !== -1; index = source.indexOf("{", index + 1)) {
    // An interpolation brace does not open the callable body used by block rules.
    if (source[index - 1] !== "$") {
      return index;
    }
  }

  return -1;
}

// Locate an unnecessary final bare return for the useless-return advisory.
// An empty list means the last meaningful line is not a bare return.
function terminalBareReturnLines(source: string): number[] {
  const lines = source.split(/\r?\n/);
  let current = lines.length - 1;
  // Walk backward over the function's closing lines to locate unnecessary returns.
  while (current >= 0) {
    const trimmed = lines[current]?.trim() ?? "";
    // Closing braces and blank lines contain no return statement to report.
    if (trimmed === "" || trimmed === "}") {
      current -= 1;
      continue;
    }
    return /^return\s*;?$/.test(trimmed) && !isOnlyStatementOfCatch(lines, current) ? [current] : [];
  }
  return [];
}

// A bare `return;` that is a catch block's only statement is that catch's handling: removing it would leave an empty catch
// that `waste.swallowed-catch` reports. Comments are already masked to blank lines, so the previous non-blank line is code.
function isOnlyStatementOfCatch(lines: string[], returnIndex: number): boolean {
  for (let current = returnIndex - 1; current >= 0; current -= 1) {
    const trimmed = lines[current]?.trim() ?? "";
    if (trimmed !== "") {
      return /\bcatch\b[^{]*\{$/.test(trimmed);
    }
  }
  return false;
}


// Locate immediate temporary-to-return patterns for the redundant-variable advisory.
// Keep the declared and returned name identical so each finding points to the variable the developer can remove.
function redundantVariableReturns(source: string): Array<{ name: string; lineOffset: number }> {
  const results: Array<{ name: string; lineOffset: number }> = [];
  // Record each matched temporary with its source offset so the advisory points to the declaration.
  for (const match of source.matchAll(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]+;\s*return\s+\1\s*;/g)) {
    results.push({ name: match[1] ?? "", lineOffset: lineOffset(source, match.index ?? 0) });
  }
  return results.filter((result) => result.name !== "");
}

// Matches test/it openers, including a discarded registration result.
// Used by the block parser to pick the right pattern and by setup detection to skip the test wrapper line itself.
function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:void\s+)?(?:test|it)\s*\(/.test(line);
}

// Builds report blocks from the shared syntax tree while preserving anchors and fingerprints.
// Span-only utilities without a parse retain the legacy regex walk.
export function functionBlocks(source: string, codeSource = source, parsed?: ParsedScript): FunctionBlock[] {
  const scan = functionBlockScan(source, codeSource, parsed);
  const matchPoints = matchPointsFor(scan, parsed);
  const ownedCallableNodes = ownedCallables(matchPoints, parsed);
  // Each stable block receives one metric result based on the final one-block-per-line ownership set.
  return matchPoints.map((point) => functionBlockFromPoint(scan, point, ownedCallableNodes));
}

/**
 * Builds blocks for the callable forms only the size and complexity rules measure: object-literal `key: function`
 * methods, functions assigned to a member, `var` function expressions and immediately invoked functions.
 * @param source Raw script text the blocks slice their bodies from.
 * @param codeSource The same text with comments and literals masked.
 * @param parsed Shared parse of the script; these forms are found only on the syntax tree.
 * @returns One block per occurrence of these forms, in source order; empty when the script uses none of them.
 */
export function measuredOnlyFunctionBlocks(source: string, codeSource: string, parsed: ParsedScript): FunctionBlock[] {
  const scan = functionBlockScan(source, codeSource, parsed);
  const ownedCallableNodes = ownedCallables(matchPointsFor(scan, parsed), parsed);
  return measuredOnlyCallablePoints(parsed).map((point) => functionBlockFromPoint(scan, blockMatchPoint(point), ownedCallableNodes));
}

// Reads the lines, code-line flags and re-exported names one script's block builders share.
function functionBlockScan(source: string, codeSource: string, parsed: ParsedScript | undefined): FunctionBlockScan {
  return {
    lines: source.split(/\r?\n/),
    codeLines: codeSource.split(/\r?\n/),
    isCodeLine: codeLineFlags(source, parsed),
    patterns: FUNCTION_BLOCK_PATTERNS,
    reExportedNames: collectReExportedNames(codeSource),
  };
}

// Every AST-backed block owns one callable body, and so does every measure-only callable, so a nested callable's
// decisions count in its own measure and never again in the function around it. Regex-only span probes have no node.
function ownedCallables(matchPoints: BlockMatchPoint[], parsed: ParsedScript | undefined): Set<import("typescript").Node> {
  const ownedCallableNodes = new Set<import("typescript").Node>();
  for (const point of matchPoints) {
    // A missing node means a caller requested the legacy regex discovery path without reparsing.
    if (point.callableNode) {
      ownedCallableNodes.add(point.callableNode);
    }
  }
  for (const point of parsed ? measuredOnlyCallablePoints(parsed) : []) {
    ownedCallableNodes.add(point.callableNode);
  }
  return ownedCallableNodes;
}

// One callable hit used to build the block that report rules inspect.
//
// Parsed hits carry their node and exact range; legacy span probes carry only text coordinates.
// Empty optional fields mean the caller deliberately supplied no shared parse.
interface BlockMatchPoint {
  lineIndex: number;
  // AST-known first line of the declaration; regex points leave it absent and keep the name line.
  declarationLineIndex?: number;
  // AST-known end line; regex points keep the legacy brace walk instead.
  endLineIndex?: number;
  name: string;
  params: string;
  parameterCount?: number;
  // AST-known body presence; regex points leave it absent and fall back to the text heuristic.
  hasBody?: boolean;
  // AST-backed visibility; regex points leave these absent and retain the text fallback.
  isDirectlyExported?: boolean;
  isExplicitlyPublic?: boolean;
  isModuleScoped?: boolean;
  // AST-known `override` modifier; regex points leave it absent, so their names stay reportable.
  isOverride?: boolean;
  callableNode?: import("typescript").Node;
}

// Chooses the discovery mode: AST points from the shared parse, or the legacy regex line walk.
function matchPointsFor(scan: FunctionBlockScan, parsed: ParsedScript | undefined): BlockMatchPoint[] {
  // A normal script scan already owns one ParsedScript and must reuse its callable points here.
  if (parsed) {
    return callableMatchPoints(parsed).map(blockMatchPoint);
  }
  const points: BlockMatchPoint[] = [];
  // Span-only utilities still use the legacy masked-line inventory without triggering a parse.
  scan.codeLines.forEach((line, index) => {
    const match = functionBlockMatch(scan, line, index);
    // Only lines that contain a supported callable shape become legacy block points.
    if (match) {
      points.push({ lineIndex: index, name: match[1] ?? "", params: match[2] ?? "" });
    }
  });
  return points;
}

// Carries one parsed callable point into the block builder's shape.
function blockMatchPoint(point: CallableMatchPoint): BlockMatchPoint {
  return {
    lineIndex: point.lineIndex,
    declarationLineIndex: point.declarationLineIndex,
    endLineIndex: point.endLineIndex,
    name: point.name,
    params: point.params,
    parameterCount: point.parameterCount,
    hasBody: point.hasBody,
    isDirectlyExported: point.isDirectlyExported,
    isExplicitlyPublic: point.isExplicitlyPublic,
    isModuleScoped: point.isModuleScoped,
    isOverride: point.isOverride,
    callableNode: point.callableNode,
  };
}

// Identify local declarations exposed by export lists or bare default exports for the public-doc rule.
// Export-from clauses name another module's API and cannot promote a same-named local declaration.
function collectReExportedNames(codeSource: string): ReadonlySet<string> {
  const names = new Set<string>();
  // Inspect local export lists so public declarations receive the public-documentation rule.
  for (const match of codeSource.matchAll(/export\s*\{([^}]+)\}(?!\s*from\b)/g)) {
    // Each listed local name may promote its declaration to the public API surface.
    for (const entry of (match[1] ?? "").split(",")) {
      const local = entry.trim().split(/\s+as\s+/)[0]?.trim();
      // Only a present identifier can give a local declaration public-API status.
      if (local && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(local)) {
        names.add(local);
      }
    }
  }
  // A bare default export can make an earlier local declaration public.
  for (const match of codeSource.matchAll(/^\s*export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$/gm)) {
    // A missing exported-name capture leaves the public-name set unchanged.
    if (match[1]) {
      names.add(match[1]);
    }
  }
  return names;
}

// Recognize tests, functions, methods and arrow assignments for legacy block discovery.
// Test registrations take precedence; default-export functions remain visible to public-doc checks.
function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:void\s+)?(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

// Choose the first supported callable shape on this line; no match returns undefined and creates no block.
function functionBlockMatch(scan: FunctionBlockScan, line: string, index: number): RegExpMatchArray | undefined {
  const rawLine = scan.lines[index] ?? "";
  // Try the supported callable forms in order so test registrations keep their own block role.
  for (let patternIndex = 0; patternIndex < scan.patterns.length; patternIndex += 1) {
    const pattern = scan.patterns[patternIndex];
    // A missing pattern supplies no callable evidence and cannot create a block.
    if (!pattern) {
      continue;
    }
    const match = functionPatternMatch(pattern, patternIndex, line, rawLine);
    // The first supported match determines the callable shown to block rules.
    if (match) {
      return match;
    }
  }
  return undefined;
}

// Use raw test titles and masked ordinary code to recognize a callable.
// A missing name or control keyword returns undefined rather than creating a report block.
function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  // A missing name or control keyword cannot represent a callable in the scan.
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

// Promotes a discovery point into the shared block used by report rules and context documentation.
// Parsed points receive one syntax metric; legacy span-only points keep that field absent.
function functionBlockFromPoint(scan: FunctionBlockScan, point: BlockMatchPoint, ownedCallableNodes: ReadonlySet<import("typescript").Node>): FunctionBlock {
  const index = point.lineIndex;
  const start = functionStartIndex(scan.lines, index);
  const end = point.endLineIndex ?? functionEndIndex(scan, index);
  const body = scan.lines.slice(start, end + 1).join("\n");
  const codeBody = scan.codeLines.slice(start, end + 1).join("\n");
  // A missing callable node identifies a legacy range probe, where base metrics are chosen later.
  const sharedComplexityMetrics = point.callableNode ? measureComplexity(point.callableNode, ownedCallableNodes) : undefined;
  // Parsed blocks expose metrics to both consumers; absent values stay omitted for exact optionals.
  return {
    name: point.name,
    params: point.params,
    ...(point.parameterCount === undefined ? {} : { parameterCount: point.parameterCount }),
    ...(point.hasBody === undefined ? {} : { hasBody: point.hasBody }),
    ...(point.callableNode === undefined ? {} : { callableNode: point.callableNode }),
    ...(point.isOverride === undefined ? {} : { isOverride: point.isOverride }),
    ...(sharedComplexityMetrics === undefined ? {} : { complexityMetrics: sharedComplexityMetrics }),
    startLine: start + 1,
    lineCount: end - start + 1,
    codeLineCount: scan.isCodeLine.slice(start, end + 1).filter(Boolean).length,
    body,
    codeBody,
    isPublic: point.isExplicitlyPublic ?? /\bexport\b|\bpublic\b/.test(scan.codeLines.slice(start, index + 1).join("\n")),
    isExported: (point.isDirectlyExported ?? /^\s*export\b/.test(scan.codeLines[index] ?? ""))
      || point.isModuleScoped !== false && scan.reExportedNames.has(point.name),
    isTest: isTestInvocationLine(scan.codeLines[index] ?? ""),
    // Look upward from the declaration, not the name: a split-line `export async function` header would otherwise hide the declaration's own docblock
    // behind its modifier line.
    hasLeadingComment: hasLeadingCommentBeforeLines(scan.lines, (point.declarationLineIndex ?? index) + 1),
    declarationLine: index + 1,
  };
}

// Choose the correct expression or brace-body end so block rules inspect only this callable's source.
function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

// Find the end of an opened callable body using masked code so literal braces cannot distort the report range.
function blockFunctionEndIndex(scan: FunctionBlockScan, index: number): number {
  const state: FunctionBodyScanState = { depth: 0, hasSeenOpen: false };
  let end = index;
  // Read code lines until the complete callable body ends.
  for (let current = index; current < scan.lines.length; current += 1) {
    // Count only code braces; missing lines provide no characters to inspect.
    for (const character of scan.codeLines[current] ?? "") {
      applyFunctionBodyCharacter(state, character);
    }
    end = current;
    // Stop once the opened body closes so later functions cannot enter this block's findings.
    if (isFunctionBodyClosed(state)) {
      break;
    }
  }
  return end;
}

// Update body depth for one code character while locating the callable shown in scan findings.
function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  // An opening brace starts or nests the body whose range anchors the developer's warning.
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  // A closing brace moves the scan toward the end of this callable.
  } else if (character === "}") {
    state.depth -= 1;
  }
}

// Finish a block only after its body has opened and its braces have closed.
function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

// Locate a single-expression arrow's end for block discovery.
// Undefined means this line needs the ordinary brace-body walk.
function expressionArrowEndIndex(codeLines: string[], index: number): number | undefined {
  const line = codeLines[index] ?? "";
  const arrowIndex = line.indexOf("=>");
  // A block-bodied or non-arrow line uses the ordinary brace walk instead.
  if (!isExpressionArrowLine(line, arrowIndex)) {
    return undefined;
  }
  // Look ahead for the end of this expression body before building its report block.
  for (let current = index; current < codeLines.length; current += 1) {
    const endIndex = expressionArrowEndStep(codeLines, line, arrowIndex, index, current);
    // A known end gives block rules the exact expression span; undefined means keep looking.
    if (endIndex !== undefined) {
      return endIndex;
    }
  }
  return index;
}

// Distinguish expression arrows from brace bodies so scan rules receive the correct callable span.
function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

// Check one line for the end of an expression-arrow body; undefined means continue looking.
// A blank line ends the previous body rather than joining the next declaration.
function expressionArrowEndStep(codeLines: string[], line: string, arrowIndex: number, start: number, current: number): number | undefined {
  const trimmed = (codeLines[current] ?? "").trim();
  // On the declaration line, only a terminating semicolon completes this expression body.
  if (current === start) {
    return line.slice(arrowIndex + 2).trim().endsWith(";") ? current : undefined;
  }
  // A blank line marks that the walk has passed the expression's body.
  if (trimmed === "") {
    return current - 1;
  }
  return trimmed.endsWith(";") ? current : undefined;
}

// Keep control-flow keywords out of callable discovery so block rules cannot report them as functions.
function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

// Include attached documentation and decorators in the callable's range.
// Trim blank separators so a warning points to this declaration rather than the previous function's empty space.
function functionStartIndex(lines: string[], index: number): number {
  let start = index;
  // Include attached documentation and decorators so the report range follows the full declaration.
  while (start > 0) {
    const previous = lines[start - 1]?.trim() ?? "";
    // A prefix line belongs to this callable's leading context.
    if (isFunctionPrefixLine(previous)) {
      start -= 1;
      continue;
    }
    break;
  }
  // Remove blank separators so the warning starts at this declaration rather than empty space above it.
  while (start < index && (lines[start]?.trim() ?? "") === "") {
    start += 1;
  }
  return start;
}

// Decide whether an attached decorator, docblock or blank line belongs to the callable's leading context.
function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

// Checks a masked test body before Gruff warns that the test makes no assertion.

// TypeORM's `value.should.be.eql(expected)` counts; an ordinary `options.should` property does not.
export function hasAssertion(maskedTestBody: string): boolean {
  // Standard assert calls and named assert helpers show a developer's expected result.
  if (/\bassert(?:\.[A-Za-z]+|[A-Z][A-Za-z0-9_$]*)?\s*\(/.test(maskedTestBody)) {
    return true;
  }
  // A typed expect call can verify a result even when its type arguments precede the call.
  if (/\bexpect(?:\.(?:assertions|hasAssertions)|[A-Z][A-Za-z0-9_$]*)?\s*(?:<[^;]*?>\s*)?\(/.test(maskedTestBody)) {
    return true;
  }
  // A project Check helper can be the test's assertion even without an assert import.
  if (/\b[A-Za-z_$][A-Za-z0-9_$]*Check\s*\(/.test(maskedTestBody)) {
    return true;
  }
  // Promise rejection and resolution matchers also verify an expected result.
  if (/\.(?:rejects|resolves)\b/.test(maskedTestBody) || /\b(?:doesNotReject|rejects)\s*\(/.test(maskedTestBody)) {
    return true;
  }
  // These observed TypeORM matcher calls check values inside returned test callbacks.
  if (/\.\s*should\s*\.\s*be\s*\.\s*(?:eql|equal|greaterThan|instanceOf)\s*\(/.test(maskedTestBody)) {
    return true;
  }
  return false;
}

// Count meaningful test setup before its first assertion for the fixture-purpose documentation check.
export function setupLineCount(source: string): number {
  let count = 0;
  // Count meaningful setup work before the first assertion in the developer's test.
  for (const line of functionBodyContent(source).split(/\r?\n/)) {
    const trimmed = line.trim();
    // Blank lines and closing syntax add no fixture setup work.
    if (isIgnorableSetupLine(trimmed)) {
      continue;
    }
    // The first assertion ends setup, so later test work cannot inflate this fixture-purpose check.
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

// Keep blank lines and closing syntax out of the test-setup count shown to the fixture-purpose rule.
function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}
