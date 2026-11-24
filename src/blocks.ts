// Finds function and test blocks that developers see in Gruff's source findings.

// Block rules cover size, documentation, parameters, returns and assertion presence.
// Finding helpers keep each warning anchored to the declaration the developer can edit.
import { optionBoolean, ruleSeverity, threshold } from "./config.ts";
import { hasFunctionLeadingCommentBeforeLines } from "./comment-scanner.ts";
import { baseComplexityMetrics, complexityMetrics as measureComplexity, type ComplexityMetrics } from "./complexity-metrics.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { ruleDescriptors } from "./rules.ts";
import { lineOffset, parameterNames } from "./findings-helpers.ts";
import { bandedFields, GROUP_PARAMETERS, LOWER_BAND_FUNCTION, LOWER_BAND_PARAMETER, SIMPLIFY_PATH, SPLIT_FUNCTION } from "./limit-band.ts";
import { callableMatchPoints, codeLineFlags, isCallableReturningValue, isPublicExportedClassMethod, measuredOnlyCallablePoints, type CallableMatchPoint, type ParsedScript } from "./parsed-script.ts";
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
  // The shared cyclomatic count the cyclomatic finding reports.
  cyclomatic: number;
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

/**
 * Builds a high-confidence finding from the rule details and severity, omitting remediation when the rule has no advice.
 * Use the metadata variant when the rule needs measurements; analysis then replaces the confidence with the rule's catalogue confidence.
 *
 * @param args - Rule details, severity, pillar, file, and block used for the stable source anchor.
 * @returns High-confidence finding anchored to the block span, with test-quality advice attached when available.
 */
export function blockFinding(args: BlockFindingArgs): Finding {
  const endLine = args.block.startLine + args.block.lineCount - 1;
  const remediation = TEST_QUALITY_ADVICE.get(args.ruleId);
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, endLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name, ...(remediation === undefined ? {} : { remediation }) });
}

/**
 * Builds a medium-confidence finding with attached measurements without changing the fingerprint, and analysis then applies catalogue confidence.
 * Uses explicit remediation and falls back to rule advice, omitting remediation when the override is empty or neither source supplies advice.
 *
 * @param args - Rule details, severity, pillar, metadata, optional remediation, file, and block used for the stable source anchor.
 * @returns Medium-confidence finding anchored to the block span with metadata attached and resolved remediation.
 */
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

/**
 * Builds the rule context for a callable, using base complexity for legacy spans to preserve the report invariant without another parse.
 *
 * @param file - Source file descriptor providing display paths for source anchors.
 * @param block - Discovered function or test block providing the span and optional syntax metrics.
 * @param config - Active rule configuration supplying thresholds and severities.
 * @param findings - Shared output collector where rules append emitted findings.
 * @returns Rule context bundling the callable, settings, shared findings collector, and resolved complexity metrics.
 */
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
  };
}

/**
 * Runs size and complexity checks first, then missing-documentation and useless-return checks for one callable.
 *
 * @param context - Shared block rule context supplying the callable, rule settings, measurements, and findings collector.
 * @returns Nothing. Appends matching findings to context.findings.
 */
export function analyseBlockRules(context: BlockRuleContext): void {
  analyseBlockMeasures(context);
  pushMissingFunctionDocFinding(context);
  pushUselessReturnFindings(context);
}

/**
 * Runs size and complexity rules in the stable order used by analyseBlockRules for callables measured only by those rules.
 * See FAMILY-CONTRACT.md section 12 under four more function forms for why documentation and useless-return checks are skipped.
 *
 * @param context - Shared block rule context supplying the block measurements, rule config, and findings collector.
 * @returns Nothing. Appends matching size and complexity findings to context.findings.
 */
export function analyseBlockMeasures(context: BlockRuleContext): void {
  pushFunctionLengthFinding(context);
  pushParameterCountFinding(context);
  pushCyclomaticFinding(context);
}

/**
 * Checks whether a callable's codeLineCount exceeds the configured size.function-length limit, which defaults to 200.
 *
 * @param context - Shared block rule context supplying the callable block, source location, rule settings, and findings collector.
 * @returns Nothing. Appends a banded size finding to context.findings when codeLineCount exceeds the limit.
 */
function pushFunctionLengthFinding(context: BlockRuleContext): void {
  const functionLengthThreshold = threshold(context.config, "size.function-length", 200);
  // Lower-band overruns are advisory. The upper band uses the configured severity.
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

/**
 * Checks whether a callable exceeds the configured parameter-count limit, which defaults to seven.
 * Uses the parsed parameterCount when present; otherwise counts nonempty comma-separated entries in parameter text.
 *
 * @param context - Shared block rule context supplying the callable block, source location, rule settings, and findings collector.
 * @returns Nothing. Appends a banded parameter-count finding to context.findings when the count exceeds the limit.
 */
function pushParameterCountFinding(context: BlockRuleContext): void {
  const params = context.block.parameterCount ?? context.block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
  const parameterCountThreshold = threshold(context.config, "size.parameter-count", 7);
  // The lower band is advisory. The upper band uses the configured severity for the larger overrun.
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

/**
 * Checks whether a callable's shared cyclomatic count exceeds the configured limit, which defaults to 15.
 * Uses context's file, callable, and complexity breakdown to anchor and explain the finding.
 *
 * @param context - Shared block rule context supplying the cyclomatic count, complexity breakdown, settings, and findings collector.
 * @returns Nothing. Appends a banded complexity finding to context.findings when cyclomatic complexity exceeds the limit.
 */
function pushCyclomaticFinding(context: BlockRuleContext): void {
  const cyclomaticThreshold = threshold(context.config, "complexity.cyclomatic", 15);
  // The lower band is advisory. The upper band uses the configured severity for the larger overrun.
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

/**
 * Checks whether a non-test callable lacks a recognized leading comment.
 * Exported APIs receive warnings and internal callables receive advisory findings.
 *
 * @param context - Shared block rule context supplying the callable block, location, rule settings, and findings collector.
 * @returns Nothing. Appends a missing-documentation finding to context.findings when a leading comment is missing.
 */
function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  if (context.block.isTest || context.block.hasLeadingComment) {
    return;
  }
  const isExportedApi = context.block.isExported || isEveryCallablePublicMethod(context);
  const ruleId = isExportedApi ? "docs.missing-exported-function-doc" : "docs.missing-internal-function-doc";
  const severity = isExportedApi ? "warning" : "advisory";
  context.findings.push(blockFinding({ ruleId, message: missingFunctionDocMessage(context.block, isExportedApi ? "Exported" : "Internal"), file: context.file, block: context.block, severity, pillar: "documentation" }));
}

/**
 * Formats a missing-documentation message for a callable, requesting descriptions for non-this parameters, return values, and throws.
 * A throw token in the masked body triggers the failure prompt under the docs.missing-error-behavior-doc criterion.
 *
 * @param block - Callable block supplying name, parameter text, masked body, and optional syntax node.
 * @param audience - Label prefix indicating whether the callable is Exported or Internal.
 * @returns Formatted missing-documentation message prefixed by audience, with no suffix when no prompts apply.
 */
function missingFunctionDocMessage(block: FunctionBlock, audience: "Exported" | "Internal"): string {
  const asks: string[] = [];
  const names = parameterNames(block.params).map((parameter) => parameter.name).filter((name) => name !== "this");
  if (names.length > 0) {
    asks.push(`describe ${names.length > 1 ? "parameters" : "parameter"} ${names.map((name) => `\`${name}\``).join(", ")}`);
  }
  if (block.callableNode !== undefined && isCallableReturningValue(block.callableNode)) {
    asks.push("describe the return value");
  }
  if (/\bthrow\b/.test(block.codeBody)) {
    asks.push("say when it throws");
  }
  const suffix = asks.length > 0 ? `; ${asks.join("; ")}` : "";
  return `${audience} function \`${block.name}\` is missing a leading maintainer comment${suffix}.`;
}

/**
 * Checks whether context enables either everyCallable tag option and its parsed callable is a public method of a directly exported class.
 *
 * @param context - Shared block rule context supplying the rule config and optional parsed callable node.
 * @returns True when enabled and callableNode is a public method of a directly exported class; false if callableNode is absent.
 */
function isEveryCallablePublicMethod(context: BlockRuleContext): boolean {
  return isTagRuleEveryCallable(context.config) && context.block.callableNode !== undefined && isPublicExportedClassMethod(context.block.callableNode);
}

/**
 * Checks whether either tag rule's everyCallable switch is enabled; both are on by default.
 * Setting both false keeps a public method of an exported class in the internal tier.
 *
 * @param config - Active rule configuration containing option overrides for tag rules.
 * @returns True if docs.missing-param-tag or docs.missing-return-tag has everyCallable enabled.
 */
function isTagRuleEveryCallable(config: Config): boolean {
  return optionBoolean(config, "docs.missing-param-tag", "everyCallable", true)
    || optionBoolean(config, "docs.missing-return-tag", "everyCallable", true);
}

/**
 * Detects terminal bare returns in a callable's masked body and anchors each finding using context.block.startLine.
 *
 * @param context - Shared block rule context supplying the callable block, file path, and findings collector.
 * @returns Nothing. Appends waste.useless-return advisories to context.findings for each detected terminal bare return.
 */
function pushUselessReturnFindings(context: BlockRuleContext): void {
  // The line scan skips a return it recognizes as the catch's only handling, so the advice cannot leave that catch empty.
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

/**
 * Extracts a brace body or expression-arrow body from callable source text for downstream scan checks.
 *
 * @param source - Raw or masked callable source text containing a brace block or arrow expression.
 * @returns Body slice between outer braces or after the first arrow, or an empty string when no inspectable body is found.
 */
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

/**
 * Finds the callable's opening brace index while skipping template interpolation braces.
 *
 * @param source - Callable source text to scan for an opening body brace.
 * @returns Zero-based index of the first non-interpolation opening brace, or -1 for an expression body so block rules use fallback.
 */
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

/**
 * Finds a terminal bare return in masked callable source for useless-return findings.
 *
 * @param source - Comment-masked callable body text split by line to inspect trailing statements.
 * @returns One-element array with the zero-based return line index, or empty when absent or when it is the catch block's only statement.
 */
function terminalBareReturnLines(source: string): number[] {
  const lines = source.split(/\r?\n/);
  let current = lines.length - 1;
  while (current >= 0) {
    const trimmed = lines[current]?.trim() ?? "";
    // Closing braces and blank lines can follow the last statement without making it nonterminal.
    if (trimmed === "" || trimmed === "}") {
      current -= 1;
      continue;
    }
    return /^return\s*;?$/.test(trimmed) && !isOnlyStatementOfCatch(lines, current) ? [current] : [];
  }
  return [];
}

/**
 * Guards against waste.useless-return suggesting a removal that would leave a catch empty and eligible for waste.swallowed-catch.
 *
 * @param lines - Comment-masked lines of the callable body.
 * @param returnIndex - Zero-based line index of the candidate bare return statement.
 * @returns True if the first nonblank line before returnIndex opens a catch block; otherwise false.
 */
function isOnlyStatementOfCatch(lines: string[], returnIndex: number): boolean {
  for (let current = returnIndex - 1; current >= 0; current -= 1) {
    const trimmed = lines[current]?.trim() ?? "";
    if (trimmed !== "") {
      return /\bcatch\b[^{]*\{$/.test(trimmed);
    }
  }
  return false;
}

/**
 * Checks whether a line opens a test or it registration, allowing a discarded void registration result.
 * The block parser uses the result to select the test pattern and mark test blocks.
 *
 * @param line - Source or masked line to check for a leading test or it call.
 * @returns True when the line starts with a test or it invocation; otherwise false.
 */
function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:void\s+)?(?:test|it)\s*\(/.test(line);
}

/**
 * Discovers report blocks from source, reusing a shared syntax tree for discovery and metrics when supplied.
 * Without parsed, falls back to legacy regex discovery and omits syntax metrics.
 *
 * @param source - Raw script text used to slice raw bodies and detect leading comments.
 * @param codeSource - Masked script text used for matching and codeBody fields; defaults to source.
 * @param parsed - Optional shared syntax tree for AST-based discovery and complexity metrics.
 * @returns Extracted function and test blocks in discovery order, or an empty array when no supported callable is found.
 */
export function functionBlocks(source: string, codeSource = source, parsed?: ParsedScript): FunctionBlock[] {
  const scan = functionBlockScan(source, codeSource, parsed);
  const matchPoints = matchPointsFor(scan, parsed);
  const ownedCallableNodes = ownedCallables(matchPoints, parsed);
  // Share ownership so enclosing block metrics skip nested callables that have their own blocks.
  return matchPoints.map((point) => functionBlockFromPoint(scan, point, ownedCallableNodes));
}

/**
 * Builds blocks for size and complexity checks on function expressions and arrows.
 * Covers noncomputed object properties such as key: function, member assignments, var bindings and immediate invocation.
 * Baseline matching also uses their declaration spans so that same-named callables can be ranked separately.
 *
 * @param source - Raw script text used to slice each callable body.
 * @param codeSource - Masked script text used to slice the corresponding code body.
 * @param parsed - Shared syntax tree used to locate the covered callable forms.
 * @returns One block per occurrence of these forms, in source order; empty when the script uses none of them.
 */
export function measuredOnlyFunctionBlocks(source: string, codeSource: string, parsed: ParsedScript): FunctionBlock[] {
  const scan = functionBlockScan(source, codeSource, parsed);
  const ownedCallableNodes = ownedCallables(matchPointsFor(scan, parsed), parsed);
  return measuredOnlyCallablePoints(parsed).map((point) => functionBlockFromPoint(scan, blockMatchPoint(point), ownedCallableNodes));
}

/**
 * Prepares the line arrays, code-line flags, regex patterns, and local export names used by block builders.
 * Without parsed, comments and blank lines are excluded from code-line flags, but decorator lines remain countable.
 *
 * @param source - Raw script text split into lines and inspected for code-line flags.
 * @param codeSource - Masked script text split into code lines and scanned for local re-exports.
 * @param parsed - Optional shared syntax tree enabling decorator exclusion in code-line flags.
 * @returns Scan state holding raw lines, masked lines, code-line flags, callable patterns, and re-exported names.
 */
function functionBlockScan(source: string, codeSource: string, parsed: ParsedScript | undefined): FunctionBlockScan {
  return {
    lines: source.split(/\r?\n/),
    codeLines: codeSource.split(/\r?\n/),
    isCodeLine: codeLineFlags(source, parsed),
    patterns: FUNCTION_BLOCK_PATTERNS,
    reExportedNames: collectReExportedNames(codeSource),
  };
}

/**
 * Collects callable syntax nodes owned by discovered blocks so complexity measurement keeps nested decisions out of enclosing counts.
 * Without parsed, only nodes already present in matchPoints are included; points without callableNode contribute nothing.
 *
 * @param matchPoints - Discovered callable match points whose syntax nodes belong to their own report blocks.
 * @param parsed - Optional shared syntax tree used to include measured-only callable nodes.
 * @returns Set of owned callable syntax nodes excluded from enclosing complexity totals.
 */
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

/**
 * Collects callable match points for block construction.
 * Reuses the supplied parse so discovery shares one syntax tree; otherwise derives points from scan lines without creating a parse.
 *
 * @param scan - Precomputed scan lines and ordered regex patterns used for legacy line matching.
 * @param parsed - Optional shared syntax tree that must be reused when supplied.
 * @returns Ordered list of callable match points from the syntax tree or legacy line scan.
 */
function matchPointsFor(scan: FunctionBlockScan, parsed: ParsedScript | undefined): BlockMatchPoint[] {
  if (parsed) {
    return callableMatchPoints(parsed).map(blockMatchPoint);
  }
  const points: BlockMatchPoint[] = [];
  // Span-only utilities still use the legacy masked-line inventory without triggering a parse.
  scan.codeLines.forEach((line, index) => {
    const match = functionBlockMatch(scan, line, index);
    // A legacy hit carries text coordinates, so block construction estimates its end from the source.
    if (match) {
      points.push({ lineIndex: index, name: match[1] ?? "", params: match[2] ?? "" });
    }
  });
  return points;
}

/**
 * Converts a parsed callable match point into block builder input, preserving its declaration metadata and syntax node.
 *
 * @param point - Parsed callable match point emitted by the syntax tree walker.
 * @returns Block match point carrying the same coordinates, visibility flags, parameter data, and syntax node.
 */
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

/**
 * Collects local names from export lists or bare default exports for public-documentation checks.
 * Export-from clauses refer to another module and do not add names to this local set.
 *
 * @param codeSource - Comment-masked module source text to scan for local export lists and default exports.
 * @returns Read-only set of locally declared identifiers re-exported by the module.
 */
function collectReExportedNames(codeSource: string): ReadonlySet<string> {
  const names = new Set<string>();
  for (const match of codeSource.matchAll(/export\s*\{([^}]+)\}(?!\s*from\b)/g)) {
    for (const entry of (match[1] ?? "").split(",")) {
      const local = entry.trim().split(/\s+as\s+/)[0]?.trim();
      if (local && /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(local)) {
        names.add(local);
      }
    }
  }
  // A bare default export can make an earlier local declaration public.
  for (const match of codeSource.matchAll(/^\s*export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$/gm)) {
    if (match[1]) {
      names.add(match[1]);
    }
  }
  return names;
}

/**
 * Builds the ordered regular expressions used by legacy callable discovery.
 * Test registrations take precedence; named default-export functions remain eligible for public-documentation checks.
 *
 * @returns Ordered array of patterns matching tests, function declarations, methods, and arrow bindings.
 */
function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:void\s+)?(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

/**
 * Tests ordered callable patterns against one masked source line to find the first supported declaration or test opener.
 *
 * @param scan - Scan state supplying the ordered callable patterns and raw source lines.
 * @param line - Comment-masked line at the current scan position.
 * @param index - Zero-based line index used to look up the raw line for recovering test titles.
 * @returns First accepted regex match array, or undefined when no pattern matches the line.
 */
function functionBlockMatch(scan: FunctionBlockScan, line: string, index: number): RegExpMatchArray | undefined {
  const rawLine = scan.lines[index] ?? "";
  // Try the supported callable forms in order so test registrations keep their own block role.
  for (let patternIndex = 0; patternIndex < scan.patterns.length; patternIndex += 1) {
    const pattern = scan.patterns[patternIndex];
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

/**
 * Matches one legacy callable pattern against a line while rejecting missing names and control-flow keywords.
 * Position zero uses rawLine for recognized test openers to preserve their string titles.
 *
 * @param pattern - Regular expression for one callable form.
 * @param patternIndex - Zero-based position of pattern in the ordered pattern list.
 * @param line - Comment-masked line used for all non-test patterns and test recognition.
 * @param rawLine - Unmasked line used when patternIndex is zero and line opens a test invocation.
 * @returns Match array with a non-control callable name, or undefined when rejected.
 */
function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  // A missing name or control keyword cannot represent a callable in the scan.
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

/**
 * Builds the block inspected by report rules and context documentation, preserving complexity ownership for parsed points.
 * Legacy span-only points omit syntax complexity metrics.
 *
 * @param scan - Scan state supplying raw lines, masked lines, code-line flags, and local re-export names.
 * @param point - Discovered callable match point giving line bounds, visibility, and optional syntax node.
 * @param ownedCallableNodes - Set of owned callable nodes skipped when measuring nested complexity.
 * @returns Constructed FunctionBlock with source spans, code line counts, visibility flags, and optional metrics.
 */
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
    // behind its modifier line. A divider or the file's overview above it is not its comment.
    hasLeadingComment: hasFunctionLeadingCommentBeforeLines(scan.lines, (point.declarationLineIndex ?? index) + 1),
    declarationLine: index + 1,
  };
}

/**
 * Determines the zero-based end line for a callable starting at index, preferring expression-arrow termination over brace scanning.
 *
 * @param scan - Scan state supplying raw and masked source lines.
 * @param index - Zero-based declaration line index where the callable begins.
 * @returns Zero-based closing line index from expression-arrow termination or the brace scan fallback.
 */
function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

/**
 * Walks brace depth across masked code lines to locate the closing line of a brace-delimited callable.
 *
 * @param scan - Scan state supplying raw lines for length bounds and masked code lines for brace counting.
 * @param index - Zero-based line index where the callable header starts.
 * @returns Zero-based closing line index, or the last visited line (or index if none visited) when an opened body never closes.
 */
function blockFunctionEndIndex(scan: FunctionBlockScan, index: number): number {
  const state: FunctionBodyScanState = { depth: 0, hasSeenOpen: false };
  let end = index;
  for (let current = index; current < scan.lines.length; current += 1) {
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

/**
 * Advances brace-depth tracking for one character from a masked code line.
 *
 * @param state - Mutable brace scan state recording current depth and whether an opening brace was seen.
 * @param character - Single character from the masked code line being scanned.
 * @returns Nothing. Increments or decrements state.depth and marks state.hasSeenOpen on an opening brace.
 */
function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  } else if (character === "}") {
    state.depth -= 1;
  }
}

/**
 * Checks whether the brace scanner has seen an opening brace and returned to zero depth or below.
 *
 * @param state - Current brace scan state for the callable body walk.
 * @returns True when an opening brace was observed and brace depth is zero or less; otherwise false.
 */
function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

/**
 * Estimates the zero-based end line for an expression-bodied arrow function starting at index.
 *
 * @param codeLines - Comment-masked source lines for the file.
 * @param index - Zero-based line index where the arrow declaration begins.
 * @returns Zero-based end line index (defaulting to index if unterminated), or undefined if not an expression arrow.
 */
function expressionArrowEndIndex(codeLines: string[], index: number): number | undefined {
  const line = codeLines[index] ?? "";
  const arrowIndex = line.indexOf("=>");
  // These lines fall through to the caller's brace scan for a span estimate.
  if (!isExpressionArrowLine(line, arrowIndex)) {
    return undefined;
  }
  for (let current = index; current < codeLines.length; current += 1) {
    const endIndex = expressionArrowEndStep(codeLines, line, arrowIndex, index, current);
    // A terminator or following blank line sets the reported end; otherwise keep looking.
    if (endIndex !== undefined) {
      return endIndex;
    }
  }
  return index;
}

/**
 * Distinguishes single-expression arrow headers from brace-bodied functions so scan rules receive the right span.
 *
 * @param line - Comment-masked line containing the callable header.
 * @param arrowIndex - Zero-based character offset of the first arrow token, or -1 if absent.
 * @returns True when an arrow is present and no opening brace follows it on the same line.
 */
function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

/**
 * Evaluates one line in an expression-arrow scan, stopping on a trailing semicolon or a blank continuation line.
 *
 * @param codeLines - Comment-masked source lines for the file.
 * @param line - Masked declaration line text containing the arrow token.
 * @param arrowIndex - Character offset of the arrow token within line.
 * @param start - Zero-based line index of the arrow declaration.
 * @param current - Zero-based line index currently inspected by the forward scan.
 * @returns Estimated end line index (current on semicolon, current - 1 on blank continuation), or undefined when scan must continue.
 */
function expressionArrowEndStep(codeLines: string[], line: string, arrowIndex: number, start: number, current: number): number | undefined {
  const trimmed = (codeLines[current] ?? "").trim();
  // Only the text after the arrow can end the span on the declaration line.
  if (current === start) {
    return line.slice(arrowIndex + 2).trim().endsWith(";") ? current : undefined;
  }
  if (trimmed === "") {
    return current - 1;
  }
  return trimmed.endsWith(";") ? current : undefined;
}

/**
 * Checks whether a candidate identifier is a control-flow keyword excluded by legacy callable discovery.
 *
 * @param name - Identifier matched before an opening parenthesis by a legacy method pattern.
 * @returns True when name is if, for, while, switch, or catch; otherwise false.
 */
function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

/**
 * Finds the zero-based scan start for a declaration, extending upward over attached docblock or decorator prefix lines.
 *
 * @param lines - Raw source lines of the file.
 * @param index - Zero-based line index of the callable declaration header.
 * @returns Zero-based index of the first attached prefix line, or index when no docblock or decorator precedes it.
 */
function functionStartIndex(lines: string[], index: number): number {
  let start = index;
  while (start > 0) {
    const previous = lines[start - 1]?.trim() ?? "";
    if (isFunctionPrefixLine(previous)) {
      start -= 1;
      continue;
    }
    break;
  }
  // Skip leading blanks so the range starts at the first attached prefix line or at the declaration itself.
  while (start < index && (lines[start]?.trim() ?? "") === "") {
    start += 1;
  }
  return start;
}

/**
 * Checks whether a preceding line looks like a decorator, JSDoc line, or blank separator attached to a callable.
 *
 * @param trimmedLine - Trimmed source line preceding the current start position.
 * @returns True when the line is blank or starts with an at-sign, JSDoc opener, or asterisk so the block scan includes it.
 */
function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

// Checks a masked test body before Gruff warns that the test makes no assertion.

/**
 * Checks whether a masked test body contains a recognized assertion-like call or matcher marker for test-quality checks.
 * For should.be chains, only calls to eql, equal, greaterThan, or instanceOf count.
 *
 * @param maskedTestBody - Comment-masked body text of a test block.
 * @returns True if an assert, expect, Check helper, promise matcher, or supported should.be call is found.
 */
export function hasAssertion(maskedTestBody: string): boolean {
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
  // Promise matcher properties count as assertion markers even without a following matcher call.
  if (/\.(?:rejects|resolves)\b/.test(maskedTestBody) || /\b(?:doesNotReject|rejects)\s*\(/.test(maskedTestBody)) {
    return true;
  }
  if (/\.\s*should\s*\.\s*be\s*\.\s*(?:eql|equal|greaterThan|instanceOf)\s*\(/.test(maskedTestBody)) {
    return true;
  }
  return false;
}

/**
 * Counts eligible setup lines in a masked test body up to the first assertion marker, or all eligible lines when no marker exists.
 * Excludes blank lines and lines containing only } or });; an uninspectable body counts as zero.
 *
 * @param source - Comment-masked test block source text.
 * @returns Number of fixture-purpose setup lines before the first recognized assertion marker.
 */
export function setupLineCount(source: string): number {
  let count = 0;
  for (const line of functionBodyContent(source).split(/\r?\n/)) {
    const trimmed = line.trim();
    // Standalone block and callback closers add no setup work in the two recognized forms.
    if (isIgnorableSetupLine(trimmed)) {
      continue;
    }
    // The first recognized assertion marker ends this count, so later test work cannot inflate it.
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

/**
 * Checks whether a trimmed line is empty or a standalone closer, excluding it from the test's setup line count.
 *
 * @param trimmedLine - Already trimmed line from the callable body.
 * @returns True when trimmedLine is empty or contains only } or });; otherwise false.
 */
function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}
