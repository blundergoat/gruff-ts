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

// Returns a high-confidence finding from the rule details and severity in args, using its file and block for the stable source anchor.
// Omits remediation when the rule has no advice. Use the metadata variant when the rule needs measurements. Analysis then
// replaces the confidence with the rule's catalogue confidence.
export function blockFinding(args: BlockFindingArgs): Finding {
  const endLine = args.block.startLine + args.block.lineCount - 1;
  const remediation = TEST_QUALITY_ADVICE.get(args.ruleId);
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, endLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name, ...(remediation === undefined ? {} : { remediation }) });
}

// Returns a medium-confidence finding from the rule details and severity in args, using its file and block for the stable source anchor.
// Attaches args.metadata without changing the fingerprint. Uses explicit remediation and falls back to rule advice when it is absent.
// The finding omits remediation when the override is empty or neither source supplies advice. Analysis then replaces the
// confidence with the rule's catalogue confidence.
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

// Returns the rule context for a callable, using file for source anchors, block for the span and metrics, and config for rule limits.
// Shares findings as the output collector and uses base complexity for legacy spans to preserve the report invariant without another parse.
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

// Returns nothing. Appends findings to context.findings using the callable, settings and measurements supplied in context.
// Run size and complexity checks first, then missing-documentation and useless-return checks.
export function analyseBlockRules(context: BlockRuleContext): void {
  analyseBlockMeasures(context);
  pushMissingFunctionDocFinding(context);
  pushUselessReturnFindings(context);
}

// Runs size and complexity rules in the stable order used by analyseBlockRules for callables measured only by those rules.
// Returns nothing. Uses the block measurements and rule config in context to append any findings to context.findings.
// See FAMILY-CONTRACT.md section 12 under four more function forms for why documentation and useless-return checks are skipped.
export function analyseBlockMeasures(context: BlockRuleContext): void {
  pushFunctionLengthFinding(context);
  pushParameterCountFinding(context);
  pushCyclomaticFinding(context);
}

// Append a size finding to context.findings when its callable's codeLineCount exceeds the configured limit, which defaults to 200.
// context supplies the source location and rule settings.
// Returns nothing.
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

// Append a parameter-count finding to context.findings when its callable exceeds the configured limit, which defaults to seven.
// Use context's parsed parameterCount when present; otherwise count nonempty comma-separated entries in its parameter text.
// Returns nothing.
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

// Append a cyclomatic finding to context.findings when context's shared count exceeds its configured limit, which defaults to 15.
// Use context's file, callable and complexity breakdown to anchor and explain the finding.
// Returns nothing.
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

// Append a missing-documentation finding to context.findings unless its block is a test or has a recognized leading comment.
// context supplies location and settings. Exported APIs receive warnings and internal callables receive advisory findings.
// Returns nothing.
function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  if (context.block.isTest || context.block.hasLeadingComment) {
    return;
  }
  const isExportedApi = context.block.isExported || isEveryCallablePublicMethod(context);
  const ruleId = isExportedApi ? "docs.missing-exported-function-doc" : "docs.missing-internal-function-doc";
  const severity = isExportedApi ? "warning" : "advisory";
  context.findings.push(blockFinding({ ruleId, message: missingFunctionDocMessage(context.block, isExportedApi ? "Exported" : "Internal"), file: context.file, block: context.block, severity, pillar: "documentation" }));
}

// Returns a missing-doc message for the block, prefixed by audience. If no prompts apply, the message has no suffix.
// Requests descriptions for named parameters other than this and for a return value when the parsed callable returns one.
// A throw token in the masked body triggers the failure prompt under the docs.missing-error-behavior-doc criterion.
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

// Return whether context enables either everyCallable tag option and its parsed callable is a public method of a directly exported class.
// An absent callableNode returns false; the caller uses a true result to select exported-documentation severity.
function isEveryCallablePublicMethod(context: BlockRuleContext): boolean {
  return isTagRuleEveryCallable(context.config) && context.block.callableNode !== undefined && isPublicExportedClassMethod(context.block.callableNode);
}

// Whether either tag rule's everyCallable switch is on. Both are on by default; setting both false
// keeps a public method of an exported class in the internal tier.
function isTagRuleEveryCallable(config: Config): boolean {
  return optionBoolean(config, "docs.missing-param-tag", "everyCallable", true)
    || optionBoolean(config, "docs.missing-return-tag", "everyCallable", true);
}

// Append useless-return advisories to context.findings for terminal bare returns found in context.block.codeBody.
// Add context.block.startLine to each zero-based offset so the finding points to the return in context.file.
// Returns nothing.
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

// Return the zero-based line index of a terminal bare return in masked source as a one-element array for useless-return findings.
// Return an empty array when there is no candidate or the line scan recognizes it as the catch block's only statement.
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

// Keeps waste.useless-return from suggesting a removal that would leave the catch empty and eligible for waste.swallowed-catch.
// Returns true if the first nonblank line before returnIndex in the comment-masked lines opens a catch. Otherwise returns false.
function isOnlyStatementOfCatch(lines: string[], returnIndex: number): boolean {
  for (let current = returnIndex - 1; current >= 0; current -= 1) {
    const trimmed = lines[current]?.trim() ?? "";
    if (trimmed !== "") {
      return /\bcatch\b[^{]*\{$/.test(trimmed);
    }
  }
  return false;
}

// Return whether line opens a test or it registration, allowing a discarded registration result.
// The block parser uses the result to select the test pattern and mark test blocks.
function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:void\s+)?(?:test|it)\s*\(/.test(line);
}

// Return report blocks cut from source; codeSource supplies matching text and codeBody fields and defaults to source.
// Reuse parsed for syntax-based discovery and metrics; without it, use legacy regex discovery and omit syntax metrics.
// Return an empty array when no supported callable is found.
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

// Return the line arrays, code-line flags, patterns and local export names used by block builders.
// source supplies raw text; codeSource supplies matching text; parsed enables decorator exclusion in the code-line flags.
// Without parsed, comments and blank lines are excluded from code-line flags, but decorator lines remain countable.
function functionBlockScan(source: string, codeSource: string, parsed: ParsedScript | undefined): FunctionBlockScan {
  return {
    lines: source.split(/\r?\n/),
    codeLines: codeSource.split(/\r?\n/),
    isCodeLine: codeLineFlags(source, parsed),
    patterns: FUNCTION_BLOCK_PATTERNS,
    reExportedNames: collectReExportedNames(codeSource),
  };
}

// Return the callable nodes owned by matchPoints plus the measure-only nodes discovered in parsed.
// Without parsed, only nodes already present in matchPoints are included; points without callableNode contribute nothing.
// Complexity measurement uses this set to keep nested decisions out of their enclosing callable's count.
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

// Return callable match points. The normal scan must reuse the supplied parse so that discovery shares one syntax tree.
// Otherwise derive points from scan's raw and masked lines and ordered patterns without creating a parse.
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

// Returns the block builder input for a parsed callable selected for measurement, preserving its declaration metadata and syntax node.
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

// Return local names recognized in codeSource's export lists or bare default exports for public-documentation checks.
// Export-from clauses refer to another module and do not add names to this local set.
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

// Return the ordered regex patterns used by legacy callable discovery.
// Test registrations take precedence; named default-export functions remain eligible for public-documentation checks.
function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:void\s+)?(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

// Return the first supported callable match for masked line, or undefined when no pattern accepts it.
// scan supplies the ordered patterns and raw source; index selects the raw line used to recover a test's title.
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

// Return the match for pattern, or undefined when it has no callable name or the name is a control-flow keyword.
// patternIndex is the pattern's position; position zero uses rawLine for recognized test openers to preserve their titles.
// line supplies masked code for all other matches.
function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  // A missing name or control keyword cannot represent a callable in the scan.
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

// Returns the block used by report rules and context documentation, using point for the callable and scan for its source span.
// Uses ownedCallableNodes to preserve complexity ownership when measuring parsed points. Legacy span-only points omit the metrics.
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

// Return the zero-based end line selected for the callable starting at index in scan.
// Use the expression-arrow result when available; otherwise use the brace scan, including its end-of-input fallback.
function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

// Return the zero-based closing line for a callable starting at index, using scan.codeLines for brace depth.
// If no opened body closes, return the last scan.lines index visited, or index when the loop visits no lines.
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

// Returns nothing. Updates the scanner state from one code character by tracking brace depth and recording any body opener.
function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  } else if (character === "}") {
    state.depth -= 1;
  }
}

// Return whether state records an opened body whose brace depth has returned to zero or below.
function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

// Estimate a zero-based end line for the arrow starting at index in codeLines. Use index if the scan finds no terminator.
// Return undefined if the line lacks an arrow or has an opening brace after its first arrow.
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

// Distinguish expression arrows from brace bodies so scan rules receive the correct callable span.
function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

// Return a terminating line index from codeLines, or undefined while the expression-arrow scan must continue.
// line is the declaration text, arrowIndex locates its arrow, start is its index, and current is the line being checked.
// A blank continuation line sets the estimated end to current - 1. A trailing semicolon sets it to current.
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

// Return whether the candidate name is one of the control-flow keywords excluded by legacy callable discovery.
function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

// Return the zero-based scan start for the declaration at index in lines, extending it over recognised docblock or decorator prefix lines.
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

// Returns true when the trimmed preceding line is blank or starts like a decorator or JSDoc line, so the block scan includes it.
function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

// Checks a masked test body before Gruff warns that the test makes no assertion.

// Return whether maskedTestBody contains a recognized assertion-like call or matcher marker for test-quality checks.
// For should.be chains, only calls to eql, equal, greaterThan or instanceOf count.
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

// Return the fixture-purpose setup count for the masked callable source, excluding blank lines and lines containing only } or });.
// Count eligible body lines up to the first assertion marker. With no marker, count every eligible line. An uninspectable body counts as zero.
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

// Return whether the already trimmed line is empty or contains only } or });, which excludes it from the test's setup count.
function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}
