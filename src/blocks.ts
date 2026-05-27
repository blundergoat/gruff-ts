// Function-block parsing + per-block rule pass (size, complexity, NPath, god-function, doc,
// empty-function, unused-parameter, redundant-variable, useless-return) and the block-anchored
// finding factories. Pulls the parser and the rules that operate on parsed blocks out of cli.ts.
import { ruleSeverity, threshold } from "./config.ts";
import { hasLeadingCommentBeforeLines } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { escapeRegex, isGenericName, lineOffset } from "./findings-helpers.ts";
import { countMatches } from "./text-scans.ts";
import type { Config, Finding, Pillar, Severity } from "./types.ts";

const NPATH_CAP = 1_000_000;

// Parsed callable body shared by every block-level rule (size, complexity, naming, docs). The
// `body` / `codeBody` split (raw text vs. comment-masked) lets rules choose between literal
// inspection and code-only matching without re-running the masker.
export interface FunctionBlock {
  name: string;
  params: string;
  startLine: number;
  lineCount: number;
  body: string;
  codeBody: string;
  isPublic: boolean;
  // True when the function declaration line itself starts with `export`. Distinct from `isPublic`,
  // which also matches class `public` modifiers - exports are the top-level API surface, while a
  // public class method is internal to an exported (or unexported) class. The doc rule splits
  // severity on this distinction: exported functions warrant warning-tier doc requirements,
  // internal helpers stay advisory.
  isExported: boolean;
  isTest: boolean;
  hasLeadingComment: boolean;
  declarationLine: number;
}

// Working state for the function-block parser. Patterns are precompiled once per file so each
// callable detection doesn't re-instantiate the same RegExp objects. `reExportedNames` carries
// the file-level scan of `export { foo }` / `export default foo` so a declaration like
// `function foo() {}` later re-exported via `export { foo }` is still classified as exported
// (the line-local `^export` check alone would miss this common pattern).
interface FunctionBlockScan {
  lines: string[];
  codeLines: string[];
  patterns: RegExp[];
  reExportedNames: ReadonlySet<string>;
}

const FUNCTION_BLOCK_PATTERNS = functionBlockPatterns();

// Tiny lexer for finding the closing brace of a callable. `hasSeenOpen` matters because the depth
// counter would otherwise hit zero before the body ever opened (arrow functions with a default body).
interface FunctionBodyScanState {
  depth: number;
  hasSeenOpen: boolean;
}

// Precomputed inputs for every block-level rule. Computing cyclomatic / functionBody once and
// reusing the values keeps each rule's deterministic per-block work down to a single pattern test.
export interface BlockRuleContext {
  file: SourceFile;
  block: FunctionBlock;
  config: Config;
  findings: Finding[];
  cyclomatic: number;
  functionBody: string;
}

// NPath approximation result. `isCapped: true` signals the value hit `NPATH_CAP` and is a lower
// bound - the finding message uses this to mark capped values rather than implying precision.
export interface NpathResult {
  value: number;
  isCapped: boolean;
}

// Input bundle for `blockFinding()`. The block reference replaces the explicit line: the builder
// reads `block.startLine` and `block.name` so the stable finding anchor and symbol metadata stay
// in sync with the parsed callable across every block-level rule.
export interface BlockFindingArgs {
  ruleId: string;
  message: string;
  file: SourceFile;
  block: FunctionBlock;
  severity: Severity;
  pillar: Pillar;
}

// `BlockFindingArgs` plus a rule-specific metadata payload. Used by rules that need to encode
// numeric thresholds or measurements (size, complexity values) into the Finding so downstream
// consumers can filter without re-running the analyzer.
export interface BlockFindingWithMetadataArgs extends BlockFindingArgs {
  metadata: Record<string, unknown>;
}

// Block-anchored finding factory: pulls line + symbol from the parsed callable so every
// block-level rule reports against the same anchor. Default confidence is "high"; callers
// needing metadata or lower confidence go through `blockFindingWithMetadata` to keep the
// per-rule fingerprint shape stable.
export function blockFinding(args: BlockFindingArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "high", symbol: args.block.name });
}

// Block-anchored variant that ships rule-specific metadata. Confidence defaults to "medium"
// because metadata-carrying rules (size, complexity, NPath) report measurements rather than
// definitive defects; the metadata payload is part of each rule's stable fingerprint contract.
export function blockFindingWithMetadata(args: BlockFindingWithMetadataArgs): Finding {
  return makeFinding({ ruleId: args.ruleId, message: args.message, filePath: args.file.displayPath, line: args.block.startLine, severity: args.severity, pillar: args.pillar, confidence: "medium", symbol: args.block.name, metadata: args.metadata });
}

// Computes cyclomatic and function-body once and threads them through the per-block rule pipeline.
// Pre-computing here keeps each rule's per-block work to a single threshold comparison; the
// resulting struct is part of the stable rule-context contract every per-block helper consumes.
export function blockRuleContext(file: SourceFile, block: FunctionBlock, config: Config, findings: Finding[]): BlockRuleContext {
  return {
    file,
    block,
    config,
    findings,
    cyclomatic: countMatches(block.codeBody, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1,
    functionBody: functionBodyContent(block.codeBody),
  };
}

/*
 * Per-block rule sequence. The ordering is the stable baseline contract - every block emits its
 * findings in this exact deterministic order, so reshuffling the call list churns fingerprints
 * even when no rule changes.
 */
export function analyseBlockRules(context: BlockRuleContext): void {
  pushFunctionLengthFinding(context);
  pushParameterCountFinding(context);
  pushCyclomaticFinding(context);
  pushCognitiveFinding(context);
  pushNpathFinding(context);
  pushGodFunctionFinding(context);
  pushGenericFunctionFinding(context);
  pushMissingFunctionDocFinding(context);
  pushEmptyFunctionFinding(context);
  pushUnusedParameterFindings(context);
  pushRedundantVariableFindings(context);
  pushUselessReturnFindings(context);
}

// Default threshold 200, default severity `warning` - functions past that length are usually a
// maintenance signal, not a stylistic preference. Reports `size.function-length` when the block exceeds the limit.
function pushFunctionLengthFinding(context: BlockRuleContext): void {
  const functionLengthThreshold = threshold(context.config, "size.function-length", 200);
  if (context.block.lineCount > functionLengthThreshold) {
    context.findings.push(blockFinding({ ruleId: "size.function-length", message: `Function \`${context.block.name}\` has ${context.block.lineCount} lines, above the threshold of ${functionLengthThreshold}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.function-length", "warning"), pillar: "size" }));
  }
}

// Default threshold 7. Comma-counts on `block.params` rather than parsing because the parser
// already validated the signature shape upstream. Reports `size.parameter-count` when exceeded.
function pushParameterCountFinding(context: BlockRuleContext): void {
  const params = context.block.params.split(",").map((value) => value.trim()).filter(Boolean).length;
  if (params > threshold(context.config, "size.parameter-count", 7)) {
    context.findings.push(blockFinding({ ruleId: "size.parameter-count", message: `Function \`${context.block.name}\` declares ${params} parameters.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "size.parameter-count", "warning"), pillar: "size" }));
  }
}

// Default threshold 15. Counts conditional keywords + boolean operators in the code body - see
// `blockRuleContext` for the pre-computed value. Reports `complexity.cyclomatic` when exceeded.
function pushCyclomaticFinding(context: BlockRuleContext): void {
  if (context.cyclomatic > threshold(context.config, "complexity.cyclomatic", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cyclomatic", message: `Function \`${context.block.name}\` has cyclomatic complexity ${context.cyclomatic}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cyclomatic", "warning"), pillar: "complexity" }));
  }
}

// Default threshold 15. Cognitive complexity is cyclomatic + max nesting depth - captures the
// "deeply nested" intuition pure cyclomatic misses. Reports `complexity.cognitive` when exceeded.
function pushCognitiveFinding(context: BlockRuleContext): void {
  const cognitive = context.cyclomatic + maxNestingDepth(context.block.codeBody);
  if (cognitive > threshold(context.config, "complexity.cognitive", 15)) {
    context.findings.push(blockFinding({ ruleId: "complexity.cognitive", message: `Function \`${context.block.name}\` has cognitive complexity ${cognitive}.`, file: context.file, block: context.block, severity: ruleSeverity(context.config, "complexity.cognitive", "warning"), pillar: "complexity" }));
  }
}

// Default threshold 200. NPath is the number of possible execution paths; the message marks
// `capped` when the calculation hit `NPATH_CAP` so reviewers know it's a lower bound. Reports `complexity.npath`.
function pushNpathFinding(context: BlockRuleContext): void {
  const npath = approximateNpath(context.functionBody);
  const npathThreshold = threshold(context.config, "complexity.npath", 200);
  if (npath.value > npathThreshold) {
    context.findings.push(npathFinding(context, npath, npathThreshold, ruleSeverity(context.config, "complexity.npath", "warning")));
  }
}

/*
 * Stable `complexity.npath` finding factory. `capped` and `cap` are surfaced in metadata so
 * downstream tooling can distinguish "5000" from "≥ NPATH_CAP" - both would render as the same
 * value otherwise.
 */
function npathFinding(context: BlockRuleContext, npath: NpathResult, thresholdValue: number, severity: Severity): Finding {
  return blockFindingWithMetadata({
    ruleId: "complexity.npath",
    message: `Function \`${context.block.name}\` has approximate NPath complexity ${npath.value} above the threshold of ${thresholdValue} (capped at ${NPATH_CAP}).`,
    file: context.file,
    block: context.block,
    severity,
    pillar: "complexity",
    metadata: { npath: npath.value, capped: npath.isCapped, cap: NPATH_CAP, threshold: thresholdValue },
  });
}

// Combined-shape rule: long (>45 lines) AND complex (cyclomatic >10). Thresholds are hard-coded
// because "god function" is a design heuristic, not a per-rule tunable. Reports `design.god-function`.
function pushGodFunctionFinding(context: BlockRuleContext): void {
  if (context.block.lineCount > 45 && context.cyclomatic > 10) {
    context.findings.push(blockFinding({ ruleId: "design.god-function", message: `Function \`${context.block.name}\` is both long and complex.`, file: context.file, block: context.block, severity: "warning", pillar: "design" }));
  }
}

// Names like `process`, `handle`, `run` from `config.bannedGenericNames`. The list is user-configurable;
// the rule body itself just consults the config. Reports `naming.generic-function`.
function pushGenericFunctionFinding(context: BlockRuleContext): void {
  if (isGenericName(context.block.name, context.config.bannedGenericNames)) {
    context.findings.push(blockFinding({ ruleId: "naming.generic-function", message: `Function \`${context.block.name}\` is too generic to explain intent.`, file: context.file, block: context.block, severity: "advisory", pillar: "naming" }));
  }
}

/*
 * Every non-test function must carry a leading comment. Test blocks are exempted because their
 * `test("name", …)` description already documents intent. Reports
 * `docs.missing-exported-function-doc` (warning, higher cost of omission on the public API
 * surface) when `isExported` is true, `docs.missing-internal-function-doc` (advisory) otherwise.
 */
function pushMissingFunctionDocFinding(context: BlockRuleContext): void {
  if (context.block.isTest || context.block.hasLeadingComment) {
    return;
  }
  const ruleId = context.block.isExported ? "docs.missing-exported-function-doc" : "docs.missing-internal-function-doc";
  const severity = context.block.isExported ? "warning" : "advisory";
  const audience = context.block.isExported ? "exported" : "internal";
  context.findings.push(blockFinding({ ruleId, message: `${audience === "exported" ? "Exported" : "Internal"} function \`${context.block.name}\` is missing a leading maintainer comment.`, file: context.file, block: context.block, severity, pillar: "documentation" }));
}

// Empty bodies are sometimes intentional placeholders, hence the advisory severity rather than
// warning. Reports `waste.empty-function` when the body strips to whitespace/comments only.
function pushEmptyFunctionFinding(context: BlockRuleContext): void {
  if (isBodyLessDeclaration(context.block) || isDeclarationFile(context.file)) {
    return;
  }
  if (isEmptyFunctionBody(context.block.codeBody)) {
    context.findings.push(blockFinding({ ruleId: "waste.empty-function", message: `Function \`${context.block.name}\` has no executable body.`, file: context.file, block: context.block, severity: "advisory", pillar: "maintainability" }));
  }
}

// `_`-prefixed parameters are exempted (the standard "intentionally unused" convention).
// Reports `waste.unused-parameter` for parameter names that never appear in the callable body.
function pushUnusedParameterFindings(context: BlockRuleContext): void {
  if (isBodyLessDeclaration(context.block) || isDeclarationFile(context.file)) {
    return;
  }
  for (const parameter of parameterNames(context.block.params)) {
    if (!isUnusedParameter(context, parameter.name)) {
      continue;
    }
    context.findings.push(unusedParameterFinding(context, parameter.name));
  }
}

// Skips interface methods, type-literal methods, function-type aliases, abstract members, and
// overload signatures - all of which look like a function declaration ending in `;` rather than `{`,
// and have no real body to check for emptiness or parameter usage.
function isBodyLessDeclaration(block: FunctionBlock): boolean {
  for (const rawLine of block.codeBody.split("\n")) {
    const trimmed = rawLine.trim();
    if (trimmed === "" || trimmed.startsWith("//") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
      continue;
    }
    return /\)[^{;]*;\s*$/.test(trimmed);
  }
  return false;
}

// TypeScript `.d.ts` files only declare types; every callable in them is a signature, never an
// implementation, so the empty/unused-parameter rules are categorically misapplied there.
function isDeclarationFile(file: SourceFile): boolean {
  return file.displayPath.endsWith(".d.ts");
}

// Word-boundary regex against the masked function body. The body is masked so a parameter mentioned
// only in a string literal would still count as unused - that matches the intent of the rule. A
// loose `${...param...}` regex over the raw body catches parameters used only inside template
// interpolations, which the mask would otherwise hide.
function isUnusedParameter(context: BlockRuleContext, parameterName: string): boolean {
  if (parameterName.startsWith("_")) {
    return false;
  }
  const escaped = escapeRegex(parameterName);
  if (new RegExp(`\\b${escaped}\\b`).test(context.functionBody)) {
    return false;
  }
  return !new RegExp(`\\$\\{[^}]*\\b${escaped}\\b[^}]*\\}`).test(context.block.body);
}

/*
 * Stable `waste.unused-parameter` finding shape. `block.startLine` is the anchor so the fingerprint
 * stays at the callable's declaration line, not at the parameter's column position.
 */
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

// Targets `const x = expr; return x;` patterns. The detector walks the function source once and
// reports each variable whose only use is the trailing return as `waste.redundant-variable`.
function pushRedundantVariableFindings(context: BlockRuleContext): void {
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

// Caller adds the block's start line to the relative offset so the finding anchors at the actual
// trailing statement. Reports `waste.useless-return` when the final statement is a redundant bare exit.
function pushUselessReturnFindings(context: BlockRuleContext): void {
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

// Approximation: each decision keyword (`if`, `case`, `catch`, loops) and short-circuit operator
// doubles the count. Optional chaining is stripped first so `a?.b` and `??` don't inflate the
// signal. Capped at `NPATH_CAP` - the `capped` flag tells callers to report the value as ≥, not =.
export function approximateNpath(source: string): NpathResult {
  let pathCount = 1;
  let isCapped = false;
  const normalized = source.replace(/\?\./g, "").replace(/\?\?/g, "");
  const decisionCount = countMatches(normalized, /\b(if|else if|case|catch|for|while)\b|\?|&&|\|\|/g);
  for (let index = 0; index < decisionCount; index += 1) {
    pathCount *= 2;
    if (pathCount >= NPATH_CAP) {
      pathCount = NPATH_CAP;
      isCapped = true;
      break;
    }
  }
  return { value: pathCount, isCapped };
}

// Strips line and block comments before measuring - a body containing only documentation is still
// considered empty for the `waste.empty-function` check, since no executable statements run.
function isEmptyFunctionBody(source: string): boolean {
  const body = functionBodyContent(source)
    .replace(/\/\/.*$/gm, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .trim();
  return body === "";
}

// Two shapes: block-body callables return the text between the outermost `{` and `}`; expression
// arrow functions fall back to the slice after `=>`. The trailing-`;` strip keeps the arrow
// branch usable for downstream regex tests that anchor on statement boundaries.
export function functionBodyContent(source: string): string {
  const start = source.indexOf("{");
  const end = source.lastIndexOf("}");
  if (start === -1 || end <= start) {
    const arrow = source.indexOf("=>");
    return arrow === -1 ? "" : source.slice(arrow + 2).replace(/;?\s*$/, "");
  }
  return source.slice(start + 1, end);
}

// Walks upward past blank lines and the closing `}` looking for a final `return;`. Returns the
// line offset of that statement (zero-based) or an empty list if the last real line is anything
// else - used by `waste.redundant-variable` so the finding anchors on the actual statement.
function terminalBareReturnLines(source: string): number[] {
  const lines = source.split(/\r?\n/);
  let current = lines.length - 1;
  while (current >= 0) {
    const trimmed = lines[current]?.trim() ?? "";
    if (trimmed === "" || trimmed === "}") {
      current -= 1;
      continue;
    }
    return /^return\s*;?$/.test(trimmed) ? [current] : [];
  }
  return [];
}

// Splits on `,` then strips visibility modifiers, `...rest`, default values, and type annotations
// in that order. Final filter rejects entries whose name isn't a plain identifier - destructured
// parameters land in that bucket and are intentionally invisible to per-parameter rules.
export function parameterNames(params: string): Array<{ name: string; raw: string }> {
  return params
    .split(",")
    .map((parameter) => parameter.trim())
    .filter(Boolean)
    .map((raw) => {
      const stripped = raw.replace(/^(?:public|private|protected|readonly)\s+/, "").replace(/^\.\.\./, "");
      const name = stripped.split(/[?:=]/)[0]?.trim() ?? "";
      return { name, raw: stripped };
    })
    .filter((parameter) => /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(parameter.name));
}

// Detects the `const x = expr; return x;` pattern. The regex backreference `\1` enforces that the
// returned identifier matches the declared one - used by `waste.redundant-variable` to surface
// pointless temporaries with deterministic line offsets.
function redundantVariableReturns(source: string): Array<{ name: string; lineOffset: number }> {
  const results: Array<{ name: string; lineOffset: number }> = [];
  for (const match of source.matchAll(/\b(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*[^;]+;\s*return\s+\1\s*;/g)) {
    results.push({ name: match[1] ?? "", lineOffset: lineOffset(source, match.index ?? 0) });
  }
  return results.filter((result) => result.name !== "");
}

// Deepest `{` / `}` nesting reached across the body, minus one so the body's own outer braces
// don't count. The `Math.max(0, …)` clamp protects against unbalanced inputs - feeds the nesting
// component of `complexity.cognitive` and must stay deterministic across runs.
export function maxNestingDepth(source: string): number {
  let depth = 0;
  let maxDepth = 0;
  for (const character of source) {
    if (character === "{") {
      depth += 1;
      maxDepth = Math.max(maxDepth, depth);
    } else if (character === "}") {
      depth = Math.max(0, depth - 1);
    }
  }
  return Math.max(0, maxDepth - 1);
}

// Matches `test("…", …)` and `it("…", …)` openers. Used both by the function-block parser to
// pick the right pattern and by setup detection to skip the test wrapper line itself.
function isTestInvocationLine(line: string): boolean {
  return /^\s*(?:test|it)\s*\(/.test(line);
}

// Top-level driver: precompiles patterns once, then walks the masked code lines so commented-out
// declarations don't fire. The two-source split (`source` / `codeSource`) keeps raw line text
// available for body extraction while preserving stable, comment-masked matching.
export function functionBlocks(source: string, codeSource = source): FunctionBlock[] {
  const scan: FunctionBlockScan = {
    lines: source.split(/\r?\n/),
    codeLines: codeSource.split(/\r?\n/),
    patterns: FUNCTION_BLOCK_PATTERNS,
    reExportedNames: collectReExportedNames(codeSource),
  };
  const blocks: FunctionBlock[] = [];
  scan.codeLines.forEach((line, index) => {
    const match = functionBlockMatch(scan, line, index);
    if (!match) {
      return;
    }
    blocks.push(functionBlockFromMatch(scan, match, index));
  });
  return blocks;
}

/*
 * File-level scan for re-exported local declarations. Matches `export { foo }`, `export { foo as
 * bar }` (the local name `foo` is recorded, not the renamed `bar`), and `export default foo`
 * (bare-identifier form - `export default function ...` is matched via pattern 2 in
 * functionBlockPatterns instead, then classified exported because the line itself starts with
 * `export`). Re-export-from clauses (`export { foo } from "./other"`) are intentionally skipped
 * via the negative lookahead: those names are not local declarations of this file, so promoting
 * a same-named local to "exported" would emit a false missing-public-doc finding.
 *
 * Operates on the masked codeSource so `export { foo }` inside a string literal or comment is
 * skipped. Multi-line export blocks work because `[^}]+` spans newlines, and the lookahead
 * spans whitespace and blanked-comment runs that the masker collapses to spaces.
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
  for (const match of codeSource.matchAll(/^\s*export\s+default\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*;?\s*$/gm)) {
    if (match[1]) {
      names.add(match[1]);
    }
  }
  return names;
}

// Four callable shapes in the order `functionBlockMatch` tries them: `test()` / `it()` bodies,
// `function` declarations, class methods, and arrow assignments. Pattern[0] is intentionally
// first because test bodies must match before the generic arrow pattern claims them. Pattern[1]
// accepts an optional `default` after `export` so `export default function foo() {}` parses into
// a FunctionBlock - the CHANGELOG's exported-doc-rule contract advertises that shape and the
// missing `default` token previously made those declarations invisible to every block-level rule.
function functionBlockPatterns(): RegExp[] {
  return [
    /^\s*(?:test|it)\s*\(\s*["'`]([^"'`]+)["'`]\s*,\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
    /^\s*(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)/,
    /^\s*(?:public|private|protected)?\s*(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*[:{]/,
    /^\s*(?:export\s+)?(?:const|let)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/,
  ];
}

// Tries each compiled pattern in order and returns the first hit. The loop bails when a pattern
// slot is missing (defensive guard for the precompiled list) and uses the patternIndex to let
// `functionPatternMatch` pick raw vs. masked text per pattern.
function functionBlockMatch(scan: FunctionBlockScan, line: string, index: number): RegExpMatchArray | undefined {
  const rawLine = scan.lines[index] ?? "";
  for (let patternIndex = 0; patternIndex < scan.patterns.length; patternIndex += 1) {
    const pattern = scan.patterns[patternIndex];
    if (!pattern) {
      continue;
    }
    const match = functionPatternMatch(pattern, patternIndex, line, rawLine);
    if (match) {
      return match;
    }
  }
  return undefined;
}

// Pattern[0] (`test`/`it`) needs the raw line because the test name lives inside a string
// literal that the masker would otherwise blank out. Everything else runs against the masked
// `line`. Filters out control-block keywords so `if(...) {` doesn't register as a callable.
function functionPatternMatch(pattern: RegExp, patternIndex: number, line: string, rawLine: string): RegExpMatchArray | undefined {
  const candidate = patternIndex === 0 && isTestInvocationLine(line) ? rawLine : line;
  const match = candidate.match(pattern);
  if (!match?.[1] || isControlBlockName(match[1])) {
    return undefined;
  }
  return match;
}

// Promotes a regex match into a `FunctionBlock`. `start` walks up to capture leading docblock /
// decorator lines so size and documentation rules see the full declaration footprint; the
// `isPublic` check scans that same range so `export` / `public` modifiers above the line count.
function functionBlockFromMatch(scan: FunctionBlockScan, match: RegExpMatchArray, index: number): FunctionBlock {
  const start = functionStartIndex(scan.lines, index);
  const end = functionEndIndex(scan, index);
  const body = scan.lines.slice(start, end + 1).join("\n");
  const codeBody = scan.codeLines.slice(start, end + 1).join("\n");
  return {
    name: match[1] ?? "",
    params: match[2] ?? "",
    startLine: start + 1,
    lineCount: end - start + 1,
    body,
    codeBody,
    isPublic: /\bexport\b|\bpublic\b/.test(scan.codeLines.slice(start, index + 1).join("\n")),
    isExported: /^\s*export\b/.test(scan.codeLines[index] ?? "") || scan.reExportedNames.has(match[1] ?? ""),
    isTest: isTestInvocationLine(scan.codeLines[index] ?? ""),
    hasLeadingComment: hasLeadingCommentBeforeLines(scan.lines, index + 1),
    declarationLine: index + 1,
  };
}

// Two callable shapes share one entry point: single-expression arrows return early via
// `expressionArrowEndIndex`, everything else falls into the brace-depth walker. Returning the
// wrong end index would slice the wrong body and silently corrupt every per-block rule's input.
function functionEndIndex(scan: FunctionBlockScan, index: number): number {
  return expressionArrowEndIndex(scan.codeLines, index) ?? blockFunctionEndIndex(scan, index);
}

// Brace-depth walker over masked code lines. Operates on `codeLines` so braces inside strings or
// comments don't disturb the depth counter - the masker preserves brace positions in real code
// and neutralises them everywhere else, keeping the body slice stable.
function blockFunctionEndIndex(scan: FunctionBlockScan, index: number): number {
  const state: FunctionBodyScanState = { depth: 0, hasSeenOpen: false };
  let end = index;
  for (let current = index; current < scan.lines.length; current += 1) {
    for (const character of scan.codeLines[current] ?? "") {
      applyFunctionBodyCharacter(state, character);
    }
    end = current;
    if (isFunctionBodyClosed(state)) {
      break;
    }
  }
  return end;
}

// Per-character transition for the brace-depth walker. Setting `hasSeenOpen` on `{` is the
// invariant `isFunctionBodyClosed` relies on - without it, the walker would treat the
// pre-open state (depth 0) as already closed.
function applyFunctionBodyCharacter(state: FunctionBodyScanState, character: string): void {
  if (character === "{") {
    state.depth += 1;
    state.hasSeenOpen = true;
  } else if (character === "}") {
    state.depth -= 1;
  }
}

// Termination predicate for the brace-depth walker. Requires `hasSeenOpen` so the initial
// pre-body state doesn't read as already closed - the depth counter is only meaningful after the
// first `{`.
function isFunctionBodyClosed(state: FunctionBodyScanState): boolean {
  return state.hasSeenOpen && state.depth <= 0;
}

// Returns the line index where a single-expression arrow body terminates. Detection bails when
// the line contains a `{` after `=>` (a block-bodied arrow); otherwise walks forward until a `;`
// closes the expression or a blank line ends it.
function expressionArrowEndIndex(codeLines: string[], index: number): number | undefined {
  const line = codeLines[index] ?? "";
  const arrowIndex = line.indexOf("=>");
  if (!isExpressionArrowLine(line, arrowIndex)) {
    return undefined;
  }
  for (let current = index; current < codeLines.length; current += 1) {
    const endIndex = expressionArrowEndStep(codeLines, line, arrowIndex, index, current);
    if (endIndex !== undefined) {
      return endIndex;
    }
  }
  return index;
}

// `=>` exists and no `{` follows it - that means the body is a bare expression, not a block.
// The distinction matters because expression bodies need a different end-of-block strategy.
function isExpressionArrowLine(line: string, arrowIndex: number): boolean {
  return arrowIndex !== -1 && !line.slice(arrowIndex + 2).includes("{");
}

// One step of the arrow-expression walker. On the declaration line itself, a trailing `;` closes
// the body immediately. Otherwise: a blank line means we walked past the body (back up one
// index), and a `;`-terminated line is the actual end. Returning undefined means keep walking.
function expressionArrowEndStep(codeLines: string[], line: string, arrowIndex: number, start: number, current: number): number | undefined {
  const trimmed = (codeLines[current] ?? "").trim();
  if (current === start) {
    return line.slice(arrowIndex + 2).trim().endsWith(";") ? current : undefined;
  }
  if (trimmed === "") {
    return current - 1;
  }
  return trimmed.endsWith(";") ? current : undefined;
}

// `if (...) { … }`, `for (...)`, etc. all look like `<name>(` to the pattern walker. The fixed
// exclusion list prevents control-flow blocks from being treated as callables and reported by
// per-block rules.
function isControlBlockName(name: string): boolean {
  return ["if", "for", "while", "switch", "catch"].includes(name);
}

// Walks upward from the declaration line absorbing decorator (`@`), docblock (`/**`, `*`), and
// blank lines so the function block includes its leading documentation. Stops at the first real
// code line above - that boundary becomes the block's start line.
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
  return start;
}

// Predicate that decides whether `functionStartIndex` should keep walking upward. Decorators,
// docblock openers, docblock body lines (`*`), and blank lines all belong to the declaration's
// leading block; anything else marks the boundary.
function isFunctionPrefixLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("@") || trimmedLine.startsWith("/**") || trimmedLine.startsWith("*") || trimmedLine === "";
}

// Generic "is there any assertion at all" probe used by missing-assertion rules. Accepts standard
// `assert(...)` / `assert.foo(...)` / `expect(...)` (including `expect.assertions()` / `expect.hasAssertions()`)
// PLUS project-local helpers shaped like `assertFoo(...)`, `expectFoo(...)`, `fooCheck(...)`, and
// promise-rejection patterns (`rejects.`, `doesNotReject(`). Custom helpers are common in mature
// test suites and missing them produced false positives in M38 false-positive triage.
export function hasAssertion(source: string): boolean {
  if (/\bassert(?:\.[A-Za-z]+|[A-Z][A-Za-z0-9_$]*)?\s*\(/.test(source)) {
    return true;
  }
  if (/\bexpect(?:\.(?:assertions|hasAssertions)|[A-Z][A-Za-z0-9_$]*)?\s*\(/.test(source)) {
    return true;
  }
  if (/\b[A-Za-z_$][A-Za-z0-9_$]*Check\s*\(/.test(source)) {
    return true;
  }
  if (/\.(?:rejects|resolves)\b/.test(source) || /\b(?:doesNotReject|rejects)\s*\(/.test(source)) {
    return true;
  }
  return false;
}

// Setup-bloat metric: counts non-ignorable lines preceding the first assertion in the body. Stops
// as soon as an assertion appears, so the value never overshoots the actual prologue length used
// by `test-quality.setup-bloat`.
export function setupLineCount(source: string): number {
  let count = 0;
  for (const line of functionBodyContent(source).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (isIgnorableSetupLine(trimmed)) {
      continue;
    }
    if (hasAssertion(trimmed)) {
      break;
    }
    count += 1;
  }
  return count;
}

// Filter for `setupLineCount`. Blank lines plus the two closer shapes (`}` and `});`) shouldn't
// inflate the count - those are syntax, not setup work.
function isIgnorableSetupLine(trimmedLine: string): boolean {
  return trimmedLine.length === 0 || trimmedLine === "});" || trimmedLine === "}";
}
