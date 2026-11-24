// Context-doc rules: emit findings when a function or interface comment exists but does not
// describe the WHY (complex control flow), side effects, error behavior, or public-contract
// invariants the implementation carries. Each rule reports a stable, deterministic finding.
import { type FunctionBlock } from "./blocks.ts";
import { type CommentRecord } from "./comment-scanner.ts";
import { baseComplexityMetrics } from "./complexity-metrics.ts";
import { threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Config, Finding } from "./types.ts";

// Generic declaration shape used by both function and interface comment-quality rules so they can
// share `pushStaleDeclarationCommentFinding` and `pushRestatingSignatureCommentFinding` logic.
export interface CommentedDeclaration {
  kind: "function" | "interface";
  name: string;
  line: number;
  isPublic: boolean;
}

type ContextDocFindingDetails = {
  symbol: string;
  ruleId: string;
  message: string;
  remediation: string;
  metadata: Record<string, string>;
};

type ContextDocFindingInput = ContextDocFindingDetails & {
  file: SourceFile;
  comment: CommentRecord;
};

/**
 * Evaluates `block` against rationale, side-effect, error, and invariant documentation checks and records any gaps.
 *
 * @param file - Source file whose display path anchors each emitted finding.
 * @param block - Parsed function block whose body, name, and metrics are inspected.
 * @param comment - Leading comment record providing the review text and finding line number.
 * @param config - Active analyzer configuration supplying complexity thresholds.
 * @param findings - Mutable report list where stable context-doc findings are appended.
 * @returns Nothing. Appends stable findings for each missing context class to `findings`.
 */
export function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
}

/**
 * Records an invariant-doc finding when an interface declaration signals a public contract that `comment` leaves unmarked.
 * Other declaration kinds are ignored, and the caller skips signature-restatement comments to avoid duplicate findings.
 *
 * @param file - Source file whose display path anchors the finding.
 * @param lines - Full file lines used to slice the interface declaration block.
 * @param declaration - Commented declaration metadata checked for interface kind and contract signals.
 * @param comment - Leading comment record supplying the review text and finding line.
 * @param findings - Mutable report list receiving any `docs.missing-invariant-doc` finding.
 * @returns Nothing. Appends an invariant-doc finding to `findings` only when an interface signals an undocumented contract.
 */
export function pushDeclarationContextFindings(file: SourceFile, lines: string[], declaration: CommentedDeclaration, comment: CommentRecord, findings: Finding[]): void {
  if (declaration.kind !== "interface") {
    return;
  }
  if (!hasInvariantInterfaceSignal(lines, declaration) || hasInvariantMarker(comment.text)) {
    return;
  }
  findings.push(
    contextDocFinding({
      file,
      comment,
      ...contextDocDetails(declaration.name, "docs.missing-invariant-doc", `Interface \`${declaration.name}\` defines a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, report, or determinism invariant.", "invariant"),
    }),
  );
}

/**
 * Collects context-doc finding details for `block` by checking `commentText` against complexity, side-effect, error, and invariant rules.
 *
 * @param block - Parsed function block whose name, body, and complexity metrics are inspected.
 * @param commentText - Raw comment text evaluated for rationale, side-effect, `@throws`, and invariant markers.
 * @param config - Active analyzer configuration providing configurable complexity thresholds.
 * @returns Finding detail entries for each detected documentation gap, or an empty array when none apply.
 */
function functionContextDocFindings(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails[] {
  const details: ContextDocFindingDetails[] = [];
  const body = block.codeBody;
  const complex = complexFunctionContextDocFinding(block, commentText, config);
  const sideEffect = sideEffectContextDocFinding(block, body, commentText);
  const errorBehavior = errorBehaviorContextDocFinding(block, body, commentText);
  const invariant = invariantContextDocFinding(block, commentText);
  if (complex) {
    details.push(complex);
  }
  if (sideEffect) {
    details.push(sideEffect);
  }
  if (errorBehavior) {
    details.push(errorBehavior);
  }
  if (invariant) {
    details.push(invariant);
  }
  return details;
}

/**
 * Evaluates `block` against configurable length and cyclomatic limits plus fixed cognitive and nesting limits for missing rationale docs.
 * Skips test-case callbacks because test files already use `docs.fixture-purpose-missing` for setup rationale.
 *
 * @param block - Function block checked for test status, complexity eligibility, and symbol name.
 * @param commentText - Leading comment text inspected for accepted rationale markers.
 * @param config - Active analyzer configuration supplying length and cyclomatic thresholds.
 * @returns Missing-why finding details when `commentText` lacks a rationale marker for a complex block, or `undefined` otherwise.
 */
function complexFunctionContextDocFinding(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails | undefined {
  if (block.isTest || !isComplexContextCandidate(block, config) || hasComplexWhyMarker(commentText, block.name)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-why-for-complex-code", `Complex function \`${block.name}\` has a comment, but it does not explain why the control flow exists.`, "Explain the tradeoff, compatibility reason, or invariant behind the complex control flow.", "complex-code");
}

/**
 * Checks whether a function with observable side-effect signals lacks a side-effect marker in its comment.
 *
 * @param block - Function block supplying the declaration name for signal and finding metadata.
 * @param body - Masked function body searched for filesystem, process, environment, or server mutations.
 * @param commentText - Leading comment text checked for side-effect vocabulary.
 * @returns Missing-side-effect finding details when an effect signal exists without a marker, or `undefined` otherwise.
 */
function sideEffectContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasSideEffectSignal(block.name, body) || hasSideEffectMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-side-effect-doc", `Function \`${block.name}\` performs side effects that its comment does not describe.`, "Name the observable side effect such as filesystem, process, environment, or network mutation.", "side-effect");
}

/**
 * Checks whether a function whose body contains a word-boundary `throw` lacks an `@throws` tag in its comment.
 *
 * @param block - Function block supplying the symbol name for any emitted finding details.
 * @param body - Function code body tested for `throw` at word boundaries.
 * @param commentText - Leading comment text inspected for an `@throws` marker.
 * @returns Missing-error-behavior finding details when `body` throws without an `@throws` tag, or `undefined` otherwise.
 */
function errorBehaviorContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!/\bthrow\b/.test(body) || /@throws\b/.test(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-error-behavior-doc", `Function \`${block.name}\` throws, but its comment has no @throws tag.`, "Add an @throws tag that names each error the function throws and when.", "error-behavior");
}

/**
 * Checks whether a function signaling a public contract lacks an invariant marker in its comment.
 *
 * @param block - Function block whose name and body are checked for contract signals.
 * @param commentText - Leading comment text checked for invariant or contract markers.
 * @returns Missing-invariant finding details when a contract signal has no marker, or `undefined` otherwise.
 */
function invariantContextDocFinding(block: FunctionBlock, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasInvariantFunctionSignal(block) || hasInvariantMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-invariant-doc", `Function \`${block.name}\` maintains a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, sorting, or determinism invariant.", "invariant");
}

/**
 * Builds the rule-specific detail payload shared by all context-doc findings.
 *
 * @param symbol - Declaration name attached to the finding.
 * @param ruleId - Context-doc rule identifier selected for the gap.
 * @param message - Human-readable summary explaining the missing documentation.
 * @param remediation - Actionable repair advice shown to the developer.
 * @param contextClass - Missing-context discriminator stored in `metadata.contextClass`.
 * @returns Structured finding details containing the supplied fields and `contextClass` metadata.
 */
function contextDocDetails(symbol: string, ruleId: string, message: string, remediation: string, contextClass: string): ContextDocFindingDetails {
  return {
    symbol,
    ruleId,
    message,
    remediation,
    metadata: { contextClass },
  };
}

/**
 * Materializes a stable advisory documentation finding anchored at the reviewed comment's line.
 *
 * @param input - Bundle containing the source file, comment record, symbol, rule ID, message, remediation, and metadata.
 * @returns Stable `Finding` record in the documentation pillar with advisory severity and medium confidence.
 */
function contextDocFinding(input: ContextDocFindingInput): Finding {
  const { file, comment, symbol, ruleId, message, remediation, metadata } = input;
  return makeFinding({
    ruleId,
    message,
    filePath: file.displayPath,
    line: comment.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol,
    remediation,
    metadata,
  });
}

// The cognitive-complexity limit that marks a callable complex enough to need a "why" comment. 15 is the retired
// `complexity.cognitive` rule's default, so default scans keep the same gate; no profile or config value moves it.
const COMPLEX_CONTEXT_COGNITIVE_LIMIT = 15;

/**
 * Determines whether `block` crosses any complexity threshold that requires a rationale comment.
 *
 * @param block - Function block providing line count and optional complexity metrics (falling back to baseline metrics if absent).
 * @param config - Active analyzer configuration supplying `size.function-length` and `complexity.cyclomatic` limits.
 * @returns `true` if `block` exceeds a configured length or cyclomatic limit, the fixed cognitive limit, or nesting depth 3.
 */
function isComplexContextCandidate(block: FunctionBlock, config: Config): boolean {
  // A legacy span-only caller cannot reparse here, so it receives the same neutral fallback as block rules.
  const sharedComplexityMetrics = block.complexityMetrics ?? baseComplexityMetrics();
  return (
    block.codeLineCount > threshold(config, "size.function-length", 200) ||
    sharedComplexityMetrics.cyclomatic > threshold(config, "complexity.cyclomatic", 15) ||
    sharedComplexityMetrics.cognitive > COMPLEX_CONTEXT_COGNITIVE_LIMIT ||
    sharedComplexityMetrics.maximumControlFlowNesting > 3
  );
}

/**
 * Checks whether `text` contains an accepted rationale marker for the callable named `functionName`.
 * Direct markers pass alone; constraint markers also require at least four word occurrences absent from `functionName`.
 *
 * @param text - Comment text evaluated for direct or constraint-based rationale phrasing.
 * @param functionName - Callable name whose words are excluded when counting extra words for constraint markers.
 * @returns `true` when `text` matches a direct rationale marker or a constraint marker with enough extra prose words.
 */
function hasComplexWhyMarker(text: string, functionName: string): boolean {
  if (/\b(?:because|why|intentional|trade-?off|compat(?:ibility|ible)?|avoid|preserve)\b|\b(?:due to|so that|in order to|required by)\b/i.test(text)) {
    return true;
  }
  return /\b(?:must|never|always|only|otherwise|instead|unless|since|cannot|to avoid|to keep|needs to)\b/i.test(text) && saysMoreThanTheName(text, functionName);
}

// Threshold of extra words, beyond the function name's own, before a constraint word counts as rationale: four,
// because a one-line paraphrase of a function name rarely adds that many.
const RATIONALE_MINIMUM_EXTRA_WORDS = 4;

/**
 * Checks whether comment prose (excluding tag lines such as `@param`) adds enough vocabulary beyond `functionName`.
 * Serves as a prerequisite for accepting constraint words as rationale instead of a bare name paraphrase.
 *
 * @param text - Raw comment text whose non-tag lines are tokenized into lowercase words.
 * @param functionName - CamelCase or delimited callable name split into words excluded from the extra-word count.
 * @returns `true` when the prose contains at least `RATIONALE_MINIMUM_EXTRA_WORDS` words absent from `functionName`.
 */
function saysMoreThanTheName(text: string, functionName: string): boolean {
  const nameWords = new Set(functionName.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  const prose = text.split("\n").filter((line) => !/^\s*(?:\*\s*)?@/.test(line)).join(" ");
  const extraWords = (prose.toLowerCase().match(/[a-z][a-z'-]*/g) ?? []).filter((word) => !nameWords.has(word));
  return extraWords.length >= RATIONALE_MINIMUM_EXTRA_WORDS;
}

/**
 * Checks whether `text` contains a whole-word side-effect marker, regardless of case.
 * A side-effect signal with no matching marker qualifies for the missing-side-effect finding.
 *
 * @param text - Comment text searched for side-effect verbs and target keywords.
 * @returns `true` when `text` names an observable side effect such as writes, reads, mutates, spawns, network, filesystem, or environment.
 */
function hasSideEffectMarker(text: string): boolean {
  return /\b(?:writes|reads|persists|mutates|starts|spawns|network|filesystem|environment)\b/i.test(text);
}

/**
 * Checks whether the supplied comment text contains a word that counts as a public contract marker.
 *
 * @param text - Comment text tested case-insensitively for contract and invariant vocabulary.
 * @returns `true` when `text` includes an accepted invariant, contract, schema, fingerprint, or determinism marker.
 */
function hasInvariantMarker(text: string): boolean {
  return /\b(?:invariant|contract|must|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

const SIDE_EFFECT_BODY_PATTERNS = [
  /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|mkdir(?:Sync)?|rm(?:Sync)?|rename(?:Sync)?|createWriteStream)\s*\(/,
  /\bprocess\.chdir\s*\(/,
  /\bprocess\.env\.[A-Za-z0-9_]+\s*=/,
  /\b(?:response|res)\.(?:write|end|setHeader|writeHead)\s*\(/,
  /\bcreateServer\s*\(|\.listen\s*\(/,
] as const;

/**
 * Determines whether a callable has externally observable side effects via body patterns or naming conventions.
 * Checks `SIDE_EFFECT_BODY_PATTERNS`, process execution calls, and `write`/`recordHistory`/`startDashboard` name prefixes.
 *
 * @param name - Callable identifier checked against side-effect-implying name prefixes.
 * @param body - Masked function body searched for filesystem, process, environment, or HTTP/server calls.
 * @returns `true` when either a body call pattern or a matching name prefix signals an external effect.
 */
function hasSideEffectSignal(name: string, body: string): boolean {
  return SIDE_EFFECT_BODY_PATTERNS.some((pattern) => pattern.test(body)) || hasProcessExecutionCall(body) || /^(?:write|recordHistory|startDashboard)\b/.test(name);
}

/**
 * Detects child-process execution calls inside masked function body text so literal contents cannot count as process calls.
 * Matches `exec`, `execFile`, or `spawn` (including `Sync` forms) when unprefixed or qualified with `child_process`, `childProcess`, or `cp`.
 *
 * @param body - Masked function body searched while excluding member calls such as `/re/.exec(line)`.
 * @returns `true` for a qualifying process-execution call, or `false` when no match qualifies.
 */
function hasProcessExecutionCall(body: string): boolean {
  for (const match of body.matchAll(/\b(?:(child_process|childProcess|cp)\.)?(?:exec|execFile|spawn)(?:Sync)?\s*\(/g)) {
    if (match[1] !== undefined || body[(match.index ?? 0) - 1] !== ".") {
      return true;
    }
  }
  return false;
}

/**
 * Searches both the callable name and body for vocabulary tied to the analyser's stable contracts.
 * Matches terms such as `fingerprint`, `schemaVersion`, `baseline`, `AnalysisReport`, `Finding`, `deterministic`, `dedupe`, and `sort`.
 *
 * @param block - Function block supplying the symbol name and code body to scan.
 * @returns `true` on a case-insensitive contract signal match so the caller can check the comment for an invariant marker.
 */
function hasInvariantFunctionSignal(block: FunctionBlock): boolean {
  const signalText = [block.name, block.codeBody].join("\n");
  return /\b(?:fingerprint|schemaVersion|baseline|AnalysisReport|Finding|stable sort|deterministic|dedupe|sort)\b/i.test(signalText);
}

/**
 * Checks whether `declaration.name` or its interface block text contains public-contract vocabulary.
 * A match makes the interface eligible for an invariant-documentation check.
 *
 * @param lines - Full file lines from which the interface declaration block is extracted.
 * @param declaration - Interface declaration metadata providing the name and starting line number.
 * @returns `true` when the interface name or body references contract terms such as `fingerprint`, `baseline`, `report`, or `deterministic`.
 */
function hasInvariantInterfaceSignal(lines: string[], declaration: CommentedDeclaration): boolean {
  const blockText = declarationBlockText(lines, declaration.line);
  const signalText = `${declaration.name}\n${blockText}`;
  return /\b(?:fingerprint|schemaVersion|baseline|report|Finding|AnalysisReport|Baseline|stable|deterministic)\b/i.test(signalText);
}

/**
 * Collects declaration lines starting at `line` until the closing `}` line for interface vocabulary checks.
 *
 * @param lines - Full array of source lines for the file.
 * @param line - One-based line number where the declaration starts.
 * @returns Joined slice of lines from `line` through the first trimmed `}` line, inclusive.
 */
function declarationBlockText(lines: string[], line: number): string {
  const start = Math.max(0, line - 1);
  const collected: string[] = [];
  for (let index = start; index < lines.length; index += 1) {
    const current = lines[index] ?? "";
    collected.push(current);
    if (current.trim() === "}") {
      break;
    }
  }
  return collected.join("\n");
}
