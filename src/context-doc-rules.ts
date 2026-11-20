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

// Returns nothing. Appends stable findings for missing context in block to findings, using comment as the review text and finding location.
// Uses file for report paths and config for complexity thresholds; checks rationale, side effects, errors and invariants independently.
export function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
}

// Returns nothing. Appends an invariant-doc finding to findings when an interface declaration signals a contract that comment leaves unmarked.
// Uses file for the report location, lines for interface text, and comment for the finding line and review text.
// Other declaration kinds add nothing. The caller skips signature-restatement comments to avoid duplicate findings.
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

// Returns context-doc finding details for block by checking commentText against complexity, side-effect, error and invariant requirements.
// Uses config for configurable complexity limits; an empty list means none of these checks found a gap.
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

// Checks block against config's length and cyclomatic limits and the fixed cognitive and nesting limits.
// Returns missing-why finding details when commentText lacks a rationale marker for a complex block, or undefined otherwise.
function complexFunctionContextDocFinding(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails | undefined {
  if (!isComplexContextCandidate(block, config) || hasComplexWhyMarker(commentText, block.name)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-why-for-complex-code", `Complex function \`${block.name}\` has a comment, but it does not explain why the control flow exists.`, "Explain the tradeoff, compatibility reason, or invariant behind the complex control flow.", "complex-code");
}

// Returns missing-side-effect finding details for block when body or its name signals an effect and commentText lacks a marker.
// Returns undefined when no effect signal exists or commentText already contains a side-effect marker.
function sideEffectContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasSideEffectSignal(block.name, body) || hasSideEffectMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-side-effect-doc", `Function \`${block.name}\` performs side effects that its comment does not describe.`, "Name the observable side effect such as filesystem, process, environment, or network mutation.", "side-effect");
}

// Returns missing-error-behavior finding details for block when body matches throw at word boundaries and commentText lacks an @throws marker.
// Returns undefined when body has no such match or commentText contains the marker.
function errorBehaviorContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!/\bthrow\b/.test(body) || /@throws\b/.test(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-error-behavior-doc", `Function \`${block.name}\` throws, but its comment has no @throws tag.`, "Add an @throws tag that names each error the function throws and when.", "error-behavior");
}

// Returns missing-invariant finding details for block when its name or body signals a public contract and commentText lacks a marker.
// Returns undefined when no contract signal exists or commentText already contains an invariant marker.
function invariantContextDocFinding(block: FunctionBlock, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasInvariantFunctionSignal(block) || hasInvariantMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-invariant-doc", `Function \`${block.name}\` maintains a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, sorting, or determinism invariant.", "invariant");
}

// Returns context-doc finding details: symbol names the declaration, ruleId selects the rule, and message explains the gap.
// Uses remediation as repair advice and contextClass as the missing-context discriminator in metadata.
function contextDocDetails(symbol: string, ruleId: string, message: string, remediation: string, contextClass: string): ContextDocFindingDetails {
  return {
    symbol,
    ruleId,
    message,
    remediation,
    metadata: { contextClass },
  };
}

// Returns a stable finding from input's file, comment and rule details, anchored at the comment for documentation review.
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

// Returns whether block exceeds a length or cyclomatic limit from config, the fixed cognitive limit, or nesting depth three.
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

// Returns whether text contains an accepted rationale marker for the callable named functionName.
// Direct markers pass alone; constraint markers also require at least four word occurrences absent from the name.
function hasComplexWhyMarker(text: string, functionName: string): boolean {
  if (/\b(?:because|why|intentional|trade-?off|compat(?:ibility|ible)?|avoid|preserve)\b|\b(?:due to|so that|in order to|required by)\b/i.test(text)) {
    return true;
  }
  return /\b(?:must|never|always|only|otherwise|instead|unless|since|cannot|to avoid|to keep|needs to)\b/i.test(text) && saysMoreThanTheName(text, functionName);
}

// Threshold of extra words, beyond the function name's own, before a constraint word counts as rationale: four,
// because a one-line paraphrase of a function name rarely adds that many.
const RATIONALE_MINIMUM_EXTRA_WORDS = 4;

// True when the comment's prose, with tag lines such as @param set aside, keeps at least four words that are not
// words of the function name, a prerequisite for accepting constraint words as rationale.
function saysMoreThanTheName(text: string, functionName: string): boolean {
  const nameWords = new Set(functionName.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean));
  const prose = text.split("\n").filter((line) => !/^\s*(?:\*\s*)?@/.test(line)).join(" ");
  const extraWords = (prose.toLowerCase().match(/[a-z][a-z'-]*/g) ?? []).filter((word) => !nameWords.has(word));
  return extraWords.length >= RATIONALE_MINIMUM_EXTRA_WORDS;
}

// Returns true when the callable's comment contains a whole-word side effect marker, regardless of case.
// A side effect signal with no marker qualifies for the missing-side-effect finding.
function hasSideEffectMarker(text: string): boolean {
  return /\b(?:writes|reads|persists|mutates|starts|spawns|network|filesystem|environment)\b/i.test(text);
}

// Returns whether the supplied comment text contains a word that counts as a public contract marker.
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

// Two pathways: a body pattern match (writeFile, exec, listen, response.write, …) or a name
// pattern (functions starting with write/recordHistory/startDashboard). Either is sufficient
// evidence that the callable has externally observable effects.
function hasSideEffectSignal(name: string, body: string): boolean {
  return SIDE_EFFECT_BODY_PATTERNS.some((pattern) => pattern.test(body)) || hasProcessExecutionCall(body) || /^(?:write|recordHistory|startDashboard)\b/.test(name);
}

// Checks masked body text so that literal contents cannot count as process calls.
// Returns true for bare exec, execFile or spawn spellings, including Sync forms, or matches with child_process, childProcess or cp.
// A preceding dot excludes bare matches such as /re/.exec(line). Returns false when no match qualifies.
function hasProcessExecutionCall(body: string): boolean {
  for (const match of body.matchAll(/\b(?:(child_process|childProcess|cp)\.)?(?:exec|execFile|spawn)(?:Sync)?\s*\(/g)) {
    if (match[1] !== undefined || body[(match.index ?? 0) - 1] !== ".") {
      return true;
    }
  }
  return false;
}

// Searches both the callable name and body for vocabulary tied to the analyser's stable contracts
// (fingerprint, schemaVersion, baseline, AnalysisReport, Finding, stable sort, deterministic, dedupe, sort).
// Returns true on a case-insensitive match so the caller can check the comment for an invariant marker.
function hasInvariantFunctionSignal(block: FunctionBlock): boolean {
  const signalText = [block.name, block.codeBody].join("\n");
  return /\b(?:fingerprint|schemaVersion|baseline|AnalysisReport|Finding|stable sort|deterministic|dedupe|sort)\b/i.test(signalText);
}

// Returns whether declaration.name or the text collected from lines at declaration.line contains public-contract vocabulary.
// A match makes the interface eligible for an invariant-documentation check.
function hasInvariantInterfaceSignal(lines: string[], declaration: CommentedDeclaration): boolean {
  const blockText = declarationBlockText(lines, declaration.line);
  const signalText = `${declaration.name}\n${blockText}`;
  return /\b(?:fingerprint|schemaVersion|baseline|report|Finding|AnalysisReport|Baseline|stable|deterministic)\b/i.test(signalText);
}

// Collects lines from the declaration until the first `}` at column 0 - used to feed the interface
// body to vocabulary detectors. A more precise parser would help but is unnecessary for word matches.
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
