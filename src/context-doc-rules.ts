// Context-doc rules: emit findings when a function or interface comment exists but does not
// describe the WHY (complex control flow), side effects, error behavior, or public-contract
// invariants the implementation carries. Each rule reports a stable, deterministic finding.
import { approximateNpath, functionBodyContent, type FunctionBlock, maxNestingDepth } from "./blocks.ts";
import { type CommentRecord } from "./comment-scanner.ts";
import { threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { countMatches } from "./text-scans.ts";
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

// Materialises one finding per missing context class. Each callable can theoretically produce
// four (complex, side-effect, error-behavior, invariant) — the four classes are independent signals.
// Reports each detected gap as a stable doc-context finding.
export function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
}

/*
 * Interface-only context-doc rule. The caller is responsible for skipping signature-restatement
 * comments so the useless-docblock rule's stable finding doesn't get duplicated by this one.
 * Reports `docs.missing-invariant-doc` for interfaces that carry public-contract signals.
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

// Evaluates four context classes independently — collected into a list rather than emitted directly
// so the caller can apply a single stable mapping over them.
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

// Requires "why" context only after callable complexity crosses the configured threshold.
function complexFunctionContextDocFinding(block: FunctionBlock, commentText: string, config: Config): ContextDocFindingDetails | undefined {
  if (!isComplexContextCandidate(block, config) || hasComplexWhyMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-why-for-complex-code", `Complex function \`${block.name}\` has a comment, but it does not explain why the control flow exists.`, "Explain the tradeoff, compatibility reason, or invariant behind the complex control flow.", "complex-code");
}

// Documents externally observable mutations when the comment does not mention them.
function sideEffectContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasSideEffectSignal(block.name, body) || hasSideEffectMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-side-effect-doc", `Function \`${block.name}\` performs side effects that its comment does not describe.`, "Name the observable side effect such as filesystem, process, environment, or network mutation.", "side-effect");
}

// Keeps thrown, diagnostic, and recovery behavior visible in maintainer comments.
function errorBehaviorContextDocFinding(block: FunctionBlock, body: string, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasErrorBehaviorSignal(body) || hasErrorBehaviorMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-error-behavior-doc", `Function \`${block.name}\` has error behavior that its comment does not describe.`, "Document thrown errors, diagnostics, exits, reports, or recovery behavior.", "error-behavior");
}

// Protects schema and fingerprint invariants from becoming implicit tribal knowledge.
function invariantContextDocFinding(block: FunctionBlock, commentText: string): ContextDocFindingDetails | undefined {
  if (!hasInvariantFunctionSignal(block) || hasInvariantMarker(commentText)) {
    return undefined;
  }
  return contextDocDetails(block.name, "docs.missing-invariant-doc", `Function \`${block.name}\` maintains a public contract that its comment does not describe.`, "Document the schema, fingerprint, baseline, sorting, or determinism invariant.", "invariant");
}

// Bundles the per-context-class metadata so the four detector helpers share one stable shape.
// `contextClass` is the discriminator surfaced in finding metadata.
function contextDocDetails(symbol: string, ruleId: string, message: string, remediation: string, contextClass: string): ContextDocFindingDetails {
  return {
    symbol,
    ruleId,
    message,
    remediation,
    metadata: { contextClass },
  };
}

// Anchors every context-doc finding at the comment line (not the declaration line) so the
// reviewer's eye lands on the documentation that needs editing. Reports a stable finding.
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

// Composite gate: any one of size, cyclomatic, cognitive, NPath, or nesting depth crossing the
// configured stable threshold qualifies a callable as "complex enough to need WHY context".
function isComplexContextCandidate(block: FunctionBlock, config: Config): boolean {
  const cyclomatic = countMatches(block.codeBody, /\b(if|else if|switch|case|for|while|catch)\b|\?|&&|\|\|/g) + 1;
  const cognitive = cyclomatic + maxNestingDepth(block.codeBody);
  const npath = approximateNpath(functionBodyContent(block.codeBody));
  return (
    block.lineCount > threshold(config, "size.function-length", 200) ||
    cyclomatic > threshold(config, "complexity.cyclomatic", 15) ||
    cognitive > threshold(config, "complexity.cognitive", 15) ||
    npath.value > threshold(config, "complexity.npath", 200) ||
    maxNestingDepth(block.codeBody) > 3
  );
}

// Vocabulary list signalling "the comment explains why" — the missing-why rule passes when any
// listed word appears. Adding entries here loosens the rule; removing them tightens it.
function hasComplexWhyMarker(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve)\b/i.test(text);
}

// Vocabulary for "comment names a side effect". Pairs with `SIDE_EFFECT_BODY_PATTERNS` — if the
// body matches and none of these words appear, the missing-side-effect rule fires.
function hasSideEffectMarker(text: string): boolean {
  return /\b(?:writes|reads|persists|mutates|starts|spawns|network|filesystem|environment)\b/i.test(text);
}

// Vocabulary for "comment names error behaviour". Matches throws/reports/exits/swallows/fallback/
// recover and the multi-word "returns diagnostic". Pairs with `hasErrorBehaviorSignal`.
function hasErrorBehaviorMarker(text: string): boolean {
  return /\b(?:throws|returns diagnostic|reports|exits|swallows|fallback|recover)\b/i.test(text);
}

// Vocabulary for "comment names a public contract". Seven canonical words; the rule fires when
// the callable carries invariant signals (Finding/baseline/fingerprint references) but none of these.
function hasInvariantMarker(text: string): boolean {
  return /\b(?:invariant|contract|must|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

const SIDE_EFFECT_BODY_PATTERNS = [
  /\b(?:writeFile(?:Sync)?|appendFile(?:Sync)?|mkdir(?:Sync)?|rm(?:Sync)?|rename(?:Sync)?|createWriteStream)\s*\(/,
  /\bprocess\.chdir\s*\(/,
  /\bprocess\.env\.[A-Za-z0-9_]+\s*=/,
  /\b(?:exec|execFile|spawn)(?:Sync)?\s*\(/,
  /\b(?:response|res)\.(?:write|end|setHeader|writeHead)\s*\(/,
  /\bcreateServer\s*\(|\.listen\s*\(/,
] as const;

// Two pathways: a body pattern match (writeFile, exec, listen, response.write, …) or a name
// pattern (functions starting with write/recordHistory/startDashboard). Either is sufficient
// evidence that the callable has externally observable effects.
function hasSideEffectSignal(name: string, body: string): boolean {
  return SIDE_EFFECT_BODY_PATTERNS.some((pattern) => pattern.test(body)) || /^(?:write|recordHistory|startDashboard)\b/.test(name);
}

// Detects throw, catch, process.exit, diagnostic emission, or finding/diagnostic push patterns —
// the five places error behaviour can hide inside a callable body.
function hasErrorBehaviorSignal(body: string): boolean {
  return /\bthrow\b|\bcatch\b|\bprocess\.exit\s*\(|\bdiagnosticType\s*:|\b(?:findings|diagnostics)\.push\s*\(/.test(body);
}

// Searches both the callable name and body for vocabulary tied to the analyser's stable contracts
// (fingerprint, schemaVersion, baseline, AnalysisReport, Finding, dedupe, sort). Any match
// triggers the invariant-doc rule's expectation that the comment will name an invariant.
function hasInvariantFunctionSignal(block: FunctionBlock): boolean {
  const signalText = [block.name, block.codeBody].join("\n");
  return /\b(?:fingerprint|schemaVersion|baseline|AnalysisReport|Finding|stable sort|deterministic|dedupe|sort)\b/i.test(signalText);
}

// Same idea as `hasInvariantFunctionSignal` but reads the interface body via `declarationBlockText`.
// The contract vocabulary is slightly wider (`Baseline`, `report`) because interfaces often shape
// public report types.
function hasInvariantInterfaceSignal(lines: string[], declaration: CommentedDeclaration): boolean {
  const blockText = declarationBlockText(lines, declaration.line);
  const signalText = `${declaration.name}\n${blockText}`;
  return /\b(?:fingerprint|schemaVersion|baseline|report|Finding|AnalysisReport|Baseline|stable|deterministic)\b/i.test(signalText);
}

// Collects lines from the declaration until the first `}` at column 0 — used to feed the interface
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
