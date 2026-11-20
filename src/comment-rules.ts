// Every comment-quality, fixture-purpose and context-doc rule. The orchestrator
// `analyseCommentQualityRules` fans out per-comment / per-declaration / per-block passes that all
// share a stable, deterministic emission order.
import { type FunctionBlock } from "./blocks.ts";
import { combinedContextLineComment, type CommentRecord, isOverviewOrDividerCommentAt } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { type ExportedDeclaration, interfaceDeclarations } from "./doc-rules.ts";
import { type CommentedDeclaration, pushDeclarationContextFindings, pushFunctionContextFindings } from "./context-doc-rules.ts";
import { makeFinding } from "./findings.ts";
import { splitIdentifierWords } from "./findings-helpers.ts";
import { pushFixturePurposeFindings } from "./fixture-purpose-rules.ts";
import type { Config, Finding } from "./types.ts";

type CommentQualityRuleInput = {
  file: SourceFile;
  source: string;
  codeSource: string;
  blocks: FunctionBlock[];
  comments: CommentRecord[];
  config: Config;
  findings: Finding[];
};

type FunctionContextCommentQualityInput = {
  file: SourceFile;
  lines: string[];
  comments: CommentRecord[];
  blocks: FunctionBlock[];
  config: Config;
  findings: Finding[];
};

// Runs the comment-quality checks using the source text, parsed comments, declaration blocks and configuration in input.
// Appends findings for violations of the comment-quality contract to input.findings and returns nothing.
// Shares parsed inputs so that the checks use the same source locations.
export function analyseCommentQualityRules(input: CommentQualityRuleInput): void {
  const { file, source, codeSource, blocks, comments, config, findings } = input;
  const lines = source.split(/\r?\n/);
  const declarations = commentedDeclarations(blocks, interfaceDeclarations(source, codeSource));

  analyseStandaloneCommentQuality(file, source, comments, findings, config.trackingTokens);
  analyseCommentedDeclarationQuality(file, lines, comments, declarations, findings);
  analyseFunctionContextCommentQuality({ file, lines, comments, blocks, config, findings });
  pushFixturePurposeFindings({ file, source, codeSource, lines, comments, blocks, findings });
}

/**
 * Checks comments for task tracking and suppression rationale in stable input order.
 *
 * @param file - source file whose path identifies violations
 * @param source - file text used to check marker context and locate attached rationale
 * @param comments - parsed comments to check, including those that document no declaration
 * @param findings - shared list to which violations are appended
 * @param trackingTokens - patterns for accepted tracking references. Testing a global or sticky pattern can change its lastIndex.
 * @returns nothing. Appends violations to findings.
 */
function analyseStandaloneCommentQuality(file: SourceFile, source: string, comments: CommentRecord[], findings: Finding[], trackingTokens: readonly RegExp[]): void {
  const attachedRationale = directivesWithAttachedRationale(source, comments, trackingTokens);
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, source, comment, findings, trackingTokens);
    pushSuppressionWithoutRationaleFinding(file, comment, attachedRationale.has(comment), findings, trackingTokens);
  }
}

/**
 * Run declaration context rules that need metadata and a leading comment, in stable input order.
 * Skip comments that only restate the signature because they supply no context to judge.
 *
 * @param file - Source file to which findings are attributed.
 * @param lines - Source lines used to locate each declaration's leading comment.
 * @param comments - Comment records used to find and assemble the declaration's context.
 * @param declarations - Ordered declarations to check.
 * @param findings - Collector that receives context findings.
 * @returns Nothing. Appends findings for declarations with a leading comment that supplies context.
 */
function analyseCommentedDeclarationQuality(file: SourceFile, lines: string[], comments: CommentRecord[], declarations: CommentedDeclaration[], findings: Finding[]): void {
  for (const declaration of declarations) {
    const comment = declaration.kind === "function" ? functionLeadingComment(lines, comments, declaration.line) : leadingCommentForLine(lines, comments, declaration.line);
    if (!comment) {
      continue;
    }
    if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
      pushDeclarationContextFindings(file, lines, declaration, combinedContextLineComment(comments, comment), findings);
    }
  }
}

// Checks function comments from input's source lines, comments and blocks, using its file identity and configuration.
// Appends context findings to input.findings, skipping missing or signature-only comments; returns nothing.
function analyseFunctionContextCommentQuality(input: FunctionContextCommentQualityInput): void {
  const { file, lines, comments, blocks, config, findings } = input;
  for (const block of blocks) {
    const comment = functionLeadingComment(lines, comments, block.declarationLine);
    if (!comment || isRestatingSignatureComment(comment.text, block.name, "function")) {
      continue;
    }
    pushFunctionContextFindings(file, block, combinedContextLineComment(comments, comment), config, findings);
  }
}

// Combines callable blocks and exported interfaces into one homogeneous list for the comment-quality
// rules. Test blocks are excluded because their test description is the documentation.
function commentedDeclarations(blocks: FunctionBlock[], interfaces: ExportedDeclaration[]): CommentedDeclaration[] {
  return [
    ...blocks
      .filter((block) => !block.isTest)
      .map((block) => ({ kind: "function" as const, name: block.name, line: block.declarationLine, isPublic: block.isPublic })),
    ...interfaces.map((declaration) => ({ kind: "interface" as const, name: declaration.name, line: declaration.line, isPublic: true })),
  ];
}

/**
 * Flags task comments without tracking and keeps the marker keyword in stable metadata so consumers can group by marker kind.
 *
 * @param file - source file whose display path anchors the finding
 * @param source - original source used to identify the task marker
 * @param comment - candidate comment whose text is checked for tracking and whose line anchors the finding
 * @param findings - collector for docs.todo-without-tracking findings
 * @param trackingTokens - project patterns used alongside built-in forms. Testing a global or sticky pattern can change its lastIndex.
 * @returns Nothing. It appends one finding for a comment with a recognized marker and no accepted tracking.
 */
function pushTodoWithoutTrackingFinding(file: SourceFile, source: string, comment: CommentRecord, findings: Finding[], trackingTokens: readonly RegExp[]): void {
  const marker = todoMarker(source, comment);
  if (!marker || hasTodoTracking(comment.text, trackingTokens)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.todo-without-tracking",
      message: `${marker} comment is missing an issue, owner, date, ADR, or task reference.`,
      filePath: file.displayPath,
      line: comment.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "high",
      remediation: "Attach a tracking URL, issue id, owner, date, ADR, or .goat-flow task reference.",
      metadata: { marker },
    }),
  );
}

// Finds the first leading task marker in the recorded comment body, using file text for block comments.
// Returns its uppercase spelling for a consistent finding message, or undefined when no body line introduces a task.
// A marker can follow a list or quote prefix. Mid-sentence mentions do not count. Fenced lines in block comments are skipped.
function todoMarker(source: string, comment: CommentRecord): string | undefined {
  for (const line of commentBodyLines(source, comment)) {
    const marker = leadingTodoMarker(line);
    if (marker) {
      return marker;
    }
  }
  return undefined;
}

// Returns body lines for comment, using its offsets in source to read block text and its stored text for a line comment.
// Strips block decoration and surrounding whitespace, and omits fence delimiters and their contents to ignore marker examples.
function commentBodyLines(source: string, comment: CommentRecord): string[] {
  if (comment.kind === "line") {
    return [comment.text];
  }
  const body = source.slice(comment.startIndex + 2, Math.max(comment.startIndex + 2, comment.endIndex - 1));
  const lines: string[] = [];
  let isInsideFence = false;
  for (const rawLine of body.split(/\r?\n/)) {
    const line = rawLine.replace(/^[ \t]*\*[ \t]?/, "").trim();
    if (line.startsWith("```")) {
      isInsideFence = !isInsideFence;
      continue;
    }
    if (!isInsideFence) {
      lines.push(line);
    }
  }
  return lines;
}

// Returns the uppercase marker from a comment body line that starts with a task marker, optionally after a list bullet or greater-than quote prefix.
// The marker must end the line or be followed by a colon, opening parenthesis, hyphen, or whitespace.
// Returns undefined if the line has no marker in that position or the marker lacks an allowed separator.
function leadingTodoMarker(line: string): string | undefined {
  const match = line.match(/^(?:(?:[-*>]|\d+[.)])\s+)?(TODO|FIXME|HACK|XXX)\b(.*)$/i);
  const marker = match?.[1];
  if (!marker) {
    return undefined;
  }
  const rest = match?.[2] ?? "";
  return rest === "" || /^[\s:(-]/.test(rest) ? marker.toUpperCase() : undefined;
}

const TODO_TRACKING_PATTERNS = [
  /https?:\/\//i,
  /(?:^|\s)#\d+\b/,
  /\bGH-\d+\b/i,
  /\b\d{4}-\d{2}-\d{2}\b/,
  /\bowner\s*:/i,
] as const;

// Returns true when the task comment text matches a built-in tracking form or one of the patterns from allowlists.trackingTokens.
// With no project patterns, only the built-in forms qualify. Testing a global or sticky pattern can change its lastIndex.
function hasTodoTracking(text: string, trackingTokens: readonly RegExp[] = []): boolean {
  return TODO_TRACKING_PATTERNS.some((pattern) => pattern.test(text)) || trackingTokens.some((token) => token.test(text));
}

/**
 * Flags tool suppressions that lack a rationale on the directive or in attached line comments. TypeScript directives are excluded.
 *
 * @param file - source file whose display path anchors the finding
 * @param comment - candidate directive text and source line
 * @param hasAttachedRationale - whether an attached comment already explains the suppression
 * @param findings - collector for the stable docs.suppression-without-rationale finding
 * @param trackingTokens - project patterns accepted as rationale on the directive. A global or sticky pattern can have its lastIndex changed.
 * @returns Nothing. It appends one finding for a recognized suppression with no accepted rationale.
 */
function pushSuppressionWithoutRationaleFinding(file: SourceFile, comment: CommentRecord, hasAttachedRationale: boolean, findings: Finding[], trackingTokens: readonly RegExp[]): void {
  const suppression = suppressionDirective(comment.text);
  if (!suppression || hasAttachedRationale || hasSuppressionRationale(comment.text, trackingTokens)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.suppression-without-rationale",
      message: `${suppression} suppression is missing a maintainer rationale.`,
      filePath: file.displayPath,
      line: comment.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      remediation: "Explain why the suppression is intentional, a false positive, or tracked elsewhere.",
      metadata: { suppression },
    }),
  );
}

// Returns standalone non-TypeScript suppressions explained by adjacent preceding line comments, or an empty set when none qualify.
// Pass file text to identify standalone comments and records in source order. Extra rationale patterns can change lastIndex if global or sticky.
// Blank lines, code, block or trailing comments and recognized non-TypeScript suppressions break the run so that rationale stays local.
function directivesWithAttachedRationale(source: string, comments: readonly CommentRecord[], trackingTokens: readonly RegExp[]): Set<CommentRecord> {
  const attached = new Set<CommentRecord>();
  let blockEndLine = -1;
  let hasBlockRationale = false;
  for (const comment of comments) {
    const isStandalone = comment.kind === "line" && startsItsLine(source, comment.startIndex);
    const isDirective = suppressionDirective(comment.text) !== undefined;
    const continuesBlock = isStandalone && comment.line === blockEndLine + 1;
    if (isDirective && continuesBlock && hasBlockRationale) {
      attached.add(comment);
    }
    if (isStandalone && !isDirective) {
      hasBlockRationale = (continuesBlock && hasBlockRationale) || hasSuppressionRationale(comment.text, trackingTokens);
      blockEndLine = comment.line;
    } else {
      blockEndLine = -1;
      hasBlockRationale = false;
    }
  }
  return attached;
}

// Returns true when the file text before the comment offset on that line is only whitespace.
// A trailing comment breaks the run of standalone comments that can supply suppression rationale.
function startsItsLine(source: string, commentStart: number): boolean {
  const lineStart = source.lastIndexOf("\n", commentStart - 1) + 1;
  return source.slice(lineStart, commentStart).trim() === "";
}

// Returns the supported suppression keyword found in the comment text, or undefined when there is no match.
// TypeScript ignore, expect-error, nocheck, and check directives in the text also yield undefined so the TypeScript-specific check handles them.
function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

// Returns true when the suppression comment text matches a rationale cue such as an explanatory phrase or a reason label.
// Numbered issue references, HTTP or HTTPS prefixes, and project tracking patterns also count.
// Testing a global or sticky tracking pattern can change its lastIndex.
export function hasSuppressionRationale(text: string, trackingTokens: readonly RegExp[] = []): boolean {
  return /\b(?:because|intentional|false positive|tracked in|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || trackingTokens.some((token) => token.test(text));
}

// Compares the comment text with the declaration name, using the declaration kind to filter generic words from the comment.
// Returns false for context cues. Otherwise, returns true for no remaining words, a name match, or a match with one extra trailing word.
function isRestatingSignatureComment(text: string, name: string, kind: CommentedDeclaration["kind"]): boolean {
  if (hasUsefulCommentContext(text)) {
    return false;
  }
  const words = normalizedCommentWords(text).filter((word) => !restatementStopWords(kind).has(word)).map(stemCommentWord);
  const nameWords = splitIdentifierWords(name).map(stemCommentWord);
  if (words.length === 0) {
    return true;
  }
  if (sameWords(words, nameWords)) {
    return true;
  }
  return words.length <= nameWords.length + 1 && sameWords(words.slice(0, nameWords.length), nameWords);
}

// Returns the comment text as identifier-style words for comparison with the declaration name.
// An empty list leaves the comparator with no words to distinguish the comment from the signature.
function normalizedCommentWords(text: string): string[] {
  return text
    .replace(/`/g, " ")
    .replace(/[^A-Za-z0-9_$]+/g, " ")
    .trim()
    .split(/\s+/)
    .flatMap(splitIdentifierWords)
    .filter(Boolean);
}

// Stop-word list that filters out grammatical scaffolding before name comparison. Includes the
// declaration kind itself so a kind-and-name pair is judged on the name alone.
function restatementStopWords(kind: CommentedDeclaration["kind"]): Set<string> {
  return new Set(["a", "an", "the", "this", "that", "function", "method", "helper", "type", "declaration", kind]);
}

// Trailing-`s` stripping for words longer than 3 characters. Crude but adequate for restating-
// signature detection - covers `findings`/`finding`, `imports`/`import`, etc.
function stemCommentWord(word: string): string {
  return word.length > 3 && word.endsWith("s") ? word.slice(0, -1) : word;
}

// Pointwise equality between two stemmed word arrays. Used by `isRestatingSignatureComment` to
// compare the comment's first words against the declaration name's words.
function sameWords(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((word, index) => word === right[index]);
}

// Returns true when the candidate comment contains a context keyword that exempts it from the signature-restatement check.
function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

// Finds the closest preceding record in the ordered comment list for a declaration line in the source.
// Returns that record if only blank source lines separate it from the declaration, or undefined if no comment can be attached.
function leadingCommentForLine(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  for (let index = comments.length - 1; index >= 0; index -= 1) {
    const comment = comments[index];
    if (!comment || comment.endLine >= line) {
      continue;
    }
    if (hasOnlyBlankLines(lines, comment.endLine + 1, line - 1)) {
      return comment;
    }
    return undefined;
  }
  return undefined;
}

// Filters the candidate from leadingCommentForLine for a function at one-based line, using source lines and parsed comments.
// Returns that comment unless it is absent, a divider or a file overview, in which case it returns undefined.
function functionLeadingComment(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  const comment = leadingCommentForLine(lines, comments, line);
  return comment && !isOverviewOrDividerCommentAt(lines, comment.line - 1, comment.endLine - 1, line - 1) ? comment : undefined;
}

// Tighter sibling of `hasOnlyBlankFixturePurposeGap` - exclusive upper bound. Used by
// `leadingCommentForLine` to confirm no executable token sits between a comment and its declaration.
function hasOnlyBlankLines(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line < endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}
