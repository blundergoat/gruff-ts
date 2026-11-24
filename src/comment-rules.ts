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

/**
 * Runs the comment-quality checks using the source text, parsed comments, declaration blocks, and configuration in `input`.
 * Shares parsed inputs so that all checks resolve against the same source locations.
 *
 * @param input - Bundle containing the file identity, source texts, parsed blocks and comments, config, and findings collector.
 * @returns Nothing. Appends findings for violations of the comment-quality contract to `input.findings`.
 */
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

/**
 * Checks leading function comments from `input` against function context rules, skipping missing or signature-only comments.
 *
 * @param input - Bundle providing file identity, source lines, parsed comments, function blocks, config, and findings collector.
 * @returns Nothing. Appends context findings for qualifying function comments to `input.findings`.
 */
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

/**
 * Combines callable blocks and exported interfaces into one homogeneous list for comment-quality rules.
 * Test blocks are excluded because their test description serves as the documentation.
 *
 * @param blocks - Parsed function blocks from the source file, including test blocks that will be filtered out.
 * @param interfaces - Exported interface declarations extracted from the source file.
 * @returns Ordered commented declaration descriptors covering non-test functions and exported interfaces.
 */
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

/**
 * Finds the first leading task marker in the recorded comment body, skipping mid-sentence mentions and fenced lines in block comments.
 * A marker may follow a list or quote prefix.
 *
 * @param source - Full file text used to slice block comment contents.
 * @param comment - Comment record whose body lines are inspected for a leading marker.
 * @returns Uppercase marker spelling for a consistent finding message, or `undefined` when no body line introduces a task.
 */
function todoMarker(source: string, comment: CommentRecord): string | undefined {
  for (const line of commentBodyLines(source, comment)) {
    const marker = leadingTodoMarker(line);
    if (marker) {
      return marker;
    }
  }
  return undefined;
}

/**
 * Extracts normalized body lines for a comment while stripping block decoration and surrounding whitespace.
 * Omits fenced code delimiters and their contents to ignore marker examples inside documentation.
 *
 * @param source - Full file text used to read block comment contents via `comment` offsets.
 * @param comment - Parsed comment record, either line or block.
 * @returns Body lines from `comment.text` for line comments or unfenced stripped lines sliced from `source` for block comments.
 */
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

/**
 * Extracts a leading task marker from a comment body line, optionally after a list bullet or greater-than quote prefix.
 * The marker must end the line or be followed by a colon, opening parenthesis, hyphen, or whitespace.
 *
 * @param line - Single stripped comment body line to inspect.
 * @returns Uppercase marker name when present with an allowed separator, or `undefined` otherwise.
 */
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

/**
 * Checks whether task comment text contains a built-in tracking reference or matches any configured project token.
 * With no project patterns, only the built-in forms qualify.
 *
 * @param text - Comment text to test for a URL, issue number, date, owner tag, or custom tracking token.
 * @param trackingTokens - Extra project regexes; testing a global or sticky pattern can mutate its `lastIndex`.
 * @returns `true` when `text` matches a built-in tracking form or any pattern in `trackingTokens`, `false` otherwise.
 */
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

/**
 * Collects standalone non-TypeScript suppressions explained by adjacent preceding line comments.
 * Blank lines, code, block or trailing comments, and recognized suppressions break the run so rationale stays local.
 *
 * @param source - Full file text used to verify whether each comment starts on its own line.
 * @param comments - Parsed comments in source order.
 * @param trackingTokens - Extra rationale patterns; testing global or sticky regexes can change their `lastIndex`.
 * @returns Suppression comment records with attached preceding rationale, or an empty set when none qualify.
 */
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

/**
 * Determines whether a comment begins on a line with only leading whitespace before it.
 * A trailing comment breaks the run of standalone comments that can supply suppression rationale.
 *
 * @param source - Full file text containing the comment.
 * @param commentStart - Zero-based character offset where the comment begins in `source`.
 * @returns `true` when text between the preceding newline and `commentStart` is only whitespace.
 */
function startsItsLine(source: string, commentStart: number): boolean {
  const lineStart = source.lastIndexOf("\n", commentStart - 1) + 1;
  return source.slice(lineStart, commentStart).trim() === "";
}

/**
 * Identifies a supported linter or coverage suppression keyword in comment text, excluding TypeScript directives.
 * TypeScript ignore, expect-error, nocheck, and check directives yield `undefined` so the TypeScript-specific check handles them.
 *
 * @param text - Comment text to scan for a supported suppression directive.
 * @returns Matched suppression keyword, or `undefined` when absent or handled as a TypeScript directive.
 */
function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

/**
 * Checks whether suppression comment text contains an explanatory rationale cue, issue reference, URL, or tracking token.
 *
 * @param text - Comment text to test for rationale phrases, `reason:` labels, issue numbers, URLs, or custom patterns.
 * @param trackingTokens - Project tracking regexes; testing a global or sticky pattern can change its `lastIndex`.
 * @returns `true` when `text` matches any built-in rationale cue or pattern in `trackingTokens`.
 */
export function hasSuppressionRationale(text: string, trackingTokens: readonly RegExp[] = []): boolean {
  return /\b(?:because|intentional|false positive|tracked in|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || trackingTokens.some((token) => token.test(text));
}

/**
 * Checks whether a declaration comment merely restates its signature instead of adding context.
 * Context cues exempt the comment; otherwise empty remaining words, a name match, or one extra trailing word counts as restating.
 *
 * @param text - Comment text to evaluate against the declaration name.
 * @param name - Identifier name of the commented declaration.
 * @param kind - Declaration kind used to exclude generic kind words before comparing.
 * @returns `false` when context cues are present; otherwise `true` if remaining words only match `name` (with at most one extra word).
 */
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

/**
 * Splits comment text into identifier-style words for comparison with a declaration name.
 * An empty list leaves the comparator with no words to distinguish the comment from the signature.
 *
 * @param text - Raw comment text to tokenize and split on identifier boundaries.
 * @returns Non-empty word tokens extracted from `text`.
 */
function normalizedCommentWords(text: string): string[] {
  return text
    .replace(/`/g, " ")
    .replace(/[^A-Za-z0-9_$]+/g, " ")
    .trim()
    .split(/\s+/)
    .flatMap(splitIdentifierWords)
    .filter(Boolean);
}

/**
 * Builds the stop-word set that filters out grammatical scaffolding before name comparison.
 * Includes the declaration kind itself so a kind-and-name pair is judged on the name alone.
 *
 * @param kind - Declaration kind added to the generic scaffolding words.
 * @returns Lowercase stop words to strip from normalized comment words.
 */
function restatementStopWords(kind: CommentedDeclaration["kind"]): Set<string> {
  return new Set(["a", "an", "the", "this", "that", "function", "method", "helper", "type", "declaration", kind]);
}

/**
 * Strips a trailing `s` from words longer than three characters for crude plural normalization in restatement detection.
 * Covers pairs such as `findings`/`finding` and `imports`/`import`.
 *
 * @param word - Normalized word token to stem.
 * @returns `word` without its trailing `s` when length exceeds 3, or `word` unchanged otherwise.
 */
function stemCommentWord(word: string): string {
  return word.length > 3 && word.endsWith("s") ? word.slice(0, -1) : word;
}

/**
 * Checks pointwise equality between two stemmed word lists for `isRestatingSignatureComment`.
 *
 * @param left - First stemmed word sequence to compare.
 * @param right - Second stemmed word sequence to compare.
 * @returns `true` when `left` and `right` have the same length and matching elements at every position.
 */
function sameWords(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((word, index) => word === right[index]);
}

/**
 * Checks whether a candidate comment contains a context keyword that exempts it from signature-restatement detection.
 *
 * @param text - Comment text to scan for rationale, contract, invariant, or side-effect keywords.
 * @returns `true` when `text` contains a recognized context keyword.
 */
function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

/**
 * Finds the closest preceding comment record for a declaration line when only blank lines separate them.
 *
 * @param lines - Source lines used to verify that the gap after the comment is empty.
 * @param comments - Ordered comment records from the file.
 * @param line - One-based line number of the declaration.
 * @returns Closest preceding comment separated only by blank lines, or `undefined` if none can attach.
 */
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

/**
 * Finds the leading comment for a function at a one-based line, excluding divider and file-overview comments.
 *
 * @param lines - Source lines passed to `leadingCommentForLine` and overview/divider detection.
 * @param comments - Ordered comment records from the file.
 * @param line - One-based declaration line of the function.
 * @returns Attached comment record, or `undefined` if none precedes the function or it is a divider or file overview.
 */
function functionLeadingComment(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  const comment = leadingCommentForLine(lines, comments, line);
  return comment && !isOverviewOrDividerCommentAt(lines, comment.line - 1, comment.endLine - 1, line - 1) ? comment : undefined;
}

/**
 * Checks that every one-based line in `[startLine, endLine)` is blank so `leadingCommentForLine` can confirm no code intervenes.
 * Tighter sibling of `hasOnlyBlankFixturePurposeGap` with an exclusive upper bound.
 *
 * @param lines - Zero-indexed source file lines.
 * @param startLine - Inclusive one-based start line of the gap to check.
 * @param endLine - Exclusive one-based end line of the gap to check.
 * @returns `true` when every line in `[startLine, endLine)` contains only whitespace.
 */
function hasOnlyBlankLines(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line < endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}
