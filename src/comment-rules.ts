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

/*
 * Coordinator for every comment-quality rule. Comments and declarations are parsed once, so every
 * sub-rule sees the same stable inputs.
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

/*
 * Two per-comment rules (task tracking, suppression rationale) that run on every comment regardless
 * of whether it documents a declaration, in a stable, deterministic order.
 */
function analyseStandaloneCommentQuality(file: SourceFile, source: string, comments: CommentRecord[], findings: Finding[], trackingTokens: readonly RegExp[]): void {
  const attachedRationale = directivesWithAttachedRationale(source, comments, trackingTokens);
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, source, comment, findings, trackingTokens);
    pushSuppressionWithoutRationaleFinding(file, comment, attachedRationale.has(comment), findings, trackingTokens);
  }
}

/*
 * Per-declaration context-doc rules that need both the declaration metadata and its leading comment,
 * run in stable declaration order. A comment that only restates the signature carries no context to
 * judge, so it is skipped.
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

// Function-only context-doc rule. Restating-signature comments are skipped first because they carry
// no context for these checks to judge.
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
// rules. Test blocks are excluded because their `test("…")` description is the documentation.
function commentedDeclarations(blocks: FunctionBlock[], interfaces: ExportedDeclaration[]): CommentedDeclaration[] {
  return [
    ...blocks
      .filter((block) => !block.isTest)
      .map((block) => ({ kind: "function" as const, name: block.name, line: block.declarationLine, isPublic: block.isPublic })),
    ...interfaces.map((declaration) => ({ kind: "interface" as const, name: declaration.name, line: declaration.line, isPublic: true })),
  ];
}

/*
 * One finding per comment containing an untracked task marker. The reported marker keyword is
 * preserved in stable metadata so consumers can group by marker kind. Reports the stable
 * untracked-task-marker finding when no tracking reference is attached.
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

// Four canonical task-marker words, returned in uppercase so the finding message reads consistently
// regardless of how the maintainer wrote them. A marker must INTRODUCE a comment body line - prose
// that merely mentions a marker word (quoted, backticked, or mid-sentence) stays quiet.
function todoMarker(source: string, comment: CommentRecord): string | undefined {
  for (const line of commentBodyLines(source, comment)) {
    const marker = leadingTodoMarker(line);
    if (marker) {
      return marker;
    }
  }
  return undefined;
}

// One body line per physical comment line: the trimmed `//` text, or each block-comment line with
// its `*` decoration stripped. Lines inside ``` fences are dropped so marker examples shown in
// doc comments cannot become findings.
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

// Leading-marker grammar: optional list bullet, the marker word, then a delimiter real markers use
// (":", "(", "-", whitespace, or end of line). Any other next character - a quote, slash, or
// backtick - means the line talks ABOUT a marker instead of being one.
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

// Five accepted tracking forms (URL, #123, GH-123, ISO date, `owner:`), plus any project token from
// `allowlists.trackingTokens`, so projects with different ticketing systems can comply without changing their conventions.
function hasTodoTracking(text: string, trackingTokens: readonly RegExp[] = []): boolean {
  return TODO_TRACKING_PATTERNS.some((pattern) => pattern.test(text)) || trackingTokens.some((token) => token.test(text));
}

/*
 * Targets `eslint-disable`, `biome-ignore`, coverage `istanbul ignore`, etc. when no maintainer
 * rationale is attached - the false-positive escape hatch is explicit because TS suppression
 * directives have their own dedicated rule. Reports the stable `docs.suppression-without-rationale` finding.
 * The rationale may sit on the directive itself or in the comment block attached above it.
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

/*
 * Directives whose rationale is written in the comment block attached above them. The block is an
 * unbroken run of standalone `//` lines ending on the line directly above a standalone directive; a
 * blank line, code, a trailing comment or another directive ends it, so a rationale is never borrowed
 * across them. Contract invariant: one pass in source order keeps the result deterministic.
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

// A comment starts its line when only whitespace precedes it; a comment after code annotates that code.
function startsItsLine(source: string, commentStart: number): boolean {
  const lineStart = source.lastIndexOf("\n", commentStart - 1) + 1;
  return source.slice(lineStart, commentStart).trim() === "";
}

// Returns the suppression keyword that triggered the rule. `@ts-*` directives are explicitly
// excluded - they have their own dedicated rule (`pushTsDirectiveFinding`).
function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

// Accepted rationale forms: explanatory keywords (because, intentional, false positive, tracked in), a GH-123
// reference, explicit `reason:`, a tracking URL, a #issue, or a project token from `allowlists.trackingTokens`.
export function hasSuppressionRationale(text: string, trackingTokens: readonly RegExp[] = []): boolean {
  return /\b(?:because|intentional|false positive|tracked in|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || trackingTokens.some((token) => token.test(text));
}

// Three-tier test: useful-context vocabulary short-circuits as "not restating"; identical
// word sequences are restating; near-identical sequences (one extra trailing word) are restating.
// The result keeps the context-doc rules off comments that carry nothing to judge.
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

// Strips backticks, splits on non-identifier characters, then further splits each fragment into
// identifier-style words. The flat list lets the comparator compare on a per-word basis.
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

// The shared "this comment carries real signal" vocabulary. Any match here means the comment is not
// a restatement of the signature.
function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

// Reverse scan through the comment list - the closest comment whose `endLine < line` wins, but
// only when nothing but blank lines sits between them. Anything else means the comment documents
// a different declaration.
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

// `leadingCommentForLine` for a function: a divider or the file's overview above it is not the
// function's comment (M13-T18), so the comment rules do not judge it as one.
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
