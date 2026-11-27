// Detects large test/fixture sources that need a purpose comment. Three candidate kinds in one
// pass - template-literal fixtures, generated array fixtures, and high-setup test blocks - then
// reports `docs.fixture-purpose-missing` for each candidate without a nearby explanation comment.
import { type FunctionBlock, setupLineCount } from "./blocks.ts";
import { combinedContextLineComment, type CommentRecord } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { isFixtureLikePath, isTestPath } from "./project-rules.ts";
import type { Finding } from "./types.ts";

// Below 12 lines, a fixture is short enough to read at a glance - requiring a purpose header
// would just be noise; above this threshold, the next reader needs the intent spelled out.
const FIXTURE_PURPOSE_MIN_LINES = 12;

// A potential `docs.fixture-purpose-missing` finding location. `targetKind` distinguishes
// template fixtures from generated fixtures so the metadata stays useful for downstream tooling.
interface FixturePurposeCandidate {
  line: number;
  symbol: string;
  targetKind: string;
  lineCount: number;
}

/*
 * Argument bundle for `pushFixturePurposeFindings`. The eight-field call surface is kept as a
 * stable struct so adding a new input does not silently break every per-block helper's positional
 * argument list.
 */
export interface FixturePurposeInput {
  file: SourceFile;
  source: string;
  codeSource: string;
  lines: string[];
  comments: CommentRecord[];
  blocks: FunctionBlock[];
  findings: Finding[];
}

/**
 * Appends `docs.fixture-purpose-missing` findings to `input.findings` for undocumented candidates in the parsed file context.
 * Files whose paths are neither tests nor fixture-like are ignored.
 *
 * @param input - File metadata, raw and code-only source text, lines, comments, function blocks, and target findings array.
 * @returns Nothing. Mutates `input.findings` by pushing any missing-purpose findings.
 */
export function pushFixturePurposeFindings(input: FixturePurposeInput): void {
  const { file, source, codeSource, lines, comments, blocks, findings } = input;
  if (!isTestPath(file.displayPath) && !isFixtureLikePath(file.displayPath)) {
    return;
  }
  for (const candidate of fixturePurposeCandidates(source, codeSource, blocks)) {
    if (hasFixturePurposeComment(lines, comments, candidate.line)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.fixture-purpose-missing",
        message: fixturePurposeMessage(candidate),
        filePath: file.displayPath,
        line: candidate.line,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: candidate.symbol,
        remediation: fixturePurposeRemediation(candidate),
        metadata: {
          targetKind: candidate.targetKind,
          fixtureLines: candidate.lineCount,
        },
      }),
    );
  }
}

/**
 * Builds the `docs.fixture-purpose-missing` diagnostic message for a candidate.
 * The message must name the test for `test-setup` candidates or locate other fixtures by the nearby call or declaration name.
 *
 * @param candidate - Fixture-purpose candidate providing `targetKind` and `symbol`.
 * @returns Formatted finding message describing the missing purpose comment.
 */
function fixturePurposeMessage(candidate: FixturePurposeCandidate): string {
  if (candidate.targetKind === "test-setup") {
    return `Test \`${candidate.symbol}\` builds a large fixture setup without a purpose comment above the test.`;
  }
  return `Large fixture source near \`${candidate.symbol}\` is missing a purpose comment.`;
}

/**
 * Builds the remediation guidance for a candidate's `targetKind`.
 * The recommended placement must be accepted by `hasFixturePurposeComment` so the fix can clear the finding.
 *
 * @param candidate - Fixture-purpose candidate whose `targetKind` selects test-setup or fixture placement guidance.
 * @returns Actionable remediation instruction explaining where to place the purpose comment.
 */
function fixturePurposeRemediation(candidate: FixturePurposeCandidate): string {
  if (candidate.targetKind === "test-setup") {
    return "Add a comment directly above the test declaration explaining what scanner path, regression, or fixture behavior this setup covers.";
  }
  return "Add a comment on or directly above the fixture explaining what scanner path, regression, or fixture behavior this source covers.";
}

/**
 * Finds unique fixture-purpose candidates within `source`'s line range across templates, generated arrays, and test setups.
 * Template and generated-array locations suppress overlapping test blocks.
 *
 * @param source - Full file text used to extract template literal contents and line bounds.
 * @param codeSource - Comment-stripped source text scanned for line-level fixture triggers.
 * @param blocks - Parsed function blocks evaluated for large test-setup blocks.
 * @returns Deduplicated candidates within `source` line bounds, or an empty array when none qualify.
 */
function fixturePurposeCandidates(source: string, codeSource: string, blocks: FunctionBlock[]): FixturePurposeCandidate[] {
  if (!hasFixturePurposeCandidateSignal(codeSource, blocks)) {
    return [];
  }
  const candidates: FixturePurposeCandidate[] = [];
  const seen = new Set<string>();
  const occupiedLines = new Set<number>();
  const lines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  const lineOffsets = sourceLineStartOffsets(source);

  codeLines.forEach((codeLine, index) => {
    const lineNumber = index + 1;
    const templateCandidate = fixtureTemplateCandidate(source, lineOffsets, codeLine, lineNumber);
    if (templateCandidate) {
      pushUniqueFixturePurposeCandidate(candidates, seen, templateCandidate);
      occupiedLines.add(templateCandidate.line);
    }
    const generatedCandidate = generatedFixtureCandidate(lines[index] ?? "", codeLine, lineNumber);
    if (generatedCandidate) {
      pushUniqueFixturePurposeCandidate(candidates, seen, generatedCandidate);
      occupiedLines.add(generatedCandidate.line);
    }
  });

  for (const candidate of fixtureTestBlockCandidates(blocks, occupiedLines)) {
    pushUniqueFixturePurposeCandidate(candidates, seen, candidate);
  }

  return candidates.filter((candidate) => candidate.line <= lines.length);
}

/**
 * Checks whether a file has a recognized fixture trigger or any test block so candidate extraction can proceed.
 * Returning `false` skips fixture-purpose candidate extraction for the whole file.
 *
 * @param codeSource - Comment-stripped source text checked for fixture helper calls or fixture variable declarations.
 * @param blocks - Parsed function blocks checked for at least one test block.
 * @returns `true` if the file contains a test block or fixture trigger signal, otherwise `false`.
 */
function hasFixturePurposeCandidateSignal(codeSource: string, blocks: FunctionBlock[]): boolean {
  return blocks.some((block) => block.isTest) || /\b(?:analyseFixture|analyseProject|writeFileSync|Array\.from)\s*\(/.test(codeSource) || /\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*\b[^=\n]*=/.test(codeSource);
}

/**
 * Adds `candidate` to `candidates` only if its line, symbol, and `targetKind` tuple is absent from `seen`.
 * Mutates `seen` and `candidates` together so existing tuples leave both unchanged while different kinds remain distinct.
 *
 * @param candidates - Target candidate list appended to when the tuple key is new.
 * @param seen - Deduplication key set tracking `line`, `symbol`, and `targetKind` entries already added.
 * @param candidate - Candidate entry to record if not yet seen.
 * @returns Nothing. Mutates `seen` and `candidates` when `candidate` is unique.
 */
function pushUniqueFixturePurposeCandidate(candidates: FixturePurposeCandidate[], seen: Set<string>, candidate: FixturePurposeCandidate): void {
  const key = `${candidate.line}\0${candidate.symbol}\0${candidate.targetKind}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

/**
 * Builds a template-fixture candidate when `codeLine` has a recognized trigger and large template text.
 * Reads the template literal from `source` at one-based `lineNumber` and rejects missing, empty, or small templates.
 *
 * @param source - Full file text containing the template literal body.
 * @param lineOffsets - Precomputed UTF-16 starting offsets for each line in `source`.
 * @param codeLine - Comment-stripped text of the current line checked for a fixture trigger.
 * @param lineNumber - One-based line number of `codeLine`.
 * @returns A `FixturePurposeCandidate` when triggered and over `FIXTURE_PURPOSE_MIN_LINES`, or `undefined`.
 */
function fixtureTemplateCandidate(source: string, lineOffsets: number[], codeLine: string, lineNumber: number): FixturePurposeCandidate | undefined {
  const trigger = fixtureTemplateTrigger(codeLine);
  if (!trigger) {
    return undefined;
  }
  const text = templateLiteralAtLine(source, lineOffsets, lineNumber);
  if (!text || !isLargeSourceFixtureText(text)) {
    return undefined;
  }
  return {
    line: lineNumber,
    symbol: trigger.symbol,
    targetKind: trigger.targetKind,
    lineCount: fixtureLineCount(text),
  };
}

/**
 * Identifies the fixture-trigger symbol and `targetKind` on `codeLine` for candidate metadata.
 * Checks `analyseFixture`, `analyseProject`, and `writeFileSync` in that order, then falls back to `fixtureConstantName`.
 *
 * @param codeLine - Comment-stripped source line inspected for fixture calls or declarations.
 * @returns Trigger `{ symbol, targetKind }` metadata, or `undefined` when no trigger matches.
 */
function fixtureTemplateTrigger(codeLine: string): { symbol: string; targetKind: string } | undefined {
  if (/\banalyseFixture\s*\(/.test(codeLine)) {
    return { symbol: "analyseFixture", targetKind: "inline-source" };
  }
  if (/\banalyseProject\s*\(/.test(codeLine)) {
    return { symbol: "analyseProject", targetKind: "inline-project" };
  }
  if (/\bwriteFileSync\s*\(/.test(codeLine)) {
    return { symbol: "writeFileSync", targetKind: "written-source" };
  }
  const fixtureName = fixtureConstantName(codeLine);
  return fixtureName ? { symbol: fixtureName, targetKind: "fixture-constant" } : undefined;
}

/**
 * Extracts a variable declaration name matching `*Fixture` or `*FIXTURE` from `codeLine`.
 * Projects signal fixture data with those opt-in markers, so matching declarations act as a natural trigger for the rule.
 *
 * @param codeLine - Comment-stripped source line checked for a `const`, `let`, or `var` fixture declaration.
 * @returns Declared identifier name if it matches the fixture marker pattern, otherwise `undefined`.
 */
function fixtureConstantName(codeLine: string): string | undefined {
  return codeLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*)\b[^=\n]*=/)?.[1];
}

/**
 * Builds a `generated-fixture` candidate when a marked declaration and qualifying `Array.from` length digits share a line.
 * Reads length digits from `codeLine` or `rawLine`, using `rawLine` for the name only when `codeLine` has a declaration keyword.
 *
 * @param rawLine - Original source line used as fallback for fixture name and length extraction.
 * @param codeLine - Comment-stripped line checked first for the declaration and `Array.from` length.
 * @param lineNumber - One-based line number recorded as the candidate's anchor line.
 * @returns A `FixturePurposeCandidate` when both name and length exceeding `FIXTURE_PURPOSE_MIN_LINES` match, else `undefined`.
 */
function generatedFixtureCandidate(rawLine: string, codeLine: string, lineNumber: number): FixturePurposeCandidate | undefined {
  const fixtureName = fixtureConstantName(codeLine) ?? (/\b(?:const|let|var)\b/.test(codeLine) ? fixtureConstantName(rawLine) : undefined);
  const generatedLength = Number((codeLine.match(/\bArray\.from\s*\(\s*\{\s*length\s*:\s*(\d+)/) ?? rawLine.match(/\bArray\.from\s*\(\s*\{\s*length\s*:\s*(\d+)/))?.[1] ?? 0);
  if (!fixtureName || generatedLength <= FIXTURE_PURPOSE_MIN_LINES) {
    return undefined;
  }
  return {
    line: lineNumber,
    symbol: fixtureName,
    targetKind: "generated-fixture",
    lineCount: generatedLength,
  };
}

/**
 * Collects `test-setup` candidates for test blocks whose setup exceeds `FIXTURE_PURPOSE_MIN_LINES` with a fixture-shape signal.
 * Any prior template or generated-array candidate line inside a block suppresses that block to avoid duplicate reporting.
 *
 * @param blocks - Parsed function blocks to inspect for qualifying test blocks.
 * @param occupiedLines - Line numbers already claimed by template or generated-array fixture candidates.
 * @returns List of `test-setup` candidates for unsuppressed qualifying test blocks.
 */
function fixtureTestBlockCandidates(blocks: FunctionBlock[], occupiedLines: Set<number>): FixturePurposeCandidate[] {
  const candidates: FixturePurposeCandidate[] = [];
  for (const block of blocks) {
    if (!block.isTest || fixtureLineInsideBlock(block, occupiedLines)) {
      continue;
    }
    const setupLines = setupLineCount(block.codeBody);
    if (setupLines <= FIXTURE_PURPOSE_MIN_LINES || !hasFixtureSetupSignal(block.codeBody)) {
      continue;
    }
    candidates.push({
      line: block.declarationLine,
      symbol: block.name,
      targetKind: "test-setup",
      lineCount: setupLines,
    });
  }
  return candidates;
}

/**
 * Checks whether any anchor line in `occupiedLines` falls within `block`'s line range.
 * The setup scan skips matching blocks to avoid reporting the same fixture twice.
 *
 * @param block - Function block providing `startLine` and `lineCount` bounds.
 * @param occupiedLines - Set of one-based candidate anchor line numbers.
 * @returns `true` if any occupied line falls between `block.startLine` and its inclusive end line, otherwise `false`.
 */
function fixtureLineInsideBlock(block: FunctionBlock, occupiedLines: Set<number>): boolean {
  const endLine = block.startLine + block.lineCount - 1;
  for (const line of occupiedLines) {
    if (line >= block.startLine && line <= endLine) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether a test body calls `analyseFixture`, `writeFileSync`, `mkdtempSync`, or `Array.from`, or uses a fixture identifier.
 * Keeps the match narrow to avoid flagging ordinary test setup.
 *
 * @param source - Comment-stripped body text of a test block.
 * @returns `true` when a fixture-related call or case-insensitive fixture identifier is present, otherwise `false`.
 */
function hasFixtureSetupSignal(source: string): boolean {
  return /\b(?:analyseFixture|writeFileSync|mkdtempSync|Array\.from)\s*\(/.test(source) || hasFixtureIdentifier(source);
}

/**
 * Checks whether `source` contains an identifier-shaped token with `fixture` anywhere in its name, ignoring case.
 * Substring matching is intentional because fixture identifiers include names such as `userFixtureA` and `manyFixtureRows`.
 *
 * @param source - Source text scanned for identifier tokens.
 * @returns `true` if any identifier token contains `fixture` case-insensitively, otherwise `false`.
 */
function hasFixtureIdentifier(source: string): boolean {
  for (const match of source.matchAll(/\b[A-Za-z_$][A-Za-z0-9_$]*\b/g)) {
    if ((match[0] ?? "").toLowerCase().includes("fixture")) {
      return true;
    }
  }
  return false;
}

/**
 * Checks whether template literal `text` exceeds `FIXTURE_PURPOSE_MIN_LINES` and contains a declarative code keyword.
 * Short strings or pure prose templates are skipped because only code-shaped fixtures require a purpose comment.
 *
 * @param text - Template literal contents extracted from a fixture candidate line.
 * @returns `true` when both the line-count threshold and code-keyword check pass, otherwise `false`.
 */
function isLargeSourceFixtureText(text: string): boolean {
  return fixtureLineCount(text) > FIXTURE_PURPOSE_MIN_LINES && /\b(?:function|class|interface|type|enum|const|let|var|import|export|test|it)\b/.test(text);
}

/**
 * Counts the LF or CRLF lines in `text`, including blank padding for the size threshold.
 * Empty text counts as one line, and a trailing newline adds an empty final line.
 *
 * @param text - Fixture text whose line count is measured.
 * @returns Total number of lines produced by splitting on LF or CRLF newlines.
 */
function fixtureLineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

/**
 * Computes each line's starting UTF-16 offset in `source` for locating fixture templates by line number.
 * Index 0 always holds 0 for the first line, including empty strings, and each LF character adds the next offset.
 *
 * @param source - Full source text to index by line start.
 * @returns Array of zero-based UTF-16 character offsets indexed by zero-based line number.
 */
function sourceLineStartOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      offsets.push(index + 1);
    }
  }
  return offsets;
}

/**
 * Locates the first backtick on one-based `lineNumber` and extracts the template literal text up to its closing backtick.
 *
 * @param source - Full file text containing the template literal.
 * @param lineOffsets - Precomputed UTF-16 line-start offsets for `source`.
 * @param lineNumber - One-based line number where the opening backtick is expected.
 * @returns Enclosed template text, or `undefined` if the line, opening backtick, or unescaped closing backtick is missing.
 */
function templateLiteralAtLine(source: string, lineOffsets: number[], lineNumber: number): string | undefined {
  const start = lineOffsets[lineNumber - 1];
  if (start === undefined) {
    return undefined;
  }
  const nextLineStart = lineOffsets[lineNumber] ?? source.length + 1;
  const firstBacktick = source.indexOf("`", start);
  if (firstBacktick < 0 || firstBacktick >= nextLineStart) {
    return undefined;
  }
  const end = closingTemplateLiteralIndex(source, firstBacktick + 1);
  return end === undefined ? undefined : source.slice(firstBacktick + 1, end);
}

/**
 * Searches `source` from `startIndex` (immediately after the opening backtick) for the next unescaped backtick.
 * Backslash escapes are skipped and `${...}` interpolations are not parsed.
 *
 * @param source - Full source string being scanned.
 * @param startIndex - Zero-based character index immediately following the opening backtick.
 * @returns Index of the closing backtick in `source`, or `undefined` if none is found before end-of-file.
 */
function closingTemplateLiteralIndex(source: string, startIndex: number): number | undefined {
  let isEscaped = false;
  for (let index = startIndex; index < source.length; index += 1) {
    const character = source[index] ?? "";
    if (isEscaped) {
      isEscaped = false;
      continue;
    }
    if (character === "\\") {
      isEscaped = true;
      continue;
    }
    if (character === "`") {
      return index;
    }
  }
  return undefined;
}

/**
 * Checks whether the candidate at one-based `line` has a qualifying purpose comment in `comments`.
 * Evaluates a spanning same-line comment alone first, then checks the nearest preceding comment across a blank-only gap,
 * combining adjacent line comments only for that preceding header.
 *
 * @param lines - File lines used to verify only blank lines intervene between a preceding comment and `line`.
 * @param comments - Parsed comment records for the file in source order.
 * @param line - One-based candidate anchor line number.
 * @returns `true` if a same-line comment or contiguous preceding comment header qualifies, otherwise `false`.
 */
function hasFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && isFixturePurposeComment(sameLine.text)) {
    return true;
  }
  const leading = leadingFixturePurposeComment(lines, comments, line);
  return Boolean(leading && isFixturePurposeComment(combinedContextLineComment(comments, leading).text));
}

// This word-count threshold accepts a comment as a purpose statement even without the vocabulary
// fast path, because grading wording by keyword list sent maintainers into rewrite loops when a
// genuine explanation missed the exact words. Shorter comments still need a vocabulary word.
const FIXTURE_PURPOSE_MIN_WORDS = 8;

/**
 * Checks whether comment `text` qualifies as a fixture explanation via purpose vocabulary or minimum word count.
 *
 * @param text - Normalized comment body text to evaluate.
 * @returns `true` if `text` contains a purpose marker or at least `FIXTURE_PURPOSE_MIN_WORDS` words, else `false`.
 */
function isFixturePurposeComment(text: string): boolean {
  return hasFixturePurposeMarker(text) || fixtureCommentWordCount(text) >= FIXTURE_PURPOSE_MIN_WORDS;
}

/**
 * Counts alphanumeric word-like tokens in comment text so punctuation-only fragments do not count as substantive prose.
 *
 * @param text - Comment body text split on whitespace.
 * @returns Number of whitespace-delimited tokens containing at least one ASCII letter or digit.
 */
function fixtureCommentWordCount(text: string): number {
  return text.split(/\s+/).filter((token) => /[A-Za-z0-9]/.test(token)).length;
}

/**
 * Finds the nearest comment in `comments` immediately above `line` separated by only blank lines.
 * Fixture-purpose counterpart to `leadingCommentForLine`.
 *
 * @param lines - File lines inspected to confirm no non-blank code lies between the comment and `line`.
 * @param comments - Parsed comment records for the file in source order.
 * @param line - One-based anchor line of the fixture or test declaration.
 * @returns Nearest preceding `CommentRecord` across a blank-only gap, or `undefined` if none qualifies.
 */
function leadingFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): CommentRecord | undefined {
  for (let index = comments.length - 1; index >= 0; index -= 1) {
    const comment = comments[index];
    if (!comment || comment.endLine >= line) {
      continue;
    }
    if (hasOnlyBlankFixturePurposeGap(lines, comment.endLine + 1, line - 1)) {
      return comment;
    }
    return undefined;
  }
  return undefined;
}

/**
 * Checks whether `lines` contains only blank text from one-based `startLine` through `endLine`, inclusive.
 * Missing line entries count as blank and an empty range returns `true`.
 *
 * @param lines - Zero-indexed array of file lines.
 * @param startLine - Inclusive one-based first line number of the gap to inspect.
 * @param endLine - Inclusive one-based last line number of the gap to inspect.
 * @returns `true` if every line in the range is blank or missing, otherwise `false`.
 */
function hasOnlyBlankFixturePurposeGap(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line <= endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

/**
 * Checks whether comment `text` contains a recognized fixture-purpose term such as `fingerprint`, ignoring case.
 *
 * @param text - Comment body text checked for purpose vocabulary markers.
 * @returns `true` if a purpose marker word or phrase matches case-insensitively, otherwise `false`.
 */
function hasFixturePurposeMarker(text: string): boolean {
  return /\b(?:fixture|covers|reproduces|regression|scanner|parse|baseline|fingerprint|noise|valid case|invalid case|because)\b/i.test(text);
}
