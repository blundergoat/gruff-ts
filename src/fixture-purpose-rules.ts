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

// Appends docs.fixture-purpose-missing findings to input.findings for undocumented candidates in input's file and parsed source context.
// Files whose paths are neither tests nor fixture-like are ignored; returns no value.
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

// Returns the missing fixture-purpose message for the candidate.
// The message must name the test for setup candidates or locate other fixtures by the nearby call or declaration name.
function fixturePurposeMessage(candidate: FixturePurposeCandidate): string {
  if (candidate.targetKind === "test-setup") {
    return `Test \`${candidate.symbol}\` builds a large fixture setup without a purpose comment above the test.`;
  }
  return `Large fixture source near \`${candidate.symbol}\` is missing a purpose comment.`;
}

// Returns the purpose-comment recommendation for the candidate's targetKind.
// The recommended placement must be accepted by hasFixturePurposeComment so the fix can clear the finding.
function fixturePurposeRemediation(candidate: FixturePurposeCandidate): string {
  if (candidate.targetKind === "test-setup") {
    return "Add a comment directly above the test declaration explaining what scanner path, regression, or fixture behavior this setup covers.";
  }
  return "Add a comment on or directly above the fixture explaining what scanner path, regression, or fixture behavior this source covers.";
}

// Finds fixture-purpose candidates using source for literal text, codeSource for line triggers, and blocks for test setup.
// Returns unique candidates within source's line range; template and generated-array locations suppress overlapping test blocks.
// Returns an empty array when no qualifying candidate is found.
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

// Returns whether codeSource has a recognized fixture trigger or blocks contains a test, allowing candidate extraction to proceed.
// False skips fixture-purpose candidate extraction for the whole file.
function hasFixturePurposeCandidateSignal(codeSource: string, blocks: FunctionBlock[]): boolean {
  return blocks.some((block) => block.isTest) || /\b(?:analyseFixture|analyseProject|writeFileSync|Array\.from)\s*\(/.test(codeSource) || /\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*\b[^=\n]*=/.test(codeSource);
}

// Adds candidate to candidates only if its line, symbol and targetKind tuple is absent from seen.
// Mutates seen and candidates together and returns no value; existing tuples leave both unchanged, and different kinds remain distinct.
function pushUniqueFixturePurposeCandidate(candidates: FixturePurposeCandidate[], seen: Set<string>, candidate: FixturePurposeCandidate): void {
  const key = `${candidate.line}\0${candidate.symbol}\0${candidate.targetKind}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

// Returns a large template-fixture candidate when codeLine supplies a recognized trigger, or undefined when the trigger or size check fails.
// Reads template text from source using lineOffsets, the source offsets for line starts, and one-based lineNumber.
// Missing or empty template text also returns undefined.
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

// Returns a fixture-trigger symbol and targetKind from codeLine for candidate metadata, or undefined when none matches.
// Checks analyseFixture, analyseProject and writeFileSync in that order, then uses fixtureConstantName for declarations.
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

// Identifier names matching `*Fixture` or `*FIXTURE` are treated as opt-in markers - projects
// signal "this is fixture data" with that suffix, so it's the natural trigger for the rule.
function fixtureConstantName(codeLine: string): string | undefined {
  return codeLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*)\b[^=\n]*=/)?.[1];
}

// Returns a generated-fixture candidate when a marked declaration and qualifying Array.from length digits share a line.
// Reads leading length digits from codeLine or rawLine. Uses rawLine for the name only when codeLine has a declaration keyword.
// lineNumber supplies the reported line. Returns undefined if the name is absent or the parsed length fails FIXTURE_PURPOSE_MIN_LINES.
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

// Returns candidates for test blocks in blocks whose setup exceeds FIXTURE_PURPOSE_MIN_LINES and has a fixture-shape signal.
// occupiedLines contains prior template or generated-array candidate lines; any such line inside a block suppresses that block.
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

// Returns true when the anchor line of a template or generated fixture candidate falls inside the test block.
// The setup scan skips a matching block to avoid reporting the fixture twice.
function fixtureLineInsideBlock(block: FunctionBlock, occupiedLines: Set<number>): boolean {
  const endLine = block.startLine + block.lineCount - 1;
  for (const line of occupiedLines) {
    if (line >= block.startLine && line <= endLine) {
      return true;
    }
  }
  return false;
}

// Returns true if the test body contains a call shaped like analyseFixture, writeFileSync, mkdtempSync, or Array.from,
// or an identifier containing fixture in any case. Keep the match narrow to avoid flagging ordinary test setup.
function hasFixtureSetupSignal(source: string): boolean {
  return /\b(?:analyseFixture|writeFileSync|mkdtempSync|Array\.from)\s*\(/.test(source) || hasFixtureIdentifier(source);
}

// Returns whether source text contains an identifier-shaped token with fixture anywhere in it, ignoring case.
// Substring matching is intentional because fixture identifiers include names such as userFixtureA and manyFixtureRows.
function hasFixtureIdentifier(source: string): boolean {
  for (const match of source.matchAll(/\b[A-Za-z_$][A-Za-z0-9_$]*\b/g)) {
    if ((match[0] ?? "").toLowerCase().includes("fixture")) {
      return true;
    }
  }
  return false;
}

// Two conjoint conditions: enough lines AND at least one declarative keyword. Short strings or
// pure prose templates don't need a purpose comment; only code-shaped fixtures do.
function isLargeSourceFixtureText(text: string): boolean {
  return fixtureLineCount(text) > FIXTURE_PURPOSE_MIN_LINES && /\b(?:function|class|interface|type|enum|const|let|var|import|export|test|it)\b/.test(text);
}

// Returns the LF or CRLF line count of fixture text, including blank padding for the size threshold.
// Empty text counts as one line, and a trailing newline adds an empty final line.
function fixtureLineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

// Returns each line's starting UTF-16 offset in source for locating fixture templates by line number.
// Array index zero represents the first line and always contains zero, including for empty source; each LF adds another line start.
function sourceLineStartOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      offsets.push(index + 1);
    }
  }
  return offsets;
}

// Uses lineOffsets as line-start indices and one-based lineNumber to locate the first backtick on that source line.
// Returns the enclosed source text, or undefined if the line, opening backtick, or unescaped closing backtick is missing.
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

// Searches source from startIndex, immediately after the opening backtick, for the next unescaped backtick and returns its index.
// Backslash escapes are skipped; interpolation is not parsed, and no closing backtick returns undefined.
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

// Returns whether the candidate at one-based line has an accepted purpose comment in comments, using lines to check the gap.
// Checks the first spanning comment on its own. If it does not qualify, checks the nearest preceding comment across a blank-only gap.
// Combines adjacent line comments only for the preceding header, so an earlier header line can supply the purpose text.
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

// Returns whether comment text qualifies as a fixture explanation by using purpose vocabulary or meeting the minimum word count.
function isFixturePurposeComment(text: string): boolean {
  return hasFixturePurposeMarker(text) || fixtureCommentWordCount(text) >= FIXTURE_PURPOSE_MIN_WORDS;
}

// Counts word-like tokens; punctuation-only fragments do not make a comment substantive.
function fixtureCommentWordCount(text: string): number {
  return text.split(/\s+/).filter((token) => /[A-Za-z0-9]/.test(token)).length;
}

// Fixture-purpose counterpart to leadingCommentForLine. Uses lines to check the gap above the declaration at line.
// Returns the nearest preceding entry in comments if only blank lines intervene, or undefined when the fixture has no qualifying comment.
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

// Returns whether lines contains only blank text from one-based startLine through endLine, inclusive, to attach a fixture purpose comment.
// Missing line entries count as blank; an empty range returns true.
function hasOnlyBlankFixturePurposeGap(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line <= endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

// Returns whether comment text contains a fixture-purpose term such as fingerprint, ignoring case so short purpose comments can qualify.
function hasFixturePurposeMarker(text: string): boolean {
  return /\b(?:fixture|covers|reproduces|regression|scanner|parse|baseline|fingerprint|noise|valid case|invalid case|because)\b/i.test(text);
}
