// Detects large test/fixture sources that need a purpose comment. Three candidate kinds in one
// pass — template-literal fixtures, generated array fixtures, and high-setup test blocks — then
// reports `docs.fixture-purpose-missing` for each candidate without a nearby explanation comment.
import { type FunctionBlock, setupLineCount } from "./blocks.ts";
import { type CommentRecord } from "./comment-scanner.ts";
import { threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { isFixtureLikePath, isTestPath } from "./project-rules.ts";
import type { Config, Finding } from "./types.ts";

// Below 12 lines, a fixture is short enough to read at a glance — requiring a purpose header
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
  config: Config;
  findings: Finding[];
}

// Test/fixture paths only — gated up front so production source never reports fixture-purpose
// findings. Reports the stable `docs.fixture-purpose-missing` finding for each candidate.
export function pushFixturePurposeFindings(input: FixturePurposeInput): void {
  const { file, source, codeSource, lines, comments, blocks, config, findings } = input;
  if (!isTestPath(file.displayPath) && !isFixtureLikePath(file.displayPath)) {
    return;
  }
  for (const candidate of fixturePurposeCandidates(source, codeSource, blocks, config)) {
    if (hasFixturePurposeComment(lines, comments, candidate.line)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.fixture-purpose-missing",
        message: `Large fixture source near \`${candidate.symbol}\` is missing a purpose comment.`,
        filePath: file.displayPath,
        line: candidate.line,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: candidate.symbol,
        remediation: "Add a nearby comment explaining what scanner path, regression, or fixture behavior this source covers.",
        metadata: {
          targetKind: candidate.targetKind,
          fixtureLines: candidate.lineCount,
        },
      }),
    );
  }
}

// Three candidate kinds collected in one pass: template-literal fixtures, generated array fixtures,
// and test setup blocks. `occupiedLines` tracks the first two so the third doesn't double-report.
function fixturePurposeCandidates(source: string, codeSource: string, blocks: FunctionBlock[], config: Config): FixturePurposeCandidate[] {
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

  for (const candidate of fixtureTestBlockCandidates(blocks, config, occupiedLines)) {
    pushUniqueFixturePurposeCandidate(candidates, seen, candidate);
  }

  return candidates.filter((candidate) => candidate.line <= lines.length);
}

// Composite key prevents two fixture candidates landing at the same line/symbol/kind tuple — a
// real case when one declaration triggers both a template-literal match and a generated-array match.
function pushUniqueFixturePurposeCandidate(candidates: FixturePurposeCandidate[], seen: Set<string>, candidate: FixturePurposeCandidate): void {
  const key = `${candidate.line}\0${candidate.symbol}\0${candidate.targetKind}`;
  if (seen.has(key)) {
    return;
  }
  seen.add(key);
  candidates.push(candidate);
}

// Two-stage gate: detect the call-site trigger (`analyseFixture`, `analyseProject`, etc.), then
// extract the adjacent template literal and confirm it is large enough to need documentation.
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

// Four trigger forms in priority order: `analyseFixture(`, `analyseProject(`, `writeFileSync(`,
// or a `*Fixture` / `*FIXTURE` constant declaration. The `targetKind` differentiates them in metadata.
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

// Identifier names matching `*Fixture` or `*FIXTURE` are treated as opt-in markers — projects
// signal "this is fixture data" with that suffix, so it's the natural trigger for the rule.
function fixtureConstantName(codeLine: string): string | undefined {
  return codeLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Fixture|FIXTURE)[A-Za-z0-9_$]*)\b[^=\n]*=/)?.[1];
}

// `Array.from({ length: N })` style generated fixtures. Requires both a `*Fixture` constant name
// and N > FIXTURE_PURPOSE_MIN_LINES so trivial test arrays don't trip the rule.
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

// Test blocks with high setup-line counts AND a fixture-shape signal. Excludes blocks whose setup
// already produced a template-literal or generated-array candidate at the same line.
function fixtureTestBlockCandidates(blocks: FunctionBlock[], config: Config, occupiedLines: Set<number>): FixturePurposeCandidate[] {
  const candidates: FixturePurposeCandidate[] = [];
  for (const block of blocks) {
    if (!block.isTest || fixtureLineInsideBlock(block, occupiedLines)) {
      continue;
    }
    const setupLines = setupLineCount(block.codeBody);
    if (setupLines <= threshold(config, "test-quality.setup-bloat", 12) || !hasFixtureSetupSignal(block.codeBody)) {
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

// Returns true if any occupied line falls inside the block's line range. Prevents test blocks
// from double-reporting on a fixture that was already detected as a template literal.
function fixtureLineInsideBlock(block: FunctionBlock, occupiedLines: Set<number>): boolean {
  const endLine = block.startLine + block.lineCount - 1;
  for (const line of occupiedLines) {
    if (line >= block.startLine && line <= endLine) {
      return true;
    }
  }
  return false;
}

// Either the canonical fixture-generation calls (analyseFixture / writeFileSync / mkdtempSync /
// Array.from) or an identifier containing "fixture". The narrow allowlist is deliberate — broader
// matchers would catch ordinary production code that happens to construct test data.
function hasFixtureSetupSignal(source: string): boolean {
  return /\b(?:analyseFixture|writeFileSync|mkdtempSync|Array\.from)\s*\(/.test(source) || hasFixtureIdentifier(source);
}

// Substring (not word boundary) match because fixture identifiers in real projects include forms
// like `userFixtureA`, `manyFixtureRows`, etc. Lowercased so casing variants all match.
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

// Newline-count, not "nonblank-line count" — the rule cares about apparent fixture size as the
// maintainer sees it, including blank padding.
function fixtureLineCount(text: string): number {
  return text.split(/\r?\n/).length;
}

// Index → line lookup support. Used by the fixture-template detector to map a byte offset to a
// (line, column) coordinate without splitting the whole source on every query.
function sourceLineStartOffsets(source: string): number[] {
  const offsets = [0];
  for (let index = 0; index < source.length; index += 1) {
    if (source[index] === "\n") {
      offsets.push(index + 1);
    }
  }
  return offsets;
}

// Walks forward from the line's start offset to find the opening backtick on that line, then
// searches for its match. Returns undefined when no template starts on the line.
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

// Linear walk respecting `\`` escapes. Does NOT handle `${…}` interpolation specially — fixture
// templates rarely contain nested backticks, and a stricter parse would not help the rule's signal.
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

// Two acceptable positions: a comment on the candidate line itself, or one directly above with
// nothing but blank lines in between. Anything farther away cannot be claimed as documentation.
function hasFixturePurposeComment(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasFixturePurposeMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingFixturePurposeComment(lines, comments, line);
  return Boolean(leading && hasFixturePurposeMarker(leading.text));
}

// Like `leadingCommentForLine` but with the fixture-specific blank-gap predicate that allows for
// slightly more spacing than the documentation-rule version.
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

// Identical to `hasOnlyBlankLines` but with an inclusive upper bound — fixtures may have one
// extra blank line of breathing room above them that ordinary declaration comments do not.
function hasOnlyBlankFixturePurposeGap(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line <= endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

// Vocabulary list of words a meaningful fixture-purpose comment is expected to use (fixture,
// covers, regression, baseline, fingerprint, …). Project task references count as well.
function hasFixturePurposeMarker(text: string): boolean {
  return /\b(?:fixture|covers|reproduces|regression|scanner|parse|baseline|fingerprint|noise|valid case|invalid case|because|M\d{1,3})\b/i.test(text) || /\.goat-flow\/tasks\//.test(text);
}
