// Every documentation, comment-quality, fixture-purpose, stale-reference, context-doc,
// magic-threshold, and restating-signature rule. The biggest of the rule-pack modules; the
// orchestrator `analyseCommentQualityRules` fans out per-comment / per-declaration / per-block
// passes that all share a stable, deterministic emission order.
import { existsSync } from "node:fs";
import { dirname as dirnamePath, resolve } from "node:path";
import { cwd } from "node:process";
import { approximateNpath, functionBodyContent, type FunctionBlock, maxNestingDepth, parameterNames, setupLineCount } from "./blocks.ts";
import { type CommentRecord, commentTextAtLine, hasLeadingCommentBeforeLine } from "./comment-scanner.ts";
import { threshold } from "./config.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { normalizedIdentifier, splitIdentifierWords } from "./findings-helpers.ts";
import { isFixtureLikePath, isTestPath } from "./project-rules.ts";
import { ruleDescriptors } from "./rules.ts";
import { byteLine, countMatches } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

// Below 12 lines, a fixture is short enough to read at a glance — requiring a purpose header
// would just be noise; above this threshold, the next reader needs the intent spelled out.
const FIXTURE_PURPOSE_MIN_LINES = 12;

// Lightweight shape used by both public-doc and class/file-mismatch rules. Holds the declaration
// keyword (`class`, `interface`, …), the symbol name, and the declaration line for finding anchors.
export interface ExportedDeclaration {
  kind: string;
  name: string;
  line: number;
}

// Generic declaration shape used by both function and interface comment-quality rules so they can
// share `pushStaleDeclarationCommentFinding` and `pushRestatingSignatureCommentFinding` logic.
export interface CommentedDeclaration {
  kind: "function" | "interface";
  name: string;
  line: number;
  isPublic: boolean;
}

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

type MagicThresholdCandidate = {
  label: string;
  value: string;
  kind: string;
};

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
interface FixturePurposeInput {
  file: SourceFile;
  source: string;
  codeSource: string;
  lines: string[];
  comments: CommentRecord[];
  blocks: FunctionBlock[];
  config: Config;
  findings: Finding[];
}

// Precomputed JSDoc + signature pair used by every docblock rule (stale-param, missing-param,
// missing-return, useless-docblock) so the parser runs only once per source file.
interface DocumentedExportBlock {
  doc: string;
  name: string;
  params: string[];
  paramTags: string[];
  line: number;
  returnType: string;
}

// Argument bundle shared by every docblock-related finding builder. `parameter` is optional
// because some docblock rules anchor on the symbol alone, not a specific parameter.
interface DocFindingInput {
  ruleId: string;
  message: string;
  file: SourceFile;
  line: number;
  symbol: string;
  parameter?: string;
}

// Scans the masked code for the five exportable kinds. The order returned matches source order
// because `matchAll` walks left-to-right, which is what downstream rules depend on.
export function exportedDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)].map((match) => ({
    kind: match[1] ?? "",
    name: match[2] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/*
 * Skips functions and interfaces — those have dedicated rules (`docs.missing-function-doc`,
 * `docs.missing-interface-doc`). Reports the stable `docs.missing-public-doc` finding for
 * classes/types/enums without a leading JSDoc-style block comment.
 */
export function pushMissingPublicDocFinding(file: SourceFile, source: string, declaration: ExportedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" || declaration.kind === "interface") {
    return;
  }
  if (hasDocCommentBeforeLine(source, declaration.line)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.missing-public-doc",
      message: `Exported item \`${declaration.name}\` is missing a doc comment.`,
      filePath: file.displayPath,
      line: declaration.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Add a /** ... */ comment explaining the exported API.",
    }),
  );
}

// Anchors the finding at line 1 because the overview comment is expected at the very top of the
// file. Reports the stable `docs.missing-file-overview` finding when no top-of-file comment exists.
export function analyseFileOverviewDoc(file: SourceFile, source: string, findings: Finding[]): void {
  if (hasFileOverviewComment(source)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.missing-file-overview",
      message: `Source file \`${file.displayPath}\` is missing a top-of-file purpose comment.`,
      filePath: file.displayPath,
      line: 1,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      remediation: "Add a brief /** ... */ overview before imports or declarations.",
      metadata: {},
    }),
  );
}

/*
 * Same shape as `pushMissingFunctionDocFinding` but for interfaces. The stable
 * `docs.missing-interface-doc` rule reports any exported interface without a leading comment block.
 */
export function analyseInterfaceDocs(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const declaration of interfaceDeclarations(source, codeSource)) {
    if (hasLeadingCommentBeforeLine(source, declaration.line)) {
      continue;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.missing-interface-doc",
        message: `Interface \`${declaration.name}\` is missing a leading maintainer comment.`,
        filePath: file.displayPath,
        line: declaration.line,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: declaration.name,
        remediation: "Add a short /** ... */ or // comment explaining the interface contract.",
        metadata: { interfaceName: declaration.name },
      }),
    );
  }
}

// Line-anchored regex (`^[ \t]*` + `gm` flag) so the match start is the declaration line, not the
// first character of the keyword inside another construct. See lessons file for the indent-newline trap.
function interfaceDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/^[ \t]*(?:export[ \t]+)?interface[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b/gm)].map((match) => ({
    kind: "interface",
    name: match[1] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/*
 * Coordinator for every comment-quality rule. Comments and declarations are parsed once and the
 * rule descriptor + CLI flag sets are computed once, so every sub-rule sees the same stable inputs.
 */
export function analyseCommentQualityRules(input: CommentQualityRuleInput): void {
  const { file, source, codeSource, blocks, comments, config, findings } = input;
  const lines = source.split(/\r?\n/);
  const descriptorIds = new Set(ruleDescriptors().map((descriptor) => descriptor.ruleId));
  const cliFlags = knownCliFlags();
  const declarations = commentedDeclarations(blocks, interfaceDeclarations(source, codeSource));

  analyseStandaloneCommentQuality(file, comments, descriptorIds, cliFlags, findings);
  analyseCommentedDeclarationQuality(file, lines, comments, declarations, findings);
  analyseFunctionContextCommentQuality({ file, lines, comments, blocks, config, findings });
  pushMagicThresholdFindings(file, source, codeSource, comments, findings);
  pushFixturePurposeFindings({ file, source, codeSource, lines, comments, blocks, config, findings });
}

/*
 * Five per-comment rules (task tracking, suppression rationale, stale file refs, stale rule refs,
 * stale CLI flag refs) that run on every comment regardless of whether it documents a declaration.
 * Stable, deterministic emission order across the five sub-checks.
 */
function analyseStandaloneCommentQuality(file: SourceFile, comments: CommentRecord[], descriptorIds: Set<string>, cliFlags: Set<string>, findings: Finding[]): void {
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, comment, findings);
    pushSuppressionWithoutRationaleFinding(file, comment, findings);
    pushStaleFileReferenceFindings(file, comment, findings);
    pushStaleRuleReferenceFindings(file, comment, descriptorIds, findings);
    pushStaleCliFlagReferenceFindings(file, comment, cliFlags, findings);
  }
}

/*
 * Per-declaration rules that need both the declaration metadata and its leading comment. Each
 * declaration is checked against three rules (stale reference, restating signature, context-doc)
 * in their stable, deterministic order.
 */
function analyseCommentedDeclarationQuality(file: SourceFile, lines: string[], comments: CommentRecord[], declarations: CommentedDeclaration[], findings: Finding[]): void {
  for (const declaration of declarations) {
    const comment = leadingCommentForLine(lines, comments, declaration.line);
    if (!comment) {
      continue;
    }
    pushStaleDeclarationCommentFinding(file, comment, declaration, findings);
    pushRestatingSignatureCommentFinding(file, comment, declaration, findings);
    pushDeclarationContextFindings(file, lines, declaration, comment, findings);
  }
}

// Function-only context-doc rule. Restating-signature comments are skipped first because the
// useless-docblock rule has already flagged them; running context checks on top would be redundant noise.
function analyseFunctionContextCommentQuality(input: FunctionContextCommentQualityInput): void {
  const { file, lines, comments, blocks, config, findings } = input;
  for (const block of blocks) {
    const comment = leadingCommentForLine(lines, comments, block.declarationLine);
    if (!comment || isRestatingSignatureComment(comment.text, block.name, "function")) {
      continue;
    }
    pushFunctionContextFindings(file, block, comment, config, findings);
  }
}

// Test/fixture paths only — gated up front so production source never reports fixture-purpose
// findings. Reports the stable `docs.fixture-purpose-missing` finding for each candidate.
function pushFixturePurposeFindings(input: FixturePurposeInput): void {
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
function pushTodoWithoutTrackingFinding(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  const marker = todoMarker(comment.text);
  if (!marker || hasTodoTracking(comment.text)) {
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
// regardless of how the maintainer wrote them.
function todoMarker(text: string): string | undefined {
  return text.match(/\b(TODO|FIXME|HACK|XXX)\b/i)?.[1]?.toUpperCase();
}

const TODO_TRACKING_PATTERNS = [
  /https?:\/\//i,
  /(?:^|\s)#\d+\b/,
  /\bGH-\d+\b/i,
  /\bM\d{1,3}\b/,
  /\.goat-flow\/tasks\//,
  /\bADR-\d{3}\b/i,
  /\b\d{4}-\d{2}-\d{2}\b/,
  /\bowner\s*:/i,
] as const;

// Eight accepted tracking forms (URL, #123, GH-123, M123, .goat-flow/tasks, ADR-001, ISO date,
// `owner:`). The stable set is intentionally generous so projects with different ticketing systems
// can comply without changing their conventions.
function hasTodoTracking(text: string): boolean {
  return TODO_TRACKING_PATTERNS.some((pattern) => pattern.test(text));
}

/*
 * Targets `eslint-disable`, `biome-ignore`, coverage `istanbul ignore`, etc. when no maintainer
 * rationale is attached — the false-positive escape hatch is explicit because TS suppression
 * directives have their own dedicated rule. Reports the stable `docs.suppression-without-rationale` finding.
 */
function pushSuppressionWithoutRationaleFinding(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  const suppression = suppressionDirective(comment.text);
  if (!suppression || hasSuppressionRationale(comment.text)) {
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

// Returns the suppression keyword that triggered the rule. `@ts-*` directives are explicitly
// excluded — they have their own dedicated rule (`pushTsDirectiveFinding`).
function suppressionDirective(text: string): string | undefined {
  if (/@ts-(?:ignore|expect-error|nocheck|check)\b/.test(text)) {
    return undefined;
  }
  const match = text.match(/\b(eslint-disable(?:-next-line|-line)?|biome-ignore|oxlint-disable|istanbul ignore|c8 ignore|v8 ignore|prettier-ignore)\b/i);
  return match?.[1];
}

// Accepted rationale forms: explanatory keywords (because, intentional, false positive, tracked in),
// project task markers (M123, ADR-XXX, GH-123), explicit `reason:`, a tracking URL, or a #issue.
export function hasSuppressionRationale(text: string): boolean {
  return /\b(?:because|intentional|false positive|tracked in|M\d{1,3}|ADR-\d{3}|GH-\d+)\b/i.test(text) || /\breason\s*:/i.test(text) || /(?:^|\s)#\d+\b/.test(text) || /https?:\/\//i.test(text) || /\.goat-flow\/tasks\//.test(text);
}

/*
 * Scans the comment text for path-shaped references and reports any that resolve to nothing on
 * disk. Historical-context comments (migration notes, legacy markers) are exempted on purpose
 * because they intentionally name removed files. Reports the stable `docs.stale-comment` finding.
 */
function pushStaleFileReferenceFindings(file: SourceFile, comment: CommentRecord, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/[`'"]((?:\.{1,2}\/|src\/|bin\/|scripts\/|docs\/|fixtures\/|\.goat-flow\/)[A-Za-z0-9_./-]+\.(?:ts|tsx|js|json|ya?ml|toml|md|sh))[`'"]/g)) {
    const referencedPath = match[1] ?? "";
    if (referencedPathExists(file, referencedPath)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references missing path \`${referencedPath}\`.`, { staleReference: referencedPath, referenceType: "path" }));
  }
}

// Tries both the project-root and same-directory interpretations because comments are inconsistent
// about which they imply. Either match is enough to consider the reference live.
function referencedPathExists(file: SourceFile, referencedPath: string): boolean {
  const fromProject = resolve(cwd(), referencedPath);
  const fromFile = resolve(dirnamePath(file.absolutePath), referencedPath);
  return existsSync(fromProject) || existsSync(fromFile);
}

/*
 * Walks every `pillar.rule-id` shape in the comment and reports those not in the descriptor set.
 * Historical-context comments stay exempt so removed rules can remain referenced in lessons text.
 * Reports the stable `docs.stale-comment` finding for each stale rule id.
 */
function pushStaleRuleReferenceFindings(file: SourceFile, comment: CommentRecord, descriptorIds: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/\b((?:complexity|dead-code|design|docs|modernisation|naming|security|sensitive-data|size|test-quality|waste)\.[a-z0-9-]+)\b/g)) {
    const ruleId = match[1] ?? "";
    if (descriptorIds.has(ruleId)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown rule id \`${ruleId}\`.`, { staleReference: ruleId, referenceType: "ruleId" }));
  }
}

/*
 * Each double-dash option in a comment must appear in `cliFlags` (parsed from the CLI source) or
 * it counts as a stale reference. Historical context comments stay exempt by design. Reports the
 * stable `docs.stale-comment` finding for each unknown option name.
 */
function pushStaleCliFlagReferenceFindings(file: SourceFile, comment: CommentRecord, cliFlags: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/(?<![A-Za-z0-9])--[a-z][a-z0-9-]*/g)) {
    const flag = match[0] ?? "";
    if (cliFlags.has(flag)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown CLI flag \`${flag}\`.`, { staleReference: flag, referenceType: "cliFlag" }));
  }
}

// Static list of valid CLI options. Hand-curated rather than parsed from the Commander definition
// at runtime because the stale-CLI-flag rule must not depend on import order — both files would
// otherwise have to load the analyser to power their checks.
function knownCliFlags(): Set<string> {
  return new Set([
    "--ansi",
    "--baseline",
    "--config",
    "--diff",
    "--fail-on",
    "--format",
    "--generate-baseline",
    "--help",
    "--history-file",
    "--host",
    "--include-ignored",
    "--no-ansi",
    "--no-baseline",
    "--no-config",
    "--no-interaction",
    "--output",
    "--port",
    "--project-root",
    "--quiet",
    "--silent",
    "--verbose",
    "--version",
  ]);
}

// A comment whose prose names a different symbol than the declaration directly below it. The
// historical-context escape hatch keeps migration notes (which intentionally name removed symbols)
// quiet. Reports `docs.stale-comment` with stable metadata.
function pushStaleDeclarationCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  const referencedName = referencedDeclarationName(comment.text, declaration.kind);
  if (!referencedName || referencedName === declaration.name) {
    return;
  }
  findings.push(staleCommentFinding(file, comment, `Comment names \`${referencedName}\` but documents \`${declaration.name}\`.`, { staleReference: referencedName, referenceType: declaration.kind, symbol: declaration.name }));
}

// Two-pass match: either `<kind> name` (e.g., "function fooBar") or leading `name <kind|helper|
// method|contract|type>`. Both forms appear in real comments and either is sufficient evidence
// that the comment intends to name a specific symbol.
function referencedDeclarationName(text: string, kind: CommentedDeclaration["kind"]): string | undefined {
  const identifier = "([A-Za-z_$][A-Za-z0-9_$]*)";
  const direct = text.match(new RegExp(["\\b", kind, "\\s+`?", identifier, "`?"].join(""), "i"));
  if (direct?.[1]) {
    return direct[1];
  }
  const leading = text.match(new RegExp(["^`?", identifier, "`?\\s+(?:", kind, "|helper|method|contract|type)\\b"].join(""), "i"));
  return leading?.[1];
}

/*
 * Public block-doc comments are exempted on purpose because their first words usually mirror the
 * API surface — that's the documented JSDoc convention, not a useless docblock. Reports the stable
 * `docs.useless-docblock` finding otherwise.
 */
function pushRestatingSignatureCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" && declaration.isPublic && comment.kind === "block") {
    return;
  }
  if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Comment for \`${declaration.name}\` only restates the signature.`, file, line: comment.line, symbol: declaration.name }));
}

// Materialises one finding per missing context class. Each callable can theoretically produce
// four (complex, side-effect, error-behavior, invariant) — the four classes are independent signals.
// Reports each detected gap as a stable doc-context finding.
function pushFunctionContextFindings(file: SourceFile, block: FunctionBlock, comment: CommentRecord, config: Config, findings: Finding[]): void {
  for (const detail of functionContextDocFindings(block, comment.text, config)) {
    findings.push(contextDocFinding({ file, comment, ...detail }));
  }
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

/*
 * Interface-only context-doc rule. Skips when the comment is a signature restatement so the
 * useless-docblock rule's stable finding doesn't get duplicated by this one. Reports
 * `docs.missing-invariant-doc` for interfaces that carry public-contract signals.
 */
function pushDeclarationContextFindings(file: SourceFile, lines: string[], declaration: CommentedDeclaration, comment: CommentRecord, findings: Finding[]): void {
  if (declaration.kind !== "interface" || isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
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

// Vocabulary used by the magic-threshold rule. A numeric constant followed by a comment containing
// any of these words is treated as "explained".
function hasThresholdRationaleMarker(text: string): boolean {
  return /\b(?:threshold|limit|cap|budget|tuned|default|because|empirical)\b/i.test(text);
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

/*
 * Test files are exempt because their `expect(x).toBe(42)` patterns legitimately contain
 * unexplained numbers. For every production source line, the rule looks for either a named
 * threshold/limit/cap or a `threshold(config, …)` default call, then checks that a nearby comment
 * explains it. Reports the stable `docs.magic-threshold-without-rationale` finding.
 */
function pushMagicThresholdFindings(file: SourceFile, source: string, codeSource: string, comments: CommentRecord[], findings: Finding[]): void {
  if (isTestPath(file.displayPath)) {
    return;
  }
  const lines = source.split(/\r?\n/);
  const codeLines = codeSource.split(/\r?\n/);
  codeLines.forEach((codeLine, index) => {
    const candidate = magicThresholdCandidate(lines[index] ?? "", codeLine);
    if (!candidate || hasNearbyThresholdRationale(lines, comments, index + 1)) {
      return;
    }
    findings.push(
      makeFinding({
        ruleId: "docs.magic-threshold-without-rationale",
        message: `Threshold-like value \`${candidate.label}\` lacks a nearby rationale comment.`,
        filePath: file.displayPath,
        line: index + 1,
        severity: "advisory",
        pillar: "documentation",
        confidence: "medium",
        symbol: candidate.label,
        remediation: "Add a nearby comment explaining the threshold, limit, budget, or default.",
        metadata: { value: candidate.value, thresholdKind: candidate.kind },
      }),
    );
  });
}

// Two candidate sources: a named constant (`const maxThings = N`) or a `threshold()` default call.
// Either is treated as policy-shaped numeric — ordinary arithmetic constants stay quiet.
function magicThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  return namedThresholdCandidate(rawLine) ?? configDefaultThresholdCandidate(rawLine, codeLine);
}

// Identifiers ending in Threshold/Limit/Cap/Budget/Timeout/Tolerance/Weight/Score/Max/Min/Default/
// Entropy/Length signal "policy number". `-1`, `0`, `1`, `2` are exempt because they're usually sentinels.
function namedThresholdCandidate(rawLine: string): MagicThresholdCandidate | undefined {
  const named = rawLine.match(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*(?:Threshold|Limit|Cap|Budget|Timeout|Tolerance|Weight|Score|Max|Min|Default|Entropy|Length)[A-Za-z0-9_$]*)\b[^=\n]*=\s*(-?\d+(?:\.\d+)?)/i);
  const label = named?.[1];
  const thresholdValue = named?.[2];
  if (!label) {
    return undefined;
  }
  if (!thresholdValue || isCommonSafeNumber(thresholdValue)) {
    return undefined;
  }
  return { label, value: thresholdValue, kind: "named-threshold" };
}

// Cheap gate first: only look for the four-arg `threshold(config, "rule", "key", N)` form when the
// masked code actually contains `threshold(`. Required because labels come from raw text but the
// call shape must originate in executable code — masked code is the only stable signal for that.
function configDefaultThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  if (!/\bthreshold\s*\(/.test(codeLine)) {
    return undefined;
  }
  const thresholdDefault = rawLine.match(/\bthreshold\s*\([^)]*,\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*,\s*(-?\d+(?:\.\d+)?)\s*\)/);
  const ruleId = thresholdDefault?.[1];
  const key = thresholdDefault?.[2];
  const thresholdValue = thresholdDefault?.[3];
  if (!ruleId || !key) {
    return undefined;
  }
  if (!thresholdValue || isCommonSafeNumber(thresholdValue)) {
    return undefined;
  }
  return { label: `${ruleId}.${key}`, value: thresholdValue, kind: "config-default" };
}

// Four sentinel values that recur as "counter starts", "boolean toggle as int", and "default
// count" without being policy decisions. Anything outside this set is treated as a threshold.
function isCommonSafeNumber(numericLiteral: string): boolean {
  return ["-1", "0", "1", "2"].includes(numericLiteral);
}

// Two acceptable positions for the explanatory comment: same line as the constant, or directly
// above with a blank-line gap. Mirrors `hasFixturePurposeComment` adjacency rules.
function hasNearbyThresholdRationale(lines: string[], comments: CommentRecord[], line: number): boolean {
  const sameLine = comments.find((comment) => comment.line <= line && comment.endLine >= line);
  if (sameLine && hasThresholdRationaleMarker(sameLine.text)) {
    return true;
  }
  const leading = leadingCommentForLine(lines, comments, line);
  return Boolean(leading && hasThresholdRationaleMarker(leading.text));
}

// Three-tier test: useful-context vocabulary short-circuits as "not restating"; identical
// word sequences are restating; near-identical sequences (one extra trailing word) are restating.
// The result drives the `docs.useless-docblock` rule.
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
// signature detection — covers `findings`/`finding`, `imports`/`import`, etc.
function stemCommentWord(word: string): string {
  return word.length > 3 && word.endsWith("s") ? word.slice(0, -1) : word;
}

// Pointwise equality between two stemmed word arrays. Used by `isRestatingSignatureComment` to
// compare the comment's first words against the declaration name's words.
function sameWords(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((word, index) => word === right[index]);
}

// The shared "this comment carries real signal" vocabulary. Any match here exempts the comment
// from the useless-docblock and stale-reference rules.
function hasUsefulCommentContext(text: string): boolean {
  return /\b(?:because|why|intentional|tradeoff|compat|avoid|preserve|invariant|contract|side effect|throws|writes|reads|persists|fallback|recover|stable|deterministic|schema|fingerprint)\b/i.test(text);
}

// Five vocabulary markers signal "this comment is intentionally about removed/old code". The
// stale-reference rules all consult this so legacy notes can keep naming removed paths/symbols.
function isHistoricalContextComment(text: string): boolean {
  return /\b(?:previously|legacy|compat|migration|ADR)\b/i.test(text);
}

// Single makeFinding factory for every stale-comment variant. `symbol` is omitted (not set to
// undefined) via conditional spread because exactOptionalPropertyTypes treats the two as different
// shapes — the omission keeps stable fingerprints round-tripping across baseline reads and writes.
function staleCommentFinding(file: SourceFile, comment: CommentRecord, message: string, metadata: Record<string, string>): Finding {
  const symbol = metadata["symbol"];
  return makeFinding({
    ruleId: "docs.stale-comment",
    message,
    filePath: file.displayPath,
    line: comment.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    ...(symbol ? { symbol } : {}),
    remediation: "Update the comment reference or add historical context that explains why it remains useful.",
    metadata,
  });
}

// Reverse scan through the comment list — the closest comment whose `endLine < line` wins, but
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

// Tighter sibling of `hasOnlyBlankFixturePurposeGap` — exclusive upper bound. Used by
// `leadingCommentForLine` to confirm no executable token sits between a comment and its declaration.
function hasOnlyBlankLines(lines: string[], startLine: number, endLine: number): boolean {
  for (let line = startLine; line < endLine; line += 1) {
    if ((lines[line - 1] ?? "").trim() !== "") {
      return false;
    }
  }
  return true;
}

// Four docblock rules in fixed emission order: stale param, missing param, missing return,
// useless docblock. Reordering would shift the deterministic fingerprint contract without any
// real behaviour change, so this loop is part of the stable analyzer schema.
export function analyseDocRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const documentedExport of documentedExportBlocks(source, codeSource)) {
    pushStaleParamFindings(file, documentedExport, findings);
    pushMissingParamFindings(file, documentedExport, findings);
    pushMissingReturnFinding(file, documentedExport, findings);
    pushUselessDocblockFinding(file, documentedExport, findings);
  }
}

// Walks every `/** … */ export function …` pair in the source. Skips matches whose `export`
// keyword is inside a string/regex by confirming it shows up in the masked code as well.
function documentedExportBlocks(source: string, codeSource: string): DocumentedExportBlock[] {
  const blocks: DocumentedExportBlock[] = [];
  const documentedExport = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*(?::\s*([^\x7b\n]+))?/g;
  for (const match of source.matchAll(documentedExport)) {
    const block = documentedExportBlock(source, codeSource, match);
    if (block) {
      blocks.push(block);
    }
  }
  return blocks;
}

// Promotes a regex match into the structured block consumed by docblock rules. Returns undefined
// when the matched `export` keyword is actually inside a string literal in the masked source.
function documentedExportBlock(source: string, codeSource: string, match: RegExpMatchArray): DocumentedExportBlock | undefined {
  const matchStart = regexMatchStart(match);
  const exportIndex = source.indexOf("export", matchStart);
  if (!isDocumentedExportInCode(codeSource, exportIndex)) {
    return undefined;
  }
  const doc = regexGroup(match, 1);
  return {
    doc,
    name: regexGroup(match, 2),
    params: parameterNames(regexGroup(match, 3)).map((parameter) => parameter.name),
    paramTags: docParamTags(doc),
    line: byteLine(source, matchStart),
    returnType: regexGroup(match, 4).trim(),
  };
}

// `index ?? 0` adapter for the standard regex API — match.index is technically optional under
// strict TypeScript even though every real match has it.
function regexMatchStart(match: RegExpMatchArray): number {
  return match.index ?? 0;
}

// `match[index] ?? ""` adapter — keeps callers from sprinkling default-empty handling.
function regexGroup(match: RegExpMatchArray, index: number): string {
  return match[index] ?? "";
}

// Confirms the captured `export` keyword is in real code, not inside a masked comment or string.
// The mask preserves the first letter of code tokens, so checking for `e` is sufficient.
function isDocumentedExportInCode(codeSource: string, exportIndex: number): boolean {
  return exportIndex >= 0 && codeSource[exportIndex] === "e";
}

// Walks every docblock `@param tagName` that no longer matches a real parameter. Each orphan
// reports a stable `docs.stale-param-tag` finding with `parameter` metadata in the payload.
function pushStaleParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const tag of block.paramTags) {
    if (!block.params.includes(tag)) {
      findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
    }
  }
}

// Each parameter declared in the signature must have a matching `@param` tag in the docblock.
// Reports the stable `docs.missing-param-tag` finding for each orphan.
function pushMissingParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const param of block.params) {
    if (!block.paramTags.includes(param)) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` is missing @param for \`${param}\`.`, file, line: block.line, symbol: block.name, parameter: param }));
    }
  }
}

// `@returns` only required when the signature declares a non-void return type. `void` is exempt
// because documenting "returns nothing" is noise. Reports the stable `docs.missing-return-tag`.
function pushMissingReturnFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (!needsReturnTag(block)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` is missing @returns.`, file, line: block.line, symbol: block.name }));
}

// Three conditions: a declared return type exists, it isn't void, and the docblock doesn't already
// have a `@returns` tag. Annotation-less and void returns are exempt.
function needsReturnTag(block: DocumentedExportBlock): boolean {
  return block.returnType !== "" && !/^void\b/.test(block.returnType) && !/@returns?\b/.test(block.doc);
}

// Docblock-flavoured useless-docblock rule. Targets `/** Foo */ export function foo` shapes
// that fail the same restate test as line-comment docs, then reports a stable `docs.useless-docblock`.
function pushUselessDocblockFinding(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  if (isUselessDocblock(block.doc, block.name)) {
    findings.push(docFinding({ ruleId: "docs.useless-docblock", message: `Docblock for \`${block.name}\` only restates the signature.`, file, line: block.line, symbol: block.name }));
  }
}

// Single makeFinding factory for every docblock-rule finding. `parameter` is omitted (not set to
// undefined) under exactOptionalPropertyTypes so the metadata shape stays stable and each
// baseline fingerprint round-trips cleanly across runs.
function docFinding(input: DocFindingInput): Finding {
  return makeFinding({
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.file.displayPath,
    line: input.line,
    severity: "advisory",
    pillar: "documentation",
    confidence: "medium",
    symbol: input.symbol,
    remediation: "Update the JSDoc so it documents the current signature and return value.",
    metadata: { ...(input.parameter ? { parameter: input.parameter } : {}) },
  });
}

// Pulls every `@param name` tag's name from a docblock. Order is preserved so callers can spot
// duplicate tags by simple list comparison rather than set membership.
function docParamTags(doc: string): string[] {
  const names: string[] = [];
  for (const line of doc.split(/\r?\n/)) {
    const name = docParamTagName(line);
    if (name) {
      names.push(name);
    }
  }
  return names;
}

// Skips the `{Type}` braces before reading the identifier. The two-step approach lets the type
// portion be arbitrarily complex (unions, generics) without breaking the identifier extraction.
function docParamTagName(line: string): string | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  return rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1];
}

// Removes a leading `{Type}` cluster from a `@param` tag tail. Returns the empty string when the
// braces are unbalanced — a malformed tag should not contribute a phantom parameter name.
function stripDocParamType(rest: string): string {
  if (!rest.startsWith(String.fromCharCode(123))) {
    return rest;
  }
  const end = rest.indexOf(String.fromCharCode(125));
  return end === -1 ? "" : rest.slice(end + 1).trim();
}

// Normalises the docblock to its lowercase word run and compares against the symbol's expanded
// word list. Empty docblocks are considered useless; the equality fallback on
// `normalizedIdentifier` catches the case where punctuation alone separates the two.
function isUselessDocblock(doc: string, symbol: string): boolean {
  const words = doc
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\*\s?/, "").trim())
    .filter((line) => line !== "" && !line.startsWith("@"))
    .join(" ")
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!words) {
    return true;
  }
  return words === splitIdentifierWords(symbol).join(" ") || normalizedIdentifier(words) === normalizedIdentifier(symbol);
}

// Walks upward from the declaration looking for `/** */` or `*` continuation lines. The boundary
// predicate stops the search at the first real code or non-doc text, so docblocks from earlier
// declarations don't leak across.
function hasDocCommentBeforeLine(source: string, line: number): boolean {
  const lines = source.split(/\r?\n/);
  let index = line - 2;
  while (index >= 0) {
    const current = lines[index]?.trim() ?? "";
    if (isDocCommentLine(current)) {
      return true;
    }
    if (isDocCommentSearchBoundary(current)) {
      return false;
    }
    index -= 1;
  }
  return false;
}

// `/**` openers and `*` continuation lines are both docblock material. Plain `//` comments are
// intentionally excluded — those are tracked separately by `hasLeadingCommentBeforeLine`.
function isDocCommentLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("/**") || trimmedLine.startsWith("*");
}

// Halts the docblock walker when the upward search lands on real code. `@` lines are allowed
// through because JSDoc tags appear inside the docblock body and shouldn't terminate the scan.
function isDocCommentSearchBoundary(trimmedLine: string): boolean {
  return trimmedLine !== "" && !trimmedLine.startsWith("@");
}

// File-overview presence check for `docs.missing-file-overview`. Skips a shebang first because
// scripts conventionally place `#!` on line 1, then asks whether the first real line is a
// comment — that is the contract the rule reports against.
function hasFileOverviewComment(source: string): boolean {
  const lines = source.split(/\r?\n/);
  let index = firstMeaningfulLineIndex(lines);
  if (index === undefined) {
    return false;
  }
  if (lines[index]?.startsWith("#!")) {
    index = firstMeaningfulLineIndex(lines, index + 1);
  }
  return index !== undefined && commentTextAtLine(lines, index) !== undefined;
}

// Returns the index of the first non-blank line at or after `start`. The implementation does
// not skip comments — callers asking for "first meaningful line" treat comment text as a
// meaningful signal (file-overview detection wants to land on the comment itself).
function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}
