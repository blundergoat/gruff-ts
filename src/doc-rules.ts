// JSDoc and exported-declaration documentation rules. Covers `docs.missing-public-doc`,
// `docs.missing-file-overview`, `docs.missing-interface-doc`, and the docblock rule pack
// (stale/missing @param, missing @returns, useless docblock). Stable, deterministic emission order.
import { parameterNames } from "./blocks.ts";
import { commentTextAtLine, hasLeadingCommentBeforeLine } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { normalizedIdentifier, splitIdentifierWords } from "./findings-helpers.ts";
import { byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Lightweight shape used by both public-doc and class/file-mismatch rules. Holds the declaration
// keyword (`class`, `interface`, …), the symbol name, and the declaration line for finding anchors.
export interface ExportedDeclaration {
  kind: string;
  name: string;
  line: number;
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
 * Skips functions and interfaces - those have dedicated rules (`docs.missing-function-doc`,
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
export function interfaceDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/^[ \t]*(?:export[ \t]+)?interface[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b/gm)].map((match) => ({
    kind: "interface",
    name: match[1] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/*
 * Docblock rule pack. Walks every `/** … *\/ export function …` pair and fires four sub-rules per
 * block in a stable, deterministic emission order (stale-param → missing-param → missing-return → useless-docblock).
 */
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

// `index ?? 0` adapter for the standard regex API - match.index is technically optional under
// strict TypeScript even though every real match has it.
function regexMatchStart(match: RegExpMatchArray): number {
  return match.index ?? 0;
}

// `match[index] ?? ""` adapter - keeps callers from sprinkling default-empty handling.
function regexGroup(match: RegExpMatchArray, index: number): string {
  return match[index] ?? "";
}

// Confirms the captured `export` keyword is in real code, not inside a masked comment or string.
// The mask preserves the first letter of code tokens, so checking for `e` is sufficient.
function isDocumentedExportInCode(codeSource: string, exportIndex: number): boolean {
  return exportIndex >= 0 && codeSource[exportIndex] === "e";
}

// Reports stale `@param` tags before missing ones because a rename should produce a stable pair:
// reports the "old name is stale" finding first because that order is the review contract.
function pushStaleParamFindings(file: SourceFile, block: DocumentedExportBlock, findings: Finding[]): void {
  for (const tag of block.paramTags) {
    if (!block.params.includes(tag)) {
      findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
    }
  }
}

// Complements `pushStaleParamFindings`: reports stable one-argument findings because reviewers should not re-parse the signature mentally.
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
// braces are unbalanced - a malformed tag should not contribute a phantom parameter name.
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
// intentionally excluded - those are tracked separately by `hasLeadingCommentBeforeLine`.
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
// comment - that is the contract the rule reports against.
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
// not skip comments - callers asking for "first meaningful line" treat comment text as a
// meaningful signal (file-overview detection wants to land on the comment itself).
function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}
