// JSDoc and exported-declaration documentation rules. Covers `docs.missing-public-doc`,
// `docs.missing-file-overview`, `docs.missing-interface-doc`, and the docblock rule pack
// (stale/missing @param, missing @returns). Stable, deterministic emission order.
import { commentTextAtLine, hasLeadingCommentBeforeLine } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { documentedDefaultAndLaterExports, documentedExportConstants, documentedExportFunctions, documentedMethods, documentedPrivateCallables, type DocumentedExportFunction, type ParsedScript } from "./parsed-script.ts";
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
// missing-return) so the parser runs only once per source file.
interface DocumentedCallableBlock {
  doc: string;
  name: string;
  params: string[];
  paramTags: string[];
  line: number;
  returnType: string;
  hasBodyReturnValue: boolean;
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

// One `@returns` or `@param` tag in a docblock, for the bare-tag checks: its line offset from the
// docblock's first line and whether any description text follows the tag, its `{Type}` or its name.
interface DocTagOccurrence {
  lineOffset: number;
  isDescribed: boolean;
}

// One `@param` tag in a docblock, for the bare-tag checks: the occurrence plus the parameter it names.
interface DocParamTagOccurrence extends DocTagOccurrence {
  name: string;
}

// Returns source-ordered export matches from codeSource for class, interface, type, enum or function followed directly by a simple name.
// codeSource is masked text aligned with source; source supplies line numbers. No matches produces an empty list.
export function exportedDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/\bexport\s+(class|interface|type|enum|function)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)].map((match) => ({
    kind: match[1] ?? "",
    name: match[2] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/**
 * Check for the leading docblock required by the stable docs.missing-public-doc rule.
 * Function checks are docs.missing-exported-function-doc, docs.missing-internal-function-doc. Interfaces use docs.missing-interface-doc.
 *
 * @param file - File path to attach to the finding.
 * @param source - Text searched above the exported declaration for a docblock marker.
 * @param declaration - Exported item to check. Functions and interfaces are skipped.
 * @param findings - Collector for the advisory finding.
 * @returns Nothing. Appends a finding only when an in-scope declaration lacks a leading docblock.
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

// Examines source for an overview at the first meaningful line after allowing for an optional shebang.
// Returns nothing and appends a stable docs.missing-file-overview finding to findings when the overview is absent.
// Anchors the report at line 1 of file because the overview belongs at the top.
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

/**
 * Checks interface declarations, including unexported ones, for a leading maintainer comment.
 *
 * @param file - source file whose display path anchors the findings
 * @param source - original text used to find line numbers and leading comments
 * @param codeSource - masked text searched for interface declarations
 * @param findings - accumulator for stable docs.missing-interface-doc findings
 * @returns nothing. Appends a finding for each matched interface without a usable leading comment.
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

// Returns source-ordered matches for interface headers that start a line, allowing indentation and a plain export prefix on that line.
// codeSource supplies the masked headers and same-line names. source supplies the line numbers for the interface documentation check.
export function interfaceDeclarations(source: string, codeSource: string): ExportedDeclaration[] {
  return [...codeSource.matchAll(/^[ \t]*(?:export[ \t]+)?interface[ \t]+([A-Za-z_$][A-Za-z0-9_$]*)\b/gm)].map((match) => ({
    kind: "interface",
    name: match[1] ?? "",
    line: byteLine(source, match.index ?? 0),
  }));
}

/**
 * The tag rules' `rules.<id>.options.everyCallable` switches, read once per file from the user's config.
 * Both default to true; setting both false keeps the pack on documented exported function declarations.
 */
export interface DocTagRuleSwitches {
  /** `docs.missing-param-tag`'s `everyCallable` option. */
  isParamTagEveryCallable: boolean;
  /** `docs.missing-return-tag`'s `everyCallable` option. */
  isReturnTagEveryCallable: boolean;
}

/**
 * Checks docblocks in stable order, reporting stale parameters, missing parameters, missing returns and bare tags in that order.
 * The switches gate wider coverage and extra checks so that either tag rule can be configured independently.
 *
 * @param file - source file whose display path anchors the findings
 * @param findings - report accumulator that receives the docblock findings
 * @param parsed - shared syntax tree providing the documented callables and signatures
 * @param everyCallable - enables wider coverage and bare tag checks, plus grouped stale names for params or inferred returns for returns
 * @returns nothing. Appends the docblock violations to findings.
 */
export function analyseDocRules(file: SourceFile, findings: Finding[], parsed: ParsedScript, everyCallable: DocTagRuleSwitches): void {
  for (const documentedExport of documentedBlocks(documentedExportFunctions(parsed))) {
    pushStaleParamFindings(file, documentedExport, findings, everyCallable.isParamTagEveryCallable);
    pushMissingParamFindings(file, documentedExport, findings);
    pushMissingReturnFinding(file, documentedExport, findings, everyCallable.isReturnTagEveryCallable);
    pushBareTagFindings(file, documentedExport, findings, everyCallable);
  }
  pushEveryCallableTagFindings(file, parsed, everyCallable, findings);
}

/**
 * Extends tag checks to documented arrows, function expressions, default and later exports, methods, and private and nested callables.
 * Leaves stale tags on the primary pass so that only enabled missing and bare tag checks run here.
 *
 * @param file - source file whose display path anchors the findings
 * @param parsed - shared syntax tree used to find the additional documented callables
 * @param everyCallable - switches that independently enable parameter and return tag checks
 * @param findings - accumulator for violations of the tag contract
 * @returns nothing. Appends findings for enabled checks and leaves the accumulator alone when both switches are off.
 */
function pushEveryCallableTagFindings(file: SourceFile, parsed: ParsedScript, everyCallable: DocTagRuleSwitches, findings: Finding[]): void {
  if (!everyCallable.isParamTagEveryCallable && !everyCallable.isReturnTagEveryCallable) {
    return;
  }
  const callables = [...documentedExportConstants(parsed), ...documentedDefaultAndLaterExports(parsed), ...documentedMethods(parsed), ...documentedPrivateCallables(parsed)];
  for (const block of documentedBlocks(callables)) {
    if (everyCallable.isParamTagEveryCallable) {
      pushMissingParamFindings(file, block, findings);
    }
    if (everyCallable.isReturnTagEveryCallable) {
      pushMissingReturnFinding(file, block, findings, everyCallable.isReturnTagEveryCallable);
    }
    pushBareTagFindings(file, block, findings, everyCallable);
  }
}

/**
 * Keeps the parsed declaration details for each block, and extracts parameter tag names for the documentation checks.
 *
 * @param documentedCallables - Callable declarations and their documentation from the shared syntax tree.
 * @returns One check record per input callable in the same order, or an empty array when there are none.
 */
function documentedBlocks(documentedCallables: DocumentedExportFunction[]): DocumentedCallableBlock[] {
  return documentedCallables.map((documented) => ({
    doc: documented.docText,
    name: documented.name,
    params: documented.parameterNames,
    paramTags: docParamTags(documented.docText),
    line: documented.line,
    returnType: documented.returnTypeText,
    hasBodyReturnValue: documented.hasBodyReturnValue,
  }));
}

// Returns nothing. Appends stable findings at block's location in file for documented names absent from the signature.
// isNamingEveryStaleTag groups distinct names into one finding. Otherwise findings gets one per stale tag, or none if no tags are stale.
// The caller checks for missing tags afterward so that a rename flags the old name first.
function pushStaleParamFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], isNamingEveryStaleTag: boolean): void {
  const staleTags = block.paramTags.filter((tag) => !block.params.includes(tag));
  if (isNamingEveryStaleTag) {
    pushEveryStaleParamFinding(file, block, findings, [...new Set(staleTags)]);
    return;
  }
  for (const tag of staleTags) {
    findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
  }
}

// One `docs.stale-param-tag` finding per declaration that names each stale tag once, in docblock
// order. One finding per tag would share the docblock's line and symbol, so its fingerprint would
// collapse them into the first. `parameter` metadata holds the same names, joined by ", ".
function pushEveryStaleParamFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], staleTags: string[]): void {
  if (staleTags.length === 0) {
    return;
  }
  const noun = staleTags.length === 1 ? "tag" : "tags";
  const quoted = staleTags.map((tag) => `\`${tag}\``).join(", ");
  findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param ${noun} ${quoted}.`, file, line: block.line, symbol: block.name, parameter: staleTags.join(", ") }));
}

// Appends one finding to findings for all parameters in block without an @param tag, in signature order. Uses file for the report path.
// Groups the names in the message and parameter metadata because findings on the same doc line and symbol would share a fingerprint.
// Returns nothing. Appends nothing when all declared parameters have tags.
function pushMissingParamFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const missing = block.params.filter((param) => !block.paramTags.includes(param));
  if (missing.length === 0) {
    return;
  }
  const quoted = missing.map((param) => `\`${param}\``).join(", ");
  findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` is missing @param for ${quoted}.`, file, line: block.line, symbol: block.name, parameter: missing.join(", ") }));
}

// Returns nothing. Appends a stable docs.missing-return-tag finding to findings when block in file lacks a tag this detector requires.
// A return annotation needs a tag unless it starts with void at a word boundary. isInferringReturn checks unannotated bodies for a value.
// In this detector, void is exempt because documenting "returns nothing" is noise. Project policy still requires a void return note.
function pushMissingReturnFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], isInferringReturn: boolean): void {
  if (!needsReturnTag(block, isInferringReturn)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` is missing @returns.`, file, line: block.line, symbol: block.name }));
}

// Reports whether the missing-return rule flags block when its docblock has neither @return nor @returns.
// A declared type qualifies unless it starts with the void keyword. isInferringReturn lets unannotated bodies qualify by returning a value.
function needsReturnTag(block: DocumentedCallableBlock, isInferringReturn: boolean): boolean {
  return !/@returns?\b/.test(block.doc) && isReturningValue(block, isInferringReturn);
}

// Tells the return-tag checks whether to treat a documented callable as returning a value.
// An annotation takes precedence and yields false if it starts with the word void. With no annotation,
// the result is true only when inference is enabled and the body returns a value.
function isReturningValue(block: DocumentedCallableBlock, isInferringReturn: boolean): boolean {
  if (block.returnType === "") {
    return isInferringReturn && block.hasBodyReturnValue;
  }
  return !/^void\b/.test(block.returnType);
}

/**
 * Checks existing tags on declared parameters and on callables that qualify for value-return tags.
 * The description contract is satisfied by one described occurrence for each parameter or return, including description on continuation lines.
 *
 * @param file - source file whose display path anchors the findings
 * @param block - doc text and signature used to check parameter and return tags
 * @param findings - accumulator for bare-tag violations
 * @param everyCallable - switches that independently enable the parameter and return checks
 * @returns nothing. Appends violations for enabled checks only when matching tags exist and all their occurrences are bare.
 */
function pushBareTagFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], everyCallable: DocTagRuleSwitches): void {
  if (everyCallable.isParamTagEveryCallable) {
    pushBareParamTagFindings(file, block, findings);
  }
  if (everyCallable.isReturnTagEveryCallable) {
    pushBareReturnTagFinding(file, block, findings);
  }
}

// Appends a docs.missing-param-tag finding to findings for each parameter in block with tags but no description on any of them.
// Uses file for the report path and the first bare tag for the anchor so that each reported parameter keeps a distinct fingerprint.
// Returns nothing. Tags naming no declared parameter are handled by docs.stale-param-tag.
function pushBareParamTagFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const tags = docParamTagOccurrences(block.doc);
  for (const param of block.params) {
    const bareTag = firstBareTag(tags.filter((tag) => tag.name === param));
    if (bareTag) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` has no description for @param \`${param}\`.`, file, line: block.line + bareTag.lineOffset, symbol: block.name, parameter: param }));
    }
  }
}

// Reports a stable docs.missing-return-tag finding on the first @return or @returns line when all existing return tags are bare.
// A declared type qualifies unless it starts with the void keyword. Without a declared type, the body must return a value.
// Returns nothing and appends to findings, using file for the report path and block for the doc text and signature.
function pushBareReturnTagFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  if (!isReturningValue(block, true)) {
    return;
  }
  const bareTag = firstBareTag(docReturnTagOccurrences(block.doc));
  if (bareTag) {
    findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` has no description for @returns.`, file, line: block.line + bareTag.lineOffset, symbol: block.name }));
  }
}

// Returns the first entry in tags only when all are undescribed; empty tags or any described tag returns undefined.
function firstBareTag<T extends DocTagOccurrence>(tags: T[]): T | undefined {
  return tags.some((tag) => tag.isDescribed) ? undefined : tags[0];
}

// Returns an advisory docblock finding using input's rule, message, and source location.
// An absent or empty parameter leaves that metadata field unset under exactOptionalPropertyTypes.
// The stable fingerprint comes from the rule, file path, line, and symbol.
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

// Returns the name parsed from the first @param marker on each line of doc, in stable order for stale-tag reporting.
// The list is empty when no line yields a name.
function docParamTags(doc: string): string[] {
  const names: string[] = [];
  for (const line of doc.split(/\r?\n/)) {
    const name = docParamTagParts(line)?.name;
    if (name) {
      names.push(name);
    }
  }
  return names;
}

// Reads line after its first @param marker, skipping an optional brace-delimited type through its first closing brace.
// Returns the name and raw tail for description checking, or undefined when the marker, usable name or closing type brace is missing.
function docParamTagParts(line: string): { name: string; tail: string } | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  const name = rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1];
  return name ? { name, tail: rest.slice(name.length) } : undefined;
}

// Checks the first @param marker on each line of doc and returns an occurrence when it yields a name.
// Each occurrence gives its line offset and whether it has description text on that line or before the next tag.
function docParamTagOccurrences(doc: string): DocParamTagOccurrence[] {
  const lines = docContentLines(doc);
  const tags: DocParamTagOccurrence[] = [];
  for (const [index, line] of lines.entries()) {
    const parts = docParamTagParts(line);
    if (parts) {
      tags.push({ name: parts.name, lineOffset: index, isDescribed: hasTagDescription(lines, index, parts.tail) });
    }
  }
  return tags;
}

// Returns an occurrence for the first @returns or @return marker matched on each line of doc, in docblock order.
// Each occurrence gives its line offset and whether description text follows the marker or optional type on that line or before the next tag.
function docReturnTagOccurrences(doc: string): DocTagOccurrence[] {
  const lines = docContentLines(doc);
  const tags: DocTagOccurrence[] = [];
  for (const [index, line] of lines.entries()) {
    const match = /@returns?\b/.exec(line);
    if (match) {
      tags.push({ lineOffset: index, isDescribed: hasTagDescription(lines, index, stripDocParamType(line.slice(match.index + match[0].length).trim())) });
    }
  }
  return tags;
}

// Docblock lines without their leading * marker. The doc text already starts after the /**
// opener and stops before the closer, so index 0 is the docblock's first line.
function docContentLines(doc: string): string[] {
  return doc.split(/\r?\n/).map((line) => line.replace(/^\s*\*/, "").trim());
}

// Returns whether the tag has description text in tail or subsequent lines before the next tag.
// lines holds stripped, trimmed docblock lines; index identifies the current tag.
// tail is text after the tag's name or type; a leading - alone does not count as a description.
function hasTagDescription(lines: string[], index: number, tail: string): boolean {
  if (tail.trim().replace(/^-\s*/, "") !== "") {
    return true;
  }
  const nextTag = lines.findIndex((line, lineIndex) => lineIndex > index && line.startsWith("@"));
  return lines.slice(index + 1, nextTag === -1 ? lines.length : nextTag).some((line) => line !== "");
}

// Removes a leading brace-delimited type from rest and returns the trimmed suffix after its first closing brace.
// Returns rest unchanged when no type begins it, or an empty string when an opening brace has no closing brace.
function stripDocParamType(rest: string): string {
  if (!rest.startsWith(String.fromCharCode(123))) {
    return rest;
  }
  const end = rest.indexOf(String.fromCharCode(125));
  return end === -1 ? "" : rest.slice(end + 1).trim();
}

// Returns whether the upward scan above the one-based declaration line in source reaches a /** opener or a line starting with *.
// Blank and @-prefixed lines are skipped; other text ends the search without a match.
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

// Returns whether trimmedLine begins with a /** opener or * continuation marker.
// Ordinary // comments are excluded here and checked by hasLeadingCommentBeforeLine.
function isDocCommentLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("/**") || trimmedLine.startsWith("*");
}

// Returns whether trimmedLine ends a docblock search after doc-comment lines have been ruled out.
// Blank lines and @-prefixed tag text allow the search to continue; every other line is a boundary.
function isDocCommentSearchBoundary(trimmedLine: string): boolean {
  return trimmedLine !== "" && !trimmedLine.startsWith("@");
}

// Reports whether the first content in source after blank lines and an optional shebang supplies overview text.
// An empty file, a shebang alone, an empty comment or a block containing only tag lines leaves the overview missing.
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

// Returns the first nonblank index in lines at or after start (default 0), or undefined when none remains.
// Comments count as meaningful so file-overview detection can inspect the comment itself.
function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}
