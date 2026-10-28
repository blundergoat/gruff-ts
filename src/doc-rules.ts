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
 * Skips functions and interfaces - those have dedicated rules (`docs.missing-exported-function-doc`,
 * `docs.missing-internal-function-doc`, `docs.missing-interface-doc`). Reports the stable
 * `docs.missing-public-doc` finding for classes/types/enums without a leading JSDoc-style block comment.
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

/**
 * The tag rules' `rules.<id>.options.everyCallable` switches, read once per file from the user's config.
 * Both default to false, which keeps the pack on documented exported function declarations.
 */
export interface DocTagRuleSwitches {
  /** `docs.missing-param-tag`'s `everyCallable` option. */
  isParamTagEveryCallable: boolean;
  /** `docs.missing-return-tag`'s `everyCallable` option. */
  isReturnTagEveryCallable: boolean;
}

/*
 * Docblock rule pack. Walks every documented exported function from the shared syntax tree and
 * fires its sub-rules per block in a stable, deterministic emission order
 * (stale-param → missing-param → missing-return → bare-tag).
 * `everyCallable` turns on the tag rules' widened coverage in `pushEveryCallableTagFindings`. On
 * every block, `docs.missing-return-tag`'s switch also infers a returned value from the body, and
 * each tag rule's switch also reports its tags that have no description (`pushBareTagFindings`).
 * `docs.missing-param-tag`'s switch also makes `docs.stale-param-tag` name every stale tag of a
 * block in one finding.
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

/*
 * The tag rules' widened coverage: documented exported arrow and function-expression constants,
 * default exports, callables exported by a later export statement, documented class and
 * object-literal methods, and documented private and nested functions and callable constants,
 * reported at the same severity as exported function declarations. Each tag rule reads these
 * blocks only when its own `everyCallable` switch is on, and `docs.stale-param-tag` never reads
 * them, so the default finding contract stays unchanged.
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

/*
 * Detection anchors on the syntax tree: parameter names are real AST parameters, so parenthesised
 * types such as `(typeof X)[number]` cannot truncate the signature, prose containing `export`
 * inside the docblock cannot suppress a block, and `export async function` plus generic and
 * multi-line signatures are covered. The former regex fallback for parse-less callers is gone -
 * every caller supplies the shared parse.
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

// Reports stale `@param` tags before missing ones because a rename should produce a stable pair:
// reports the "old name is stale" finding first because that order is the review contract.
// With `isNamingEveryStaleTag` (`docs.missing-param-tag`'s `everyCallable` switch), one finding
// names every stale tag instead (`pushEveryStaleParamFinding`).
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

// Complements `pushStaleParamFindings`: reports one finding per declaration that names every
// parameter with no @param tag, in signature order, so reviewers need not re-parse the signature.
// One finding per parameter would share the docblock's line and symbol, so its fingerprint would
// collapse them into the first. `parameter` metadata holds the same names, joined by ", ".
function pushMissingParamFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const missing = block.params.filter((param) => !block.paramTags.includes(param));
  if (missing.length === 0) {
    return;
  }
  const quoted = missing.map((param) => `\`${param}\``).join(", ");
  findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` is missing @param for ${quoted}.`, file, line: block.line, symbol: block.name, parameter: missing.join(", ") }));
}

// `@returns` only required when the signature declares a non-void return type, or, with
// `isInferringReturn` (the rule's `everyCallable` switch), when an unannotated body returns a value.
// `void` is exempt because documenting "returns nothing" is noise. Reports the stable `docs.missing-return-tag`.
function pushMissingReturnFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], isInferringReturn: boolean): void {
  if (!needsReturnTag(block, isInferringReturn)) {
    return;
  }
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` is missing @returns.`, file, line: block.line, symbol: block.name }));
}

// The docblock has no `@returns` tag and the callable returns a value (`isReturningValue`).
function needsReturnTag(block: DocumentedCallableBlock, isInferringReturn: boolean): boolean {
  return !/@returns?\b/.test(block.doc) && isReturningValue(block, isInferringReturn);
}

// Either a declared non-void return type exists, or there is no annotation, inference is on and the
// body returns a value. A declared type always wins over the body. Without inference,
// annotation-less and void returns are exempt.
function isReturningValue(block: DocumentedCallableBlock, isInferringReturn: boolean): boolean {
  if (block.returnType === "") {
    return isInferringReturn && block.hasBodyReturnValue;
  }
  return !/^void\b/.test(block.returnType);
}

/*
 * The tag rules' `everyCallable` check for tags with no description: a `@param` tag naming a real
 * parameter, or a `@returns` tag on a callable that returns a value, with no text after its name or
 * `{Type}` on its own line or on a continuation line. Each rule runs only when its own switch is on,
 * so at default settings a bare tag still satisfies both rules and the default finding contract
 * stays unchanged.
 */
function pushBareTagFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], everyCallable: DocTagRuleSwitches): void {
  if (everyCallable.isParamTagEveryCallable) {
    pushBareParamTagFindings(file, block, findings);
  }
  if (everyCallable.isReturnTagEveryCallable) {
    pushBareReturnTagFinding(file, block, findings);
  }
}

// One `docs.missing-param-tag` finding per parameter whose @param tags are all bare, anchored on the
// first bare tag's line so each of two bare parameters, or a bare one and a missing one, keeps its
// own fingerprint. A tag naming no parameter is left to `docs.stale-param-tag`.
function pushBareParamTagFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const tags = docParamTagOccurrences(block.doc);
  for (const param of block.params) {
    const bareTag = firstBareTag(tags.filter((tag) => tag.name === param));
    if (bareTag) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` has no description for @param \`${param}\`.`, file, line: block.line + bareTag.lineOffset, symbol: block.name, parameter: param }));
    }
  }
}

// Reports the stable `docs.missing-return-tag` finding when the callable returns a value (inference
// is on with the switch) and its @returns tags are all bare, anchored on the first bare tag's line.
function pushBareReturnTagFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  if (!isReturningValue(block, true)) {
    return;
  }
  const bareTag = firstBareTag(docReturnTagOccurrences(block.doc));
  if (bareTag) {
    findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` has no description for @returns.`, file, line: block.line + bareTag.lineOffset, symbol: block.name }));
  }
}

// The first tag when there are tags and none of them is described; one described duplicate is enough.
function firstBareTag<T extends DocTagOccurrence>(tags: T[]): T | undefined {
  return tags.some((tag) => tag.isDescribed) ? undefined : tags[0];
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
    const name = docParamTagParts(line)?.name;
    if (name) {
      names.push(name);
    }
  }
  return names;
}

// Skips the `{Type}` braces before reading the identifier. The two-step approach lets the type
// portion be arbitrarily complex (unions, generics) without breaking the identifier extraction.
// `tail` is the text after the name, where the tag's description starts.
function docParamTagParts(line: string): { name: string; tail: string } | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  const name = rest.match(/^([A-Za-z_$][A-Za-z0-9_$]*)/)?.[1];
  return name ? { name, tail: rest.slice(name.length) } : undefined;
}

// Every `@param` tag with a parameter name, in docblock order, with its line offset and whether a
// description follows the name.
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

// Every `@returns` or `@return` tag, in docblock order, with its line offset and whether a
// description follows the tag or its `{Type}`.
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

// Docblock lines without their leading `*` marker. The doc text already starts after the `/**`
// opener and stops before the closer, so index 0 is the docblock's first line.
function docContentLines(doc: string): string[] {
  return doc.split(/\r?\n/).map((line) => line.replace(/^\s*\*/, "").trim());
}

// True when description text follows the tag on its own line after an optional `-` separator, or on
// a continuation line before the next tag or the end of the docblock.
function hasTagDescription(lines: string[], index: number, tail: string): boolean {
  if (tail.trim().replace(/^-\s*/, "") !== "") {
    return true;
  }
  const nextTag = lines.findIndex((line, lineIndex) => lineIndex > index && line.startsWith("@"));
  return lines.slice(index + 1, nextTag === -1 ? lines.length : nextTag).some((line) => line !== "");
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
