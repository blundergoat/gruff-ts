// JSDoc and exported-declaration documentation rules. Covers `docs.missing-public-doc`,
// `docs.missing-file-overview`, `docs.missing-interface-doc`, and the docblock rule pack
// (stale/missing @param, missing @returns). Stable, deterministic emission order.
import { commentTextAtLine, hasLeadingCommentBeforeLine } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { type DestructuredParameterSlot, documentedDefaultAndLaterExports, documentedExportConstants, documentedExportFunctions, documentedMethods, documentedPrivateCallables, type DocumentedExportFunction, type ParsedScript } from "./parsed-script.ts";
import { isTestPath } from "./project-rules.ts";
import { byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Lightweight shape used by both public-doc and class/file-mismatch rules. Holds the declaration
// keyword (`class`, `interface`, …), the symbol name, and the declaration line for finding anchors.
export interface ExportedDeclaration {
  kind: string;
  name: string;
  line: number;
}

// One parsed `@param` tag from a docblock line, retaining its root name, optional first dotted key,
// full tag path (for stale-tag reporting), and description tail.
interface ParsedDocParamTag {
  name: string;
  fullName: string;
  propertyKey: string | undefined;
  tail: string;
}

// Precomputed leading-comment + signature pair used by every docblock rule (stale-param,
// missing-param, missing-return) so the parser runs only once per source file.
interface DocumentedCallableBlock {
  doc: string;
  hasJsDoc: boolean;
  name: string;
  params: string[];
  destructuredParameters: DestructuredParameterSlot[];
  paramTags: string[];
  parsedParamTags: ParsedDocParamTag[];
  line: number;
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

/**
 * Extracts source-ordered export matches for `class`, `interface`, `type`, `enum`, or `function` followed directly by a simple name.
 *
 * @param source - Original source text supplying one-based line numbers for each match.
 * @param codeSource - Masked text aligned with `source` searched for export declarations.
 * @returns Source-ordered export declaration records, or an empty list when nothing matches.
 */
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

/**
 * Examines source for a top-of-file overview at the first meaningful line after allowing for an optional shebang.
 * Anchors the report at line 1 because the overview belongs at the top of the file.
 *
 * @param file - Source file whose display path anchors the finding.
 * @param source - File content inspected for a leading overview comment.
 * @param findings - Accumulator receiving the stable `docs.missing-file-overview` finding when absent.
 * @returns Nothing. Appends a stable `docs.missing-file-overview` finding to `findings` when the overview is absent.
 */
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

/**
 * Finds interface headers that start a line, allowing leading indentation and a plain `export` prefix on that line.
 *
 * @param source - Original source text supplying line numbers for the interface documentation check.
 * @param codeSource - Masked text searched for interface headers and same-line names.
 * @returns Source-ordered interface declaration records for matched headers.
 */
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
 * Skips `docs.missing-param-tag`, `docs.missing-return-tag`, and extra stale-parameter checks on test files (`isTestPath`),
 * while keeping fixture directories checked and enforcing `/** ... *\/` JSDoc blocks on `//` and `/* *\/` comments when `everyCallable` is enabled.
 *
 * @param file - source file whose display path anchors findings and controls test-path skipping
 * @param findings - report accumulator that receives the docblock findings
 * @param parsed - shared syntax tree providing the documented callables and signatures
 * @param everyCallable - enables wider callable coverage, JSDoc enforcement on slash/block comments, and bare tag checks
 * @returns nothing. Appends the docblock violations to findings.
 */
export function analyseDocRules(file: SourceFile, findings: Finding[], parsed: ParsedScript, everyCallable: DocTagRuleSwitches): void {
  const isTestFile = isTestPath(file.displayPath);
  for (const documentedExport of documentedBlocks(documentedExportFunctions(parsed))) {
    if (documentedExport.hasJsDoc) {
      pushStaleParamFindings(file, documentedExport, findings, everyCallable.isParamTagEveryCallable);
      if (!isTestFile) {
        pushMissingParamFindings(file, documentedExport, findings);
        pushMissingReturnFinding(file, documentedExport, findings);
        pushBareTagFindings(file, documentedExport, findings, everyCallable);
      }
      continue;
    }
    if (!isTestFile) {
      if (everyCallable.isParamTagEveryCallable) {
        pushMissingParamFindings(file, documentedExport, findings);
      }
      if (everyCallable.isReturnTagEveryCallable) {
        pushMissingReturnFinding(file, documentedExport, findings);
      }
    }
  }
  pushEveryCallableTagFindings(file, parsed, everyCallable, findings);
}

/**
 * Extends tag checks to documented arrows, function expressions, default and later exports, methods, and private and nested callables.
 * Skips test files (`isTestPath`) and checks both `/** ... *\/` JSDoc blocks and non-JSDoc (`//` / `/* *\/`) leading comments on non-test source.
 *
 * @param file - source file whose display path anchors the findings and selects test-path skipping
 * @param parsed - shared syntax tree used to find the additional documented callables
 * @param everyCallable - switches that independently enable parameter and return tag checks
 * @param findings - accumulator for violations of the tag contract
 * @returns nothing. Appends findings for enabled checks and leaves the accumulator alone when both switches are off or the file is a test file.
 */
function pushEveryCallableTagFindings(file: SourceFile, parsed: ParsedScript, everyCallable: DocTagRuleSwitches, findings: Finding[]): void {
  if ((!everyCallable.isParamTagEveryCallable && !everyCallable.isReturnTagEveryCallable) || isTestPath(file.displayPath)) {
    return;
  }
  const callables = [...documentedExportConstants(parsed), ...documentedDefaultAndLaterExports(parsed), ...documentedMethods(parsed), ...documentedPrivateCallables(parsed)];
  for (const block of documentedBlocks(callables)) {
    if (block.hasJsDoc && everyCallable.isParamTagEveryCallable) {
      pushStaleParamFindings(file, block, findings, true);
    }
    if (everyCallable.isParamTagEveryCallable) {
      pushMissingParamFindings(file, block, findings);
    }
    if (everyCallable.isReturnTagEveryCallable) {
      pushMissingReturnFinding(file, block, findings);
    }
    if (block.hasJsDoc) {
      pushBareTagFindings(file, block, findings, everyCallable);
    }
  }
}

/**
 * Keeps the parsed declaration details for each block, and extracts parameter tag names for the documentation checks.
 *
 * @param documentedCallables - Callable declarations and their documentation from the shared syntax tree.
 * @returns One check record per input callable in the same order, or an empty array when there are none.
 */
function documentedBlocks(documentedCallables: DocumentedExportFunction[]): DocumentedCallableBlock[] {
  return documentedCallables.map((documented) => {
    const parsedParamTags = documented.hasJsDoc ? docParsedParamTags(documented.docText) : [];
    return {
      doc: documented.docText,
      hasJsDoc: documented.hasJsDoc,
      name: documented.name,
      params: documented.parameterNames,
      destructuredParameters: documented.destructuredParameters,
      paramTags: parsedParamTags.map((tag) => tag.name),
      parsedParamTags,
      line: documented.line,
    };
  });
}

/**
 * Reports documented parameter names absent from the callable signature at `block`'s location.
 * The caller checks for missing tags afterward so that a rename flags the old name first.
 *
 * @param file - Source file whose display path anchors each finding.
 * @param block - Callable docblock and signature details being checked.
 * @param findings - Accumulator receiving the stable `docs.stale-param-tag` findings.
 * @param isNamingEveryStaleTag - Groups distinct stale names into one finding when true; otherwise emits one finding per stale tag.
 * @returns Nothing. Appends stable findings to `findings`, or none if no tags are stale.
 */
function pushStaleParamFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], isNamingEveryStaleTag: boolean): void {
  const staleTags = staleParamTagNames(block);
  if (isNamingEveryStaleTag) {
    pushEveryStaleParamFinding(file, block, findings, [...new Set(staleTags)]);
    return;
  }
  for (const tag of staleTags) {
    findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param tag \`${tag}\`.`, file, line: block.line, symbol: block.name, parameter: tag }));
  }
}

/**
 * Evaluates all `@param` tags on one callable against named parameters and destructured parameter slots.
 * Each destructured slot binds to at most one non-declared JSDoc object name, preferring names whose dotted keys match that slot.
 *
 * @param block - callable signature, destructured parameter slots, and parsed `@param` tags
 * @returns Stale tag names (or dotted `obj.key` paths) in docblock order; empty when every tag matches the signature.
 */
function staleParamTagNames(block: DocumentedCallableBlock): string[] {
  const declaredNames = new Set(block.params);
  const boundSlots = bindDestructuredParamTags(block.parsedParamTags, declaredNames, block.destructuredParameters);
  const stale: string[] = [];
  for (const tag of block.parsedParamTags) {
    if (declaredNames.has(tag.name)) {
      continue;
    }
    const slot = boundSlots.get(tag.name);
    if (slot && (tag.propertyKey === undefined || slot.hasOpenKeys || slot.keys.includes(tag.propertyKey))) {
      continue;
    }
    stale.push(tag.fullName);
  }
  return stale;
}

/**
 * Maps non-declared JSDoc object names to available destructured parameter slots.
 * Pass 1 binds root names whose dotted tags match explicit destructured keys so a stale tag listed earlier cannot steal a slot.
 *
 * @param tags - parsed `@param` tags in docblock order
 * @param declaredNames - ordinary identifier parameter names in the signature
 * @param slots - destructured parameter slots in signature order
 * @returns Map from claimed JSDoc root parameter names to their bound destructured slots.
 */
function bindDestructuredParamTags(
  tags: readonly ParsedDocParamTag[],
  declaredNames: ReadonlySet<string>,
  slots: readonly DestructuredParameterSlot[],
): Map<string, DestructuredParameterSlot> {
  const bound = new Map<string, DestructuredParameterSlot>();
  if (slots.length === 0) {
    return bound;
  }
  const unclaimed = new Set<number>(slots.map((_slot, index) => index));
  const candidateRoots = collectDestructuredCandidateRoots(tags, declaredNames);
  bindMatchingKeyRoots(candidateRoots, slots, unclaimed, bound);
  bindRemainingSlotRoots(candidateRoots, slots, unclaimed, bound);
  return bound;
}

/**
 * Collects distinct non-declared `@param` root names in docblock order alongside whether each root has a root-level tag and any dotted keys.
 *
 * @param tags - parsed `@param` tags in docblock order
 * @param declaredNames - ordinary identifier parameter names already matched by name
 * @returns Map preserving first-seen root order, mapping each candidate root to its root-tag presence and dotted keys.
 */
function collectDestructuredCandidateRoots(
  tags: readonly ParsedDocParamTag[],
  declaredNames: ReadonlySet<string>,
): Map<string, { hasRootTag: boolean; dottedKeys: string[] }> {
  const roots = new Map<string, { hasRootTag: boolean; dottedKeys: string[] }>();
  for (const tag of tags) {
    if (declaredNames.has(tag.name)) {
      continue;
    }
    const entry = roots.get(tag.name) ?? { hasRootTag: false, dottedKeys: [] };
    if (tag.propertyKey === undefined) {
      entry.hasRootTag = true;
    } else {
      entry.dottedKeys.push(tag.propertyKey);
    }
    roots.set(tag.name, entry);
  }
  return roots;
}

/**
 * First pass of destructured slot assignment: binds any candidate root whose dotted keys overlap an unclaimed slot's explicit keys.
 *
 * @param candidateRoots - ordered map of non-declared `@param` root names to their root-tag presence and dotted keys
 * @param slots - destructured parameter slots from the signature
 * @param unclaimed - mutable set of still-available slot indices
 * @param bound - mutable destination map updated with matched root-to-slot bindings
 * @returns Nothing. Updates `unclaimed` and `bound` in place.
 */
function bindMatchingKeyRoots(
  candidateRoots: ReadonlyMap<string, { hasRootTag: boolean; dottedKeys: string[] }>,
  slots: readonly DestructuredParameterSlot[],
  unclaimed: Set<number>,
  bound: Map<string, DestructuredParameterSlot>,
): void {
  for (const [rootName, entry] of candidateRoots) {
    if (entry.dottedKeys.length === 0) {
      continue;
    }
    const slotIndex = [...unclaimed].find((index) => entry.dottedKeys.some((key) => slots[index]?.keys.includes(key) ?? false));
    if (slotIndex !== undefined && slots[slotIndex]) {
      unclaimed.delete(slotIndex);
      bound.set(rootName, slots[slotIndex]);
    }
  }
}

/**
 * Second pass of destructured slot assignment: binds unclaimed slots to unbound candidate roots that carry a root tag or match an open-key slot.
 *
 * @param candidateRoots - ordered map of non-declared `@param` root names to their root-tag presence and dotted keys
 * @param slots - destructured parameter slots from the signature
 * @param unclaimed - mutable set of still-available slot indices
 * @param bound - mutable destination map updated with fallback root-to-slot bindings
 * @returns Nothing. Updates `unclaimed` and `bound` in place.
 */
function bindRemainingSlotRoots(
  candidateRoots: ReadonlyMap<string, { hasRootTag: boolean; dottedKeys: string[] }>,
  slots: readonly DestructuredParameterSlot[],
  unclaimed: Set<number>,
  bound: Map<string, DestructuredParameterSlot>,
): void {
  for (const [rootName, entry] of candidateRoots) {
    if (bound.has(rootName) || unclaimed.size === 0) {
      continue;
    }
    const slotIndex = [...unclaimed].find((index) => entry.hasRootTag || (slots[index]?.hasOpenKeys ?? false));
    if (slotIndex !== undefined && slots[slotIndex]) {
      unclaimed.delete(slotIndex);
      bound.set(rootName, slots[slotIndex]);
    }
  }
}

/**
 * Emits one `docs.stale-param-tag` finding per declaration naming each stale tag once in docblock order.
 * One finding per tag would share the docblock's line and symbol, so its fingerprint would collapse them into the first.
 *
 * @param file - Source file whose display path anchors the finding.
 * @param block - Callable docblock metadata providing the name and declaration line.
 * @param findings - Accumulator receiving the finding, with `parameter` metadata holding the stale names joined by ", ".
 * @param staleTags - Distinct stale `@param` names in docblock order.
 * @returns Nothing. Appends one finding to `findings` when `staleTags` is non-empty.
 */
function pushEveryStaleParamFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[], staleTags: string[]): void {
  if (staleTags.length === 0) {
    return;
  }
  const noun = staleTags.length === 1 ? "tag" : "tags";
  const quoted = staleTags.map((tag) => `\`${tag}\``).join(", ");
  findings.push(docFinding({ ruleId: "docs.stale-param-tag", message: `Docblock for \`${block.name}\` has stale @param ${noun} ${quoted}.`, file, line: block.line, symbol: block.name, parameter: staleTags.join(", ") }));
}

/**
 * Appends one stable `docs.missing-param-tag` finding for all parameters in `block` lacking a JSDoc `@param` tag, in signature order.
 * Enforces the contract that non-JSDoc (`//` or `/* *\/`) comments cannot satisfy parameter tags and receive an explicit JSDoc-block message.
 *
 * @param file - source file whose display path anchors the finding
 * @param block - callable signature and leading comment metadata
 * @param findings - report accumulator receiving the advisory finding
 * @returns Nothing. Appends nothing when all declared parameters have JSDoc `@param` tags.
 */
function pushMissingParamFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const missing = block.hasJsDoc ? block.params.filter((param) => !block.paramTags.includes(param)) : block.params;
  if (missing.length === 0) {
    return;
  }
  const quoted = missing.map((param) => `\`${param}\``).join(", ");
  const message = block.hasJsDoc
    ? `Docblock for \`${block.name}\` is missing @param for ${quoted}.`
    : `Comment for \`${block.name}\` must be a JSDoc block (\`/** ... */\`) with @param for ${quoted}.`;
  findings.push(docFinding({ ruleId: "docs.missing-param-tag", message, file, line: block.line, symbol: block.name, parameter: missing.join(", ") }));
}

/**
 * Appends one stable `docs.missing-return-tag` finding whenever a checked callable lacks a JSDoc `@returns` tag, including `void` callables.
 * Enforces the contract that non-JSDoc (`//` or `/* *\/`) comments always report so slash or block comments cannot bypass return documentation.
 *
 * @param file - source file whose display path anchors the finding
 * @param block - callable signature and leading comment metadata
 * @param findings - report accumulator receiving the advisory finding
 * @returns Nothing. Appends a finding unless `block` carries a JSDoc block containing `@return` or `@returns`.
 */
function pushMissingReturnFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  if (block.hasJsDoc && /@returns?\b/.test(block.doc)) {
    return;
  }
  const message = block.hasJsDoc
    ? `Docblock for \`${block.name}\` is missing @returns.`
    : `Comment for \`${block.name}\` must be a JSDoc block (\`/** ... */\`) with @returns.`;
  findings.push(docFinding({ ruleId: "docs.missing-return-tag", message, file, line: block.line, symbol: block.name }));
}

/**
 * Checks existing tags on declared parameters and on every checked callable's return tags.
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

/**
 * Flags each declared parameter whose existing `@param` tags lack a description on every occurrence.
 * Anchors on the first bare tag so each reported parameter keeps a distinct fingerprint.
 * Tags naming no declared parameter are handled by `docs.stale-param-tag`.
 *
 * @param file - Source file whose display path anchors each finding.
 * @param block - Callable docblock text, line, name, and declared parameter list.
 * @param findings - Accumulator receiving `docs.missing-param-tag` findings.
 * @returns Nothing. Appends one finding to `findings` per undescribed declared parameter.
 */
function pushBareParamTagFindings(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const tags = docParamTagOccurrences(block.doc);
  for (const param of block.params) {
    const bareTag = firstBareTag(tags.filter((tag) => tag.name === param));
    if (bareTag) {
      findings.push(docFinding({ ruleId: "docs.missing-param-tag", message: `Docblock for \`${block.name}\` has no description for @param \`${param}\`.`, file, line: block.line + bareTag.lineOffset, symbol: block.name, parameter: param }));
    }
  }
}

/**
 * Reports a stable `docs.missing-return-tag` finding on the first `@return` or `@returns` line when all existing return tags lack descriptions.
 * Covers every checked callable including `void` so bare `@returns {void}` tags must still explain the contract.
 *
 * @param file - source file whose display path anchors the finding
 * @param block - doc text and signature for the callable being inspected
 * @param findings - report accumulator receiving the bare-tag finding
 * @returns Nothing. Appends a finding only when return tags exist and every occurrence lacks a description.
 */
function pushBareReturnTagFinding(file: SourceFile, block: DocumentedCallableBlock, findings: Finding[]): void {
  const bareTag = firstBareTag(docReturnTagOccurrences(block.doc));
  if (bareTag) {
    findings.push(docFinding({ ruleId: "docs.missing-return-tag", message: `Docblock for \`${block.name}\` has no description for @returns.`, file, line: block.line + bareTag.lineOffset, symbol: block.name }));
  }
}

/**
 * Selects the first tag occurrence only when every entry lacks a description.
 *
 * @param tags - Parsed `@param` or `@returns` tag occurrences for one parameter or callable.
 * @returns First entry in `tags` only when all entries are undescribed; returns `undefined` if `tags` is empty or any entry is described.
 */
function firstBareTag<T extends DocTagOccurrence>(tags: T[]): T | undefined {
  return tags.some((tag) => tag.isDescribed) ? undefined : tags[0];
}

/**
 * Builds an advisory docblock finding whose stable fingerprint derives from the rule, file path, line, and symbol.
 * Leaves the `parameter` metadata field unset under `exactOptionalPropertyTypes` when absent or empty.
 *
 * @param input - Rule identifier, message, source location, symbol, and optional parameter name.
 * @returns Constructed advisory documentation finding.
 */
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

/**
 * Parses the first `@param` tag from each line of a docblock in stable order, preserving dotted property names for destructuring checks.
 *
 * @param doc - raw JSDoc comment text between its opening and closing markers
 * @returns Parsed `@param` tags in source order; empty when no line yields a usable parameter name.
 */
function docParsedParamTags(doc: string): ParsedDocParamTag[] {
  const tags: ParsedDocParamTag[] = [];
  for (const line of doc.split(/\r?\n/)) {
    const parsedTag = docParamTagParts(line);
    if (parsedTag) {
      tags.push(parsedTag);
    }
  }
  return tags;
}

/**
 * Reads one docblock line after its first `@param` marker, skipping an optional brace-delimited type and optional `[...]` brackets.
 * Supports dotted JSDoc property paths such as `options.timeout` so destructured object tags validate cleanly.
 *
 * @param line - single line from a JSDoc comment body
 * @returns Parsed root name, full path, optional first property key, and description tail, or undefined when unusable.
 */
function docParamTagParts(line: string): ParsedDocParamTag | undefined {
  const marker = line.indexOf("@param");
  if (marker === -1) {
    return undefined;
  }
  const rest = stripDocParamType(line.slice(marker + "@param".length).trim());
  const bracketed = rest.startsWith("[");
  const nameSource = bracketed ? rest.slice(1).trimStart() : rest;
  const pathMatch = nameSource.match(/^([A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/);
  const fullName = pathMatch?.[1];
  if (!fullName) {
    return undefined;
  }
  const segments = fullName.split(".");
  const rootName = segments[0] ?? fullName;
  const tailAfterName = nameSource.slice(fullName.length);
  const tail = bracketed ? stripOptionalParamBracketTail(tailAfterName) : tailAfterName;
  return { name: rootName, fullName, propertyKey: segments[1], tail };
}

/**
 * Advances past any default value and closing `]` on a bracketed optional JSDoc parameter such as `[opts.timeout=5000] - wait`.
 *
 * @param tailAfterName - text immediately following the parameter name inside a `[...]` JSDoc parameter token
 * @returns Remaining description tail after the closing `]`, or the input unchanged when no closing bracket exists.
 */
function stripOptionalParamBracketTail(tailAfterName: string): string {
  const closeBracket = tailAfterName.indexOf("]");
  return closeBracket === -1 ? tailAfterName : tailAfterName.slice(closeBracket + 1);
}

/**
 * Inspects the first `@param` marker on each line of a docblock to track whether each tag has a description.
 *
 * @param doc - Raw JSDoc comment body between its opening and closing markers.
 * @returns Tag occurrences with parameter name, line offset, and description presence for lines yielding a name.
 */
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

/**
 * Scans each line of a docblock in order for its first `@returns` or `@return` marker and checks for description text.
 *
 * @param doc - Raw JSDoc comment body between its opening and closing markers.
 * @returns Occurrences in docblock order with line offset and whether description text follows on that line or before the next tag.
 */
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

/**
 * Strips leading `*` markers and outer whitespace from each line of a docblock body.
 * Because `doc` already starts after the opening marker and stops before the closing marker, index 0 is the first line.
 *
 * @param doc - Raw JSDoc comment body between its opening and closing markers.
 * @returns Trimmed content lines without leading `*` prefixes.
 */
function docContentLines(doc: string): string[] {
  return doc.split(/\r?\n/).map((line) => line.replace(/^\s*\*/, "").trim());
}

/**
 * Checks whether a tag carries description text on its own line or on continuation lines before the next `@` tag.
 * A leading `-` alone in the remainder does not count as a description.
 *
 * @param lines - Stripped, trimmed docblock content lines.
 * @param index - Zero-based line index of the current tag in `lines`.
 * @param tail - Text after the tag's name or type on the tag line.
 * @returns True when non-empty description text appears in `tail` or before the next tag line.
 */
function hasTagDescription(lines: string[], index: number, tail: string): boolean {
  if (tail.trim().replace(/^-\s*/, "") !== "") {
    return true;
  }
  const nextTag = lines.findIndex((line, lineIndex) => lineIndex > index && line.startsWith("@"));
  return lines.slice(index + 1, nextTag === -1 ? lines.length : nextTag).some((line) => line !== "");
}

/**
 * Strips a leading brace-delimited JSDoc type annotation from a tag tail.
 *
 * @param rest - Trimmed text immediately after a `@param` or `@returns` marker.
 * @returns Trimmed suffix after the first closing brace, `rest` unchanged if no brace begins it, or an empty string if unclosed.
 */
function stripDocParamType(rest: string): string {
  if (!rest.startsWith(String.fromCharCode(123))) {
    return rest;
  }
  const end = rest.indexOf(String.fromCharCode(125));
  return end === -1 ? "" : rest.slice(end + 1).trim();
}

/**
 * Scans upward above a declaration line to check for a leading JSDoc block opener or `*` continuation line.
 * Blank lines and `@`-prefixed lines are skipped; any other text ends the search without a match.
 *
 * @param source - Full source text containing the declaration.
 * @param line - One-based line number of the declaration.
 * @returns True when the upward scan reaches a JSDoc opener or continuation line before hitting other code or text.
 */
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

/**
 * Checks whether a trimmed line starts a JSDoc opener or `*` continuation marker.
 * Ordinary `//` comments are excluded here and checked by `hasLeadingCommentBeforeLine`.
 *
 * @param trimmedLine - Leading-and-trailing trimmed source line.
 * @returns True when `trimmedLine` starts with a JSDoc opener or `*`.
 */
function isDocCommentLine(trimmedLine: string): boolean {
  return trimmedLine.startsWith("/**") || trimmedLine.startsWith("*");
}

/**
 * Determines whether a trimmed line stops the upward docblock scan after doc-comment lines have been ruled out.
 * Blank lines and `@`-prefixed tag lines allow the search to continue; every other line is a boundary.
 *
 * @param trimmedLine - Leading-and-trailing trimmed source line.
 * @returns True when `trimmedLine` is non-empty and does not start with `@`.
 */
function isDocCommentSearchBoundary(trimmedLine: string): boolean {
  return trimmedLine !== "" && !trimmedLine.startsWith("@");
}

/**
 * Reports whether the first content in `source` after blank lines and an optional shebang supplies overview text.
 * An empty file, a shebang alone, an empty comment, or a block containing only tag lines leaves the overview missing.
 *
 * @param source - Full file text to inspect for a leading overview comment.
 * @returns True when overview comment text is found at the first meaningful line after any shebang.
 */
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

/**
 * Finds the first non-blank line index at or after `start`.
 * Comments count as meaningful so file-overview detection can inspect the comment itself.
 *
 * @param lines - Source lines split on line breaks.
 * @param start - Zero-based starting index in `lines` (defaults to `0`).
 * @returns Index of the first non-blank line at or after `start`, or `undefined` when none remains.
 */
function firstMeaningfulLineIndex(lines: string[], start = 0): number | undefined {
  for (let index = start; index < lines.length; index += 1) {
    if ((lines[index] ?? "").trim() !== "") {
      return index;
    }
  }
  return undefined;
}
