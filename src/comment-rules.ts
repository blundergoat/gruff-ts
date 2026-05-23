// Every documentation, comment-quality, fixture-purpose, stale-reference, context-doc,
// magic-threshold, and restating-signature rule. The biggest of the rule-pack modules; the
// orchestrator `analyseCommentQualityRules` fans out per-comment / per-declaration / per-block
// passes that all share a stable, deterministic emission order.
import { existsSync } from "node:fs";
import { dirname as dirnamePath, resolve } from "node:path";
import { cwd } from "node:process";
import { type FunctionBlock } from "./blocks.ts";
import { type CommentRecord } from "./comment-scanner.ts";
import { type SourceFile } from "./discovery.ts";
import { type ExportedDeclaration, interfaceDeclarations } from "./doc-rules.ts";
import { type CommentedDeclaration, pushDeclarationContextFindings, pushFunctionContextFindings } from "./context-doc-rules.ts";
import { makeFinding } from "./findings.ts";
import { splitIdentifierWords } from "./findings-helpers.ts";
import { pushFixturePurposeFindings } from "./fixture-purpose-rules.ts";
import { isTestPath } from "./project-rules.ts";
import { ruleDescriptors } from "./rules.ts";
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

type MagicThresholdCandidate = {
  label: string;
  value: string;
  kind: string;
};

const DESCRIPTOR_IDS = new Set(ruleDescriptors().map((descriptor) => descriptor.ruleId));
const CLI_FLAGS = knownCliFlags();


/*
 * Coordinator for every comment-quality rule. Comments and declarations are parsed once and the
 * rule descriptor + CLI flag sets are computed once, so every sub-rule sees the same stable inputs.
 */
export function analyseCommentQualityRules(input: CommentQualityRuleInput): void {
  const { file, source, codeSource, blocks, comments, config, findings } = input;
  const lines = source.split(/\r?\n/);
  const declarations = commentedDeclarations(blocks, interfaceDeclarations(source, codeSource));

  analyseStandaloneCommentQuality(file, comments, DESCRIPTOR_IDS, CLI_FLAGS, findings);
  analyseCommentedDeclarationQuality(file, lines, comments, declarations, findings);
  analyseFunctionContextCommentQuality({ file, lines, comments, blocks, config, findings });
  pushMagicThresholdFindings(file, lines, codeSource, comments, findings);
  pushFixturePurposeFindings({ file, source, codeSource, lines, comments, blocks, config, findings });
}

/*
 * Five per-comment rules (task tracking, suppression rationale, stale file refs, stale rule refs,
 * stale CLI flag refs) that run on every comment regardless of whether it documents a declaration.
 * Stable, deterministic emission order across the five sub-checks.
 */
function analyseStandaloneCommentQuality(file: SourceFile, comments: CommentRecord[], ruleIdSet: Set<string>, optionFlagSet: Set<string>, findings: Finding[]): void {
  for (const comment of comments) {
    pushTodoWithoutTrackingFinding(file, comment, findings);
    pushSuppressionWithoutRationaleFinding(file, comment, findings);
    pushStaleFileReferenceFindings(file, comment, findings);
    pushStaleRuleReferenceFindings(file, comment, ruleIdSet, findings);
    pushStaleCliFlagReferenceFindings(file, comment, optionFlagSet, findings);
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
    if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
      pushDeclarationContextFindings(file, lines, declaration, comment, findings);
    }
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
 * rationale is attached - the false-positive escape hatch is explicit because TS suppression
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
// excluded - they have their own dedicated rule (`pushTsDirectiveFinding`).
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
function pushStaleRuleReferenceFindings(file: SourceFile, comment: CommentRecord, ruleIdSet: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/\b((?:complexity|dead-code|design|docs|modernisation|naming|security|sensitive-data|size|test-quality|waste)\.[a-z0-9-]+)\b/g)) {
    const ruleId = match[1] ?? "";
    if (ruleIdSet.has(ruleId)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown rule id \`${ruleId}\`.`, { staleReference: ruleId, referenceType: "ruleId" }));
  }
}

/*
 * Each double-dash option in a comment must appear in `cliFlags` (parsed from the CLI source) or
 * it counts as a stale reference. The rule's value is catching gruff-ts maintainers who rename a
 * flag and forget to update its references - so the check only fires when the comment also names
 * gruff-ts (or invokes the gruff/gruff-ts binary). In any other project, flag references belong to
 * that project's CLI, not gruff-ts, and validating them against gruff-ts's own option surface
 * produces only noise. Reports the stable `docs.stale-comment` finding for each unknown option.
 */
function pushStaleCliFlagReferenceFindings(file: SourceFile, comment: CommentRecord, optionFlagSet: Set<string>, findings: Finding[]): void {
  if (isHistoricalContextComment(comment.text)) {
    return;
  }
  if (!mentionsGruffCli(comment.text)) {
    return;
  }
  for (const match of comment.text.matchAll(/(?<![A-Za-z0-9])--[a-z][a-z0-9-]*/g)) {
    const flag = match[0] ?? "";
    if (optionFlagSet.has(flag)) {
      continue;
    }
    findings.push(staleCommentFinding(file, comment, `Comment references unknown CLI flag \`${flag}\`.`, { staleReference: flag, referenceType: "cliFlag" }));
  }
}

// True when the comment names the gruff-ts CLI by binary or product name. Acts as the activation
// gate for the unknown-CLI-flag check; comments that talk about other tools' flags never trip it.
function mentionsGruffCli(text: string): boolean {
  return /\bgruff(?:-ts)?\b/i.test(text);
}

// Static list of valid CLI options. Hand-curated rather than parsed from the Commander definition
// at runtime because the stale-CLI-flag rule must not depend on import order - both files would
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
  const directBackticked = text.match(new RegExp(["\\b", kind, "\\s+`([A-Za-z_$][A-Za-z0-9_$]*)`"].join(""), "i"));
  if (directBackticked?.[1]) {
    return directBackticked[1];
  }
  const directCodeLike = text.match(new RegExp(["\\b", kind, "\\s+([A-Za-z_$][A-Za-z0-9_$]*)"].join(""), "i"));
  if (directCodeLike?.[1] && isCodeLikeIdentifier(directCodeLike[1])) {
    return directCodeLike[1];
  }
  return leadingReferencedDeclarationName(text, kind);
}

// The leading form is intentionally stricter than `<kind> name`: ordinary English such as
// "Read-only filesystem interface" or "Symlink helper" must not become a stale-symbol finding.
function leadingReferencedDeclarationName(text: string, kind: CommentedDeclaration["kind"]): string | undefined {
  const backticked = text.match(new RegExp(["^`([A-Za-z_$][A-Za-z0-9_$]*)`\\s+(?:", kind, "|helper|method|contract|type)\\b"].join(""), "i"));
  if (backticked?.[1]) {
    return backticked[1];
  }
  const codeLike = text.match(new RegExp(["^([A-Za-z_$][A-Za-z0-9_$]*)\\s+(?:", kind, "|helper|method|contract|type)\\b"].join(""), "i"));
  if (codeLike?.[1] && isCodeLikeIdentifier(codeLike[1])) {
    return codeLike[1];
  }
  return undefined;
}

// Requires a real identifier marker beyond normal prose capitalization.
function isCodeLikeIdentifier(name: string): boolean {
  return /[A-Z].*[A-Z]|[a-z][A-Z]|[_$]|\d/.test(name);
}

/*
 * Public block-doc comments are exempted on purpose because their first words usually mirror the
 * API surface - that's the documented JSDoc convention, not a useless docblock. Reports the stable
 * `docs.useless-docblock` finding otherwise.
 */
function pushRestatingSignatureCommentFinding(file: SourceFile, comment: CommentRecord, declaration: CommentedDeclaration, findings: Finding[]): void {
  if (declaration.kind === "function" && declaration.isPublic && comment.kind === "block") {
    return;
  }
  if (!isRestatingSignatureComment(comment.text, declaration.name, declaration.kind)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "docs.useless-docblock",
      message: `Comment for \`${declaration.name}\` only restates the signature.`,
      filePath: file.displayPath,
      line: comment.line,
      severity: "advisory",
      pillar: "documentation",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Update the JSDoc so it documents the current signature and return value.",
      metadata: {},
    }),
  );
}

/*
 * Test files are exempt because their `expect(x).toBe(42)` patterns legitimately contain
 * unexplained numbers. For every production source line, the rule looks for either a named
 * threshold/limit/cap or a `threshold(config, …)` default call, then checks that a nearby comment
 * explains it. Reports the stable `docs.magic-threshold-without-rationale` finding.
 */
function pushMagicThresholdFindings(file: SourceFile, lines: string[], codeSource: string, comments: CommentRecord[], findings: Finding[]): void {
  if (isTestPath(file.displayPath) || !hasMagicThresholdSignal(codeSource)) {
    return;
  }
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

// Cheap whole-file preflight for the two shapes `magicThresholdCandidate` can report.
function hasMagicThresholdSignal(codeSource: string): boolean {
  return /\bthreshold\s*\(/.test(codeSource) || /\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:Threshold|Limit|Cap|Budget|Timeout|Tolerance|Weight|Score|Max|Min|Default|Entropy|Length)[A-Za-z0-9_$]*\b/i.test(codeSource);
}

// Two candidate sources: a named constant (`const maxThings = N`) or a `threshold()` default call.
// Either is treated as policy-shaped numeric - ordinary arithmetic constants stay quiet.
function magicThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  return namedThresholdCandidate(rawLine, codeLine) ?? configDefaultThresholdCandidate(rawLine, codeLine);
}

// Identifiers ending in Threshold/Limit/Cap/Budget/Timeout/Tolerance/Weight/Score/Max/Min/Default/
// Entropy/Length signal "policy number". `-1`, `0`, `1`, `2` are exempt because they're usually sentinels.
// Gates on the masked `codeLine` so template-literal fixture content (where the same line appears as
// source text but inside a backtick) does not trip the rule.
function namedThresholdCandidate(rawLine: string, codeLine: string): MagicThresholdCandidate | undefined {
  if (!/\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*(?:Threshold|Limit|Cap|Budget|Timeout|Tolerance|Weight|Score|Max|Min|Default|Entropy|Length)[A-Za-z0-9_$]*\b/i.test(codeLine)) {
    return undefined;
  }
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
// call shape must originate in executable code - masked code is the only stable signal for that.
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

// Vocabulary used by the magic-threshold rule. A numeric constant followed by a comment containing
// any of these words is treated as "explained".
function hasThresholdRationaleMarker(text: string): boolean {
  return /\b(?:threshold|limit|cap|budget|tuned|default|because|empirical)\b/i.test(text);
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
// signature detection - covers `findings`/`finding`, `imports`/`import`, etc.
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
// shapes - the omission keeps stable fingerprints round-tripping across baseline reads and writes.
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
