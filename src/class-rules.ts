// Class + naming-inventory rules: exported-declaration docs, class/file-name mismatch,
// public-property + readonly candidates, inconsistent casing, acronym case, interface fields.
// Pulls the declaration walkers and casing helpers out of cli.ts so the orchestrator just calls
// the entry points.
import { exportedDeclarations, pushMissingPublicDocFinding } from "./doc-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName, finding, normalizedIdentifier, parameterNames } from "./findings-helpers.ts";
import { pushBooleanPrefixAt, pushNegativeBooleanAt, type NamingSurface } from "./naming-pushers.ts";
import { callableMatchPoints, declarationOwnershipPoints, type IdentifierOwner, type OwnedDeclarationPoint, type ParsedScript } from "./parsed-script.ts";
import { publicExportDeclarations, type PublicExportDeclaration } from "./public-exports.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

/*
 * One shared naming observation used by casing and acronym diagnostics. Name, line, and surface
 * preserve the report rows users already saw, while syntax-derived owner fields explain which
 * declaration or lexical scope the casing rule compares.
 */
interface DeclaredIdentifier extends IdentifierOwner {
  name: string;
  line: number;
  surface: NamingSurface;
}

const MODULE_NAMING_OWNER: IdentifierOwner = { ownerId: "module", ownerKind: "module" };

// Adds shared syntax owners to the existing text inventory, preserving every name/line/surface row.
// The casing and acronym rules receive one ordered inventory without another parse or AST walk.
export function collectDeclaredIdentifiers(source: string, codeSource: string, parsed: ParsedScript): DeclaredIdentifier[] {
  const inventory: DeclaredIdentifier[] = [];
  const seenIdentifiers = new Set<string>();
  // Records one identifier per (name, line, surface) so overlapping scans stay de-duplicated.
  const recordIdentifier = (name: string, line: number, surface: NamingSurface, owner: IdentifierOwner): void => {
    // Recovered or unsupported declarations can have no simple name, so users see no row for them.
    if (!name) {
      return;
    }
    const observationKey = `${name}@${line}@${surface}`;
    // Overlapping syntax shapes must still produce only one acronym and casing observation.
    if (seenIdentifiers.has(observationKey)) {
      return;
    }
    seenIdentifiers.add(observationKey);
    // Module and anonymous-function rows omit ownerName instead of exposing an undefined field.
    inventory.push({
      name,
      line,
      surface,
      ownerId: owner.ownerId,
      ownerKind: owner.ownerKind,
      ...(owner.ownerName === undefined ? {} : { ownerName: owner.ownerName }),
    });
  };

  const declarationOwnership = declarationOwnershipPoints(parsed);
  const variableOwners = declarationOwnerLookup(declarationOwnership.variableDeclarations);
  const contractFieldOwners = declarationOwnerLookup(declarationOwnership.contractFields);
  // The legacy text matcher remains authoritative so acronym inventory contents do not change.
  for (const match of codeSource.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    // A recovered match without a capture becomes empty and is rejected by recordIdentifier.
    const name = match[1] ?? "";
    // A missing regex index is a recovered start-of-file match, so line one is the safe anchor.
    const line = byteLine(source, match.index ?? 0);
    // A legacy-only text token has no syntax declaration; module ownership preserves acronym input.
    const declarationOwner = variableOwners.get(declarationOwnerKey(name, line)) ?? MODULE_NAMING_OWNER;
    recordIdentifier(name, line, "declaration", declarationOwner);
  }
  // Shared callable points retain one-block-per-line order and the existing parameter text policy.
  for (const callable of callableMatchPoints(parsed)) {
    // Every simple parameter belongs to the callable users see as its nearest naming boundary.
    for (const parameter of parameterNames(callable.params)) {
      recordIdentifier(parameter.name, callable.lineIndex + 1, "parameter", callable);
    }
  }
  // The existing contract walker remains last, preserving the shared inventory sequence exactly.
  for (const field of collectInterfaceFieldDeclarations(source, codeSource)) {
    // A recovered field without an AST point stays visible to acronym checks under module fallback.
    const contractFieldOwner = contractFieldOwners.get(declarationOwnerKey(field.name, field.line)) ?? MODULE_NAMING_OWNER;
    recordIdentifier(field.name, field.line, "interface-field", contractFieldOwner);
  }
  return inventory;
}

// Indexes syntax owners by the legacy name/line tuple so text observations gain stable ownership.
function declarationOwnerLookup(declarations: OwnedDeclarationPoint[]): Map<string, IdentifierOwner> {
  const owners = new Map<string, IdentifierOwner>();
  // Source order wins when recovered syntax produces duplicate name/line rows, matching de-duplication.
  for (const declaration of declarations) {
    const ownerKey = declarationOwnerKey(declaration.name, declaration.line);
    // The first syntax declaration is the same observation the legacy inventory retains.
    if (!owners.has(ownerKey)) {
      owners.set(ownerKey, declaration);
    }
  }
  return owners;
}

// Builds the stable lookup tuple shared by syntax owner rows and legacy text observations.
function declarationOwnerKey(name: string, line: number): string {
  return `${name}@${line}`;
}

// Walks existing interface/type body lines so owner enrichment cannot expand acronym coverage.
function collectInterfaceFieldDeclarations(source: string, codeSource: string): Array<{ name: string; line: number }> {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:/;
  const declarations: Array<{ name: string; line: number }> = [];
  // Each direct body line retains the same source order and line anchor as previous reports.
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    // A line without the supported field prefix produces an empty name and no inventory row.
    const name = sourceLine.match(fieldRegex)?.[1] ?? "";
    // Unsupported or recovered field syntax has no user-facing identifier row.
    if (name) {
      declarations.push({ name, line: lineIndex + 1 });
    }
  }
  return declarations;
}

// Strips separators only so `userId`, `user_id`, and `userID` collapse, while `adr013` and
// `adr020` remain distinct domain tokens instead of fake casing variants.
// Two names sharing this key but differing in original form are the casing-drift signal.
function casingCanonicalKey(name: string): string {
  return name.toLowerCase().replace(/[_\-]/g, "");
}

/*
 * Groups identifiers by owner and canonical key, then filters boundary surfaces before reporting.
 * The split flow preserves drift inside one user-reviewed scope while refusing to command rewrites
 * across DTO/UI contracts, functions, constants, or intentionally-unused `_` names. Error behavior:
 * never throws; it appends findings only. Invariant: one owner-key group yields at most one finding.
 */
export function analyseInconsistentCasing(file: SourceFile, inventory: DeclaredIdentifier[], config: Config, findings: Finding[]): void {
  // Each owner-key group can produce at most one actionable diagnostic for the CLI user.
  for (const entries of declaredIdentifierGroups(inventory).values()) {
    const candidate = inconsistentCasingCandidate(entries, config.acceptedCasingPairs);
    // A single spelling after boundary filtering means the reviewed scope is already consistent.
    if (!candidate) {
      continue;
    }
    findings.push(inconsistentCasingFinding(file, candidate));
  }
}

// Exact pair exemptions are case-insensitive but retain separators.
function isAcceptedCasingPair(first: DeclaredIdentifier, second: DeclaredIdentifier, acceptedPairs: Set<string>): boolean {
  const forward = `${first.name}:${second.name}`.toLowerCase();
  const reverse = `${second.name}:${first.name}`.toLowerCase();
  return acceptedPairs.has(forward) || acceptedPairs.has(reverse);
}

// Builds owner-plus-canonical groups once so the reporting pass cannot compare unrelated surfaces.
function declaredIdentifierGroups(inventory: DeclaredIdentifier[]): Map<string, DeclaredIdentifier[]> {
  const groups = new Map<string, DeclaredIdentifier[]>();
  // Every inventory row keeps its existing source order inside its deterministic owner boundary.
  for (const entry of inventory) {
    const canonicalKey = casingCanonicalKey(entry.name);
    // A recovered empty identifier has no comparison key and cannot help a user fix casing.
    if (!canonicalKey) {
      continue;
    }
    const ownerKey = `${entry.ownerId}\0${canonicalKey}`;
    const list = groups.get(ownerKey) ?? [];
    list.push(entry);
    groups.set(ownerKey, list);
  }
  return groups;
}

// Invariant: returns the exact variant pair to report after boundary-aware suppression has run.
function inconsistentCasingCandidate(entries: DeclaredIdentifier[], acceptedPairs: Set<string>): { first: DeclaredIdentifier; second: DeclaredIdentifier; surfaces: string[] } | undefined {
  const reportableEntries = casingReportableEntries(entries);
  const sameSurfaceEntries = sameCasingSurfaceEntries(reportableEntries);
  const surfaces = [...new Set(sameSurfaceEntries.map((entry) => entry.name))].sort();
  if (surfaces.length < 2) {
    return undefined;
  }
  const sorted = [...sameSurfaceEntries].sort((a, b) => a.line - b.line);
  for (let firstIndex = 0; firstIndex < sorted.length; firstIndex += 1) {
    const first = sorted[firstIndex];
    if (!first) {
      continue;
    }
    const second = sorted.find((entry, secondIndex) => secondIndex > firstIndex && entry.name !== first.name && !isAcceptedCasingPair(first, entry, acceptedPairs));
    if (second) {
      return { first, second, surfaces };
    }
  }
  return undefined;
}

// Builds the stable finding after candidate selection so fingerprint shape stays in one place.
function inconsistentCasingFinding(file: SourceFile, candidate: { first: DeclaredIdentifier; second: DeclaredIdentifier; surfaces: string[] }): Finding {
  const ownerLabel = casingOwnerLabel(candidate.first);
  return makeFinding({
    ruleId: "naming.inconsistent-casing",
    message: `Identifier \`${candidate.second.name}\` shares a canonical key with \`${candidate.first.name}\` within ${ownerLabel}.`,
    filePath: file.displayPath,
    line: candidate.second.line,
    severity: "advisory",
    pillar: "naming",
    confidence: "medium",
    symbol: candidate.second.name,
    remediation: `Choose one form within ${ownerLabel}, or add the exact alias pair to allowlists.acceptedCasingPairs.`,
    metadata: {
      variants: candidate.surfaces,
      ownerId: candidate.first.ownerId,
      ownerKind: candidate.first.ownerKind,
      ...(candidate.first.ownerName === undefined ? {} : { ownerName: candidate.first.ownerName }),
    },
  });
}

// Describes the comparison boundary in the same language a CLI user sees in source and reports.
function casingOwnerLabel(owner: IdentifierOwner): string {
  switch (owner.ownerKind) {
    case "module":
      return "the module scope";
    case "function":
      // Anonymous callbacks still give users a precise lexical boundary without a made-up name.
      return owner.ownerName ? `function \`${owner.ownerName}\`` : "the containing function";
    case "interface":
      // Recovered contract names are absent only on malformed source, where a neutral label is safer.
      return `interface \`${owner.ownerName ?? "anonymous"}\``;
    case "type-literal":
      // Named aliases normally supply this label; malformed source falls back without throwing.
      return `type literal \`${owner.ownerName ?? "anonymous"}\``;
  }
}

// `_event` is the standard intentionally-unused spelling; comparing it with `event` would tell an
// agent to remove useful boundary information rather than fix casing drift.
function casingReportableEntries(entries: DeclaredIdentifier[]): DeclaredIdentifier[] {
  return entries.filter((entry) => !entry.name.startsWith("_"));
}

// Contract fields and SCREAMING_SNAKE constants are boundary surfaces; remove only those entries so
// they do not mask real local drift elsewhere in the same canonical group.
function sameCasingSurfaceEntries(entries: DeclaredIdentifier[]): DeclaredIdentifier[] {
  const hasLocalSurface = entries.some((entry) => entry.surface !== "interface-field" && !isScreamingConstant(entry.name));
  return entries.filter((entry) => {
    if (hasLocalSurface && entry.surface === "interface-field") {
      return false;
    }
    return !(hasLocalSurface && isScreamingConstant(entry.name));
  });
}

// Recognises constant-style identifiers without stripping digits, so `V110` remains one token.
function isScreamingConstant(name: string): boolean {
  return /^[A-Z][A-Z0-9_]*$/.test(name) && /[A-Z]/.test(name);
}

// Splits camelCase, PascalCase, snake_case, and kebab-case into tokens. The regex preserves
// uppercase runs as a single token so the acronym detector sees `URL` and `url` as the same word.
function tokensForAcronymCheck(name: string): string[] {
  const split = name.split(/[_\-]+/).filter(Boolean);
  const tokens: string[] = [];
  for (const part of split) {
    const matches = part.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z0-9]+|[A-Z]+/g);
    if (matches) tokens.push(...matches);
    else tokens.push(part);
  }
  return tokens;
}

// Three-bucket classification used to detect when one project uses both `URL` and `Url` styles -
// the rule flags drift when two of the three buckets are seen for the same acronym in one file.
function acronymCaseClass(token: string): "upper" | "lower" | "title" {
  if (token === token.toUpperCase()) return "upper";
  if (token === token.toLowerCase()) return "lower";
  return "title";
}

/*
 * Reports when an acronym from `config.knownAcronyms` appears as all-caps plus another case form.
 * The all-caps gate exists because lower/title-only forms like `apiToken` beside `googleApiKey`
 * are idiomatic enough to avoid noisy findings. Like `analyseInconsistentCasing`, the finding
 * anchors on the second occurrence so the stable fingerprint sticks to the divergence.
 */
export function analyseAcronymCase(file: SourceFile, inventory: DeclaredIdentifier[], config: Config, findings: Finding[]): void {
  const observed = new Map<string, Map<string, { name: string; line: number }>>();
  for (const entry of inventory) {
    recordAcronymCases(observed, config, entry);
  }
  for (const [acronym, cases] of observed) {
    pushAcronymCaseFinding(file, acronym, cases, findings);
  }
}

// Adds one identifier's acronym tokens to the observed case map, skipping fixture-only constants.
function recordAcronymCases(observed: Map<string, Map<string, { name: string; line: number }>>, config: Config, entry: DeclaredIdentifier): void {
  if (isFixtureIdentifier(entry.name)) {
    return;
  }
  for (const token of tokensForAcronymCheck(entry.name)) {
    const lower = token.toLowerCase();
    if (!config.knownAcronyms.has(lower)) continue;
    const cases = observed.get(lower) ?? new Map();
    const caseKey = acronymCaseClass(token);
    if (!cases.has(caseKey)) cases.set(caseKey, { name: entry.name, line: entry.line });
    observed.set(lower, cases);
  }
}

// Reports the stable acronym-case finding only after the all-caps-vs-other drift gate passes.
function pushAcronymCaseFinding(file: SourceFile, acronym: string, cases: Map<string, { name: string; line: number }>, findings: Finding[]): void {
  if (!shouldReportAcronymCase(cases)) {
    return;
  }
  const occurrences = [...cases.values()].sort((a, b) => a.line - b.line);
  const second = occurrences[1];
  if (!second) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.acronym-case",
      message: `Acronym \`${acronym.toUpperCase()}\` appears in multiple cases in this file.`,
      filePath: file.displayPath,
      line: second.line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: second.name,
      remediation: "Use one casing for each acronym throughout the file.",
      metadata: { acronym: acronym.toUpperCase(), variants: [...cases.keys()].sort() },
    }),
  );
}

// Requires an upper-case acronym plus a different case; lower/title-only mixes stay quiet.
function shouldReportAcronymCase(cases: Map<string, { name: string; line: number }>): boolean {
  return cases.has("upper") && cases.size >= 2;
}

// Fixture constants often use SCREAMING_SNAKE vendor token names that should not force local
// camelCase variables to adopt the same acronym style.
function isFixtureIdentifier(name: string): boolean {
  return /(?:^|[_-])fixture(?:[_-]|$)/i.test(name);
}

/*
 * Walks every interface field and runs two checks per boolean field: boolean prefix and
 * negative boolean. The stable ordering matches `pushBooleanPrefixAt` → `pushNegativeBooleanAt`
 * so multiple findings on one field surface in a deterministic sequence.
 */
export function analyseInterfaceFields(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:\s*([^;]+)/;
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const match = sourceLine.match(fieldRegex);
    const name = match?.[1] ?? "";
    if (!name) continue;
    if (/^\s*boolean\b/.test(match?.[2] ?? "")) {
      pushBooleanPrefixAt(file, lineIndex + 1, name, config, findings, "interface-field");
      pushNegativeBooleanAt(file, lineIndex + 1, name, config, findings, "interface-field");
    }
  }
}

const INTERFACE_HEADER_REGEX = /\b(?:export\s+)?(?:interface\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?(?:\s+extends\s+[^{]+)?|type\s+[A-Za-z_$][A-Za-z0-9_$]*(?:\s*<[^>]*>)?\s*=\s*)\s*\{/g;

// Streams the depth-1 member lines of every interface/type-literal body so the field rules see
// each declaration exactly once. Mapped types (`{ [K in ...] }`) are skipped - no field names there.
function* walkInterfaceBodyLines(source: string, codeSource: string): Generator<{ lineIndex: number; sourceLine: string }> {
  const codeLines = codeSource.split(/\r?\n/);
  const sourceLines = source.split(/\r?\n/);
  for (const header of codeSource.matchAll(INTERFACE_HEADER_REGEX)) {
    const headerEnd = (header.index ?? 0) + header[0].length;
    // An index-signature-first body is a mapped type, not a field list the naming rules can judge.
    if (codeSource.slice(headerEnd, headerEnd + 30).trimStart().startsWith("[")) {
      continue;
    }
    yield* interfaceBodyMemberLines(codeLines, sourceLines, byteLine(source, headerEnd - 1) - 1);
  }
}

// Walks one body from its header line, yielding lines while brace depth stays at the member level.
function* interfaceBodyMemberLines(codeLines: string[], sourceLines: string[], headerLineIndex: number): Generator<{ lineIndex: number; sourceLine: string }> {
  const headerLine = codeLines[headerLineIndex] ?? "";
  let depth = 1 + countBraceChange(headerLine.slice(headerLine.lastIndexOf("{") + 1));
  for (let lineIndex = headerLineIndex + 1; depth > 0 && lineIndex < codeLines.length; lineIndex += 1) {
    const codeLine = codeLines[lineIndex] ?? "";
    // Depth 1 means we are directly inside the declaration body, where the member lines live.
    if (depth === 1) {
      yield { lineIndex, sourceLine: sourceLines[lineIndex] ?? "" };
    }
    depth += countBraceChange(codeLine);
  }
}

// Net brace delta (`{` minus `}`) for a slice of text. Used by the interface-body walker to track
// nesting depth without parsing the source twice.
function countBraceChange(text: string): number {
  let delta = 0;
  for (const character of text) {
    if (character === "{") {
      delta += 1;
    } else if (character === "}") {
      delta -= 1;
    }
  }
  return delta;
}

/*
 * Three class-pillar rules in their stable, deterministic emission order: exported-declaration
 * docs and file-name mismatch, public-property, readonly candidates.
 */
export function analyseClassRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  analyseExportedDeclarations(file, source, codeSource, config, findings, parsed);
  analysePublicProperties(file, source, codeSource, findings);
  analyseReadonlyCandidates(file, source, codeSource, findings);
}

/*
 * Keeps public-doc checks on direct exports, then evaluates class/file naming against the complete
 * syntax inventory so reports cover default/re-export forms without changing the documentation contract.
 */
function analyseExportedDeclarations(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  const directlyExportedDeclarations = exportedDeclarations(source, codeSource);
  // Public-doc findings retain their existing direct-export policy and deterministic source order.
  for (const declaration of directlyExportedDeclarations) {
    pushMissingPublicDocFinding(file, source, declaration, findings);
  }
  // Direct internal callers without a parse retain the legacy five-kind inventory; normal scans use syntax.
  const modulePublicDeclarations = parsed
    ? publicExportDeclarations(parsed)
    : directlyExportedDeclarations.map((declaration) => ({ ...declaration, kind: declaration.kind as PublicExportDeclaration["kind"] }));
  pushClassFileMismatchFinding(file, modulePublicDeclarations, config, findings);
}

/*
 * Reports a normalized class/file mismatch only when one named class is the module's sole public
 * declaration, keeping feature modules quiet while preserving the stable finding anchor.
 */
function pushClassFileMismatchFinding(file: SourceFile, publicDeclarations: PublicExportDeclaration[], config: Config, findings: Finding[]): void {
  // Feature modules with a second public declaration do not claim one primary class-to-file convention.
  if (publicDeclarations.length !== 1) {
    return;
  }
  const declaration = publicDeclarations[0];
  // Anonymous defaults and non-class exports have no named class for a user to align with the file.
  if (!declaration || declaration.kind !== "class" || declaration.name === "default") {
    return;
  }
  const fileName = fileBaseName(file.displayPath);
  const acceptedPair = `${fileName}:${declaration.name}`.toLowerCase();
  // Pair-level configuration preserves an intentional feature-file/class-role convention narrowly.
  if (config.acceptedClassFilePairs.has(acceptedPair)) {
    return;
  }
  // A normalized name match already lets a report user locate the class from the file name.
  if (normalizedIdentifier(declaration.name) === normalizedIdentifier(fileName)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.class-file-mismatch",
      message: `Exported class \`${declaration.name}\` does not match file name \`${fileName}\`.`,
      filePath: file.displayPath,
      line: declaration.line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: declaration.name,
      remediation: "Rename the class or file, or add the exact fileBase:ClassName pair to allowlists.acceptedClassFilePairs.",
      metadata: {
        className: declaration.name,
        fileName,
        candidatePrimaryExport: true,
        publicExports: publicDeclarations.map((publicDeclaration) => `${publicDeclaration.kind}:${publicDeclaration.name}`).sort(),
      },
    }),
  );
}

// Targets `public foo =` and `public foo:` patterns. The rule message recommends `readonly` or
// accessors because both preserve the field's invariant better than a raw public field, and
// reports each match as a stable `modernisation.public-property` finding.
function analysePublicProperties(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const publicProperty = /\bpublic\s+[A-Za-z_$][A-Za-z0-9_$]*\s*[=:]/g;
  for (const match of codeSource.matchAll(publicProperty)) {
    findings.push(finding({ ruleId: "modernisation.public-property", message: "Public class property exposes representation; prefer readonly or accessors when invariants matter.", file, line: byteLine(source, match.index ?? 0), severity: "advisory", pillar: "modernisation" }));
  }
}

// Visibility-modifier fields without `readonly`. The negative lookahead skips already-readonly
// properties; each remaining match reports a stable `modernisation.readonly-property-candidate`.
function analyseReadonlyCandidates(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  const readonlyCandidate = /\b(?:public|private|protected)\s+(?!readonly\b)([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*[^;=\n]+;/g;
  for (const match of codeSource.matchAll(readonlyCandidate)) {
    const name = match[1] ?? "";
    findings.push(
      makeFinding({
        ruleId: "modernisation.readonly-property-candidate",
        message: `Property \`${name}\` can be marked readonly if it is only assigned during construction.`,
        filePath: file.displayPath,
        line: byteLine(source, match.index ?? 0),
        severity: "advisory",
        pillar: "modernisation",
        confidence: "medium",
        symbol: name,
        remediation: "Mark the property readonly when mutation is not part of the type contract.",
      }),
    );
  }
}
