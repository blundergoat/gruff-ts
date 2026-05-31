// Class + naming-inventory rules: exported-declaration docs, class/file-name mismatch,
// public-property + readonly candidates, inconsistent casing, acronym case, interface fields.
// Pulls the declaration walkers and casing helpers out of cli.ts so the orchestrator just calls
// the entry points.
import { type FunctionBlock, parameterNames } from "./blocks.ts";
import { type ExportedDeclaration, exportedDeclarations, pushMissingPublicDocFinding } from "./doc-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName, finding, normalizedIdentifier } from "./findings-helpers.ts";
import { pushBooleanPrefixAt, pushNegativeBooleanAt, type NamingSurface } from "./naming-pushers.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

// One identifier observation. `line` is the declaration line in the original source so the casing
// and acronym rules can report a stable, reproducible location.
interface DeclaredIdentifier {
  name: string;
  line: number;
  surface: NamingSurface;
}

// Aggregates `const`/`let`/`var` declarations, callable parameters, and interface fields into a
// single de-duplicated list. The naming rules walk this once instead of re-parsing the file.
export function collectDeclaredIdentifiers(source: string, codeSource: string, blocks: FunctionBlock[]): DeclaredIdentifier[] {
  const inventory: DeclaredIdentifier[] = [];
  const seen = new Set<string>();
  const push = (name: string, line: number, surface: NamingSurface): void => {
    if (!name) return;
    const key = `${name}@${line}@${surface}`;
    if (seen.has(key)) return;
    seen.add(key);
    inventory.push({ name, line, surface });
  };

  for (const match of codeSource.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    push(match[1] ?? "", byteLine(source, match.index ?? 0), "declaration");
  }
  for (const block of blocks) {
    for (const parameter of parameterNames(block.params)) {
      push(parameter.name, block.declarationLine, "parameter");
    }
  }
  for (const fieldMatch of collectInterfaceFieldDeclarations(source, codeSource)) {
    push(fieldMatch.name, fieldMatch.line, "interface-field");
  }
  return inventory;
}

// Walks every interface body line and matches the field declaration regex. Used both for the
// naming inventory (above) and for the per-field interface rules (boolean prefix, negative-boolean).
function collectInterfaceFieldDeclarations(source: string, codeSource: string): DeclaredIdentifier[] {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:/;
  const out: DeclaredIdentifier[] = [];
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const name = sourceLine.match(fieldRegex)?.[1] ?? "";
    if (name) out.push({ name, line: lineIndex + 1, surface: "interface-field" });
  }
  return out;
}

// Strips separators only so `userId`, `user_id`, and `userID` collapse, while `adr013` and
// `adr020` remain distinct domain tokens instead of fake casing variants.
// Two names sharing this key but differing in original form are the casing-drift signal.
function casingCanonicalKey(name: string): string {
  return name.toLowerCase().replace(/[_\-]/g, "");
}

/*
 * Groups identifiers by canonical key, then filters out boundary surfaces before reporting. The
 * split helper flow is intentional: the rule must preserve same-scope drift signal while refusing
 * to command rewrites of constants, DTO fields, or intentionally-unused `_` names. Error behavior:
 * never throws; it reports drift by appending findings only.
 */
export function analyseInconsistentCasing(file: SourceFile, inventory: DeclaredIdentifier[], findings: Finding[]): void {
  for (const entries of declaredIdentifierGroups(inventory).values()) {
    const candidate = inconsistentCasingCandidate(entries);
    if (!candidate) {
      continue;
    }
    findings.push(inconsistentCasingFinding(file, candidate));
  }
}

// Builds canonical-key groups once so the reporting pass can stay focused on rule semantics.
function declaredIdentifierGroups(inventory: DeclaredIdentifier[]): Map<string, DeclaredIdentifier[]> {
  const groups = new Map<string, DeclaredIdentifier[]>();
  for (const entry of inventory) {
    const key = casingCanonicalKey(entry.name);
    if (!key) continue;
    const list = groups.get(key) ?? [];
    list.push(entry);
    groups.set(key, list);
  }
  return groups;
}

// Invariant: returns the exact variant pair to report after boundary-aware suppression has run.
function inconsistentCasingCandidate(entries: DeclaredIdentifier[]): { first: DeclaredIdentifier; second: DeclaredIdentifier; surfaces: string[] } | undefined {
  const reportableEntries = casingReportableEntries(entries);
  const sameSurfaceEntries = sameCasingSurfaceEntries(reportableEntries);
  const surfaces = [...new Set(sameSurfaceEntries.map((entry) => entry.name))].sort();
  if (surfaces.length < 2) {
    return undefined;
  }
  const sorted = [...sameSurfaceEntries].sort((a, b) => a.line - b.line);
  const first = sorted[0];
  const second = sorted.find((entry, index) => index > 0 && entry.name !== first?.name);
  return first && second ? { first, second, surfaces } : undefined;
}

// Builds the stable finding after candidate selection so fingerprint shape stays in one place.
function inconsistentCasingFinding(file: SourceFile, candidate: { first: DeclaredIdentifier; second: DeclaredIdentifier; surfaces: string[] }): Finding {
  return makeFinding({
    ruleId: "naming.inconsistent-casing",
    message: `Identifier \`${candidate.second.name}\` shares a canonical key with \`${candidate.first.name}\` in the same file.`,
    filePath: file.displayPath,
    line: candidate.second.line,
    severity: "advisory",
    pillar: "naming",
    confidence: "medium",
    symbol: candidate.second.name,
    remediation: "Choose one form and use it consistently within the file.",
    metadata: { variants: candidate.surfaces },
  });
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

function* walkInterfaceBodyLines(source: string, codeSource: string): Generator<{ lineIndex: number; sourceLine: string }> {
  const codeLines = codeSource.split(/\r?\n/);
  const sourceLines = source.split(/\r?\n/);
  for (const header of codeSource.matchAll(INTERFACE_HEADER_REGEX)) {
    const headerEnd = (header.index ?? 0) + header[0].length;
    if (codeSource.slice(headerEnd, headerEnd + 30).trimStart().startsWith("[")) {
      continue;
    }
    const headerLineIndex = byteLine(source, headerEnd - 1) - 1;
    const headerLine = codeLines[headerLineIndex] ?? "";
    let depth = 1 + countBraceChange(headerLine.slice(headerLine.lastIndexOf("{") + 1));
    for (let lineIndex = headerLineIndex + 1; depth > 0 && lineIndex < codeLines.length; lineIndex += 1) {
      const codeLine = codeLines[lineIndex] ?? "";
      if (depth === 1) {
        yield { lineIndex, sourceLine: sourceLines[lineIndex] ?? "" };
      }
      depth += countBraceChange(codeLine);
    }
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
export function analyseClassRules(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  analyseExportedDeclarations(file, source, codeSource, findings);
  analysePublicProperties(file, source, codeSource, findings);
  analyseReadonlyCandidates(file, source, codeSource, findings);
}

/*
 * Two rules per exported declaration. Both fire from one walk so the file isn't re-scanned for
 * each rule. Reports the stable `docs.missing-public-doc` and `naming.class-file-mismatch`
 * findings per declaration.
 */
function analyseExportedDeclarations(file: SourceFile, source: string, codeSource: string, findings: Finding[]): void {
  for (const declaration of exportedDeclarations(source, codeSource)) {
    pushMissingPublicDocFinding(file, source, declaration, findings);
    pushClassFileMismatchFinding(file, declaration, findings);
  }
}

/*
 * Compares normalised forms (lowercased, no underscores) so `UserProfile` and `user-profile.ts`
 * match. Reports the stable `naming.class-file-mismatch` finding when the exported class diverges
 * from the file name.
 */
function pushClassFileMismatchFinding(file: SourceFile, declaration: ExportedDeclaration, findings: Finding[]): void {
  const fileName = fileBaseName(file.displayPath);
  if (declaration.kind !== "class" || normalizedIdentifier(declaration.name) === normalizedIdentifier(fileName)) {
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
      remediation: "Rename the class or file so the primary export is easy to locate.",
      metadata: { className: declaration.name, fileName },
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
