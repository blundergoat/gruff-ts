// Class + naming-inventory rules: exported-declaration docs, class/file-name mismatch,
// public-property + readonly candidates, inconsistent casing, acronym case, interface fields.
// Pulls the declaration walkers and casing helpers out of cli.ts so the orchestrator just calls
// the entry points.
import { type FunctionBlock, parameterNames } from "./blocks.ts";
import { type ExportedDeclaration, exportedDeclarations, pushMissingPublicDocFinding } from "./comment-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName, finding, normalizedIdentifier } from "./findings-helpers.ts";
import { pushAbbreviationAt, pushBooleanPrefixAt, pushNegativeBooleanAt } from "./line-rules.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

// One identifier observation. `line` is the declaration line in the original source so the casing
// and acronym rules can report a stable, reproducible location.
interface DeclaredIdentifier {
  name: string;
  line: number;
}

// Aggregates `const`/`let`/`var` declarations, callable parameters, and interface fields into a
// single de-duplicated list. The naming rules walk this once instead of re-parsing the file.
export function collectDeclaredIdentifiers(source: string, codeSource: string, blocks: FunctionBlock[]): DeclaredIdentifier[] {
  const inventory: DeclaredIdentifier[] = [];
  const seen = new Set<string>();
  const push = (name: string, line: number): void => {
    if (!name) return;
    const key = `${name}@${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    inventory.push({ name, line });
  };

  for (const match of codeSource.matchAll(/\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
    push(match[1] ?? "", byteLine(source, match.index ?? 0));
  }
  for (const block of blocks) {
    for (const parameter of parameterNames(block.params)) {
      push(parameter.name, block.declarationLine);
    }
  }
  for (const fieldMatch of collectInterfaceFieldDeclarations(source, codeSource)) {
    push(fieldMatch.name, fieldMatch.line);
  }
  return inventory;
}

// Walks every interface body line and matches the field declaration regex. Used both for the
// naming inventory (above) and for the per-field interface rules (boolean prefix, abbreviation).
function collectInterfaceFieldDeclarations(source: string, codeSource: string): DeclaredIdentifier[] {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:/;
  const out: DeclaredIdentifier[] = [];
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const name = sourceLine.match(fieldRegex)?.[1] ?? "";
    if (name) out.push({ name, line: lineIndex + 1 });
  }
  return out;
}

// Strips separators and digits so `userId`, `user_id`, and `userID` all collapse to `userid`.
// Two names sharing this key but differing in original form are the casing-drift signal.
function casingCanonicalKey(name: string): string {
  return name.toLowerCase().replace(/[_\-0-9]/g, "");
}

/*
 * Groups identifiers by their canonical key and reports the second-seen variant whenever two or
 * more spellings exist. The "second variant" anchor keeps the stable fingerprint on the diverging
 * identifier rather than the original — useful when the original form is the project convention.
 */
export function analyseInconsistentCasing(file: SourceFile, inventory: DeclaredIdentifier[], findings: Finding[]): void {
  const groups = new Map<string, DeclaredIdentifier[]>();
  for (const entry of inventory) {
    const key = casingCanonicalKey(entry.name);
    if (!key) continue;
    const list = groups.get(key) ?? [];
    list.push(entry);
    groups.set(key, list);
  }
  for (const [, entries] of groups) {
    const surfaces = new Set(entries.map((entry) => entry.name));
    if (surfaces.size < 2) continue;
    const sorted = [...entries].sort((a, b) => a.line - b.line);
    const second = sorted.find((entry, index) => index > 0 && entry.name !== sorted[0]?.name);
    if (!second) continue;
    findings.push(
      makeFinding({
        ruleId: "naming.inconsistent-casing",
        message: `Identifier \`${second.name}\` shares a canonical key with \`${sorted[0]?.name}\` in the same file.`,
        filePath: file.displayPath,
        line: second.line,
        severity: "advisory",
        pillar: "naming",
        confidence: "medium",
        symbol: second.name,
        remediation: "Choose one form and use it consistently within the file.",
        metadata: { variants: [...surfaces].sort() },
      }),
    );
  }
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

// Three-bucket classification used to detect when one project uses both `URL` and `Url` styles —
// the rule flags drift when two of the three buckets are seen for the same acronym in one file.
function acronymCaseClass(token: string): "upper" | "lower" | "title" {
  if (token === token.toUpperCase()) return "upper";
  if (token === token.toLowerCase()) return "lower";
  return "title";
}

/*
 * Reports when an acronym from `config.knownAcronyms` appears in two or more case forms in one
 * file. Like `analyseInconsistentCasing`, the finding anchors on the second occurrence so the
 * stable fingerprint sticks to the divergence rather than the established style.
 */
export function analyseAcronymCase(file: SourceFile, inventory: DeclaredIdentifier[], config: Config, findings: Finding[]): void {
  const observed = new Map<string, Map<string, { name: string; line: number }>>();
  for (const entry of inventory) {
    for (const token of tokensForAcronymCheck(entry.name)) {
      const lower = token.toLowerCase();
      if (!config.knownAcronyms.has(lower)) continue;
      const cases = observed.get(lower) ?? new Map();
      const caseKey = acronymCaseClass(token);
      if (!cases.has(caseKey)) cases.set(caseKey, { name: entry.name, line: entry.line });
      observed.set(lower, cases);
    }
  }
  for (const [acronym, cases] of observed) {
    if (cases.size < 2) continue;
    const occurrences = [...cases.values()].sort((a, b) => a.line - b.line);
    const second = occurrences[1];
    if (!second) continue;
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
}

/*
 * Walks every interface field and runs three checks per field: abbreviation, boolean prefix,
 * negative boolean. The stable ordering matches `pushAbbreviationAt` → `pushBooleanPrefixAt` →
 * `pushNegativeBooleanAt` so multiple findings on one field surface in a deterministic sequence.
 */
export function analyseInterfaceFields(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[]): void {
  const fieldRegex = /^[ \t]*(?:readonly\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\??\s*:\s*([^;]+)/;
  for (const { lineIndex, sourceLine } of walkInterfaceBodyLines(source, codeSource)) {
    const match = sourceLine.match(fieldRegex);
    const name = match?.[1] ?? "";
    if (!name) continue;
    pushAbbreviationAt(file, lineIndex + 1, name, config, findings, "interface-field");
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
