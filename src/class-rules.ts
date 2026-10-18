// Class rules: exported-declaration docs, class/file-name mismatch and readonly candidates.
// Pulls the declaration walkers out of cli.ts so the orchestrator just calls the entry point.
import { exportedDeclarations, pushMissingPublicDocFinding } from "./doc-rules.ts";
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { fileBaseName, normalizedIdentifier } from "./findings-helpers.ts";
import { type ParsedScript } from "./parsed-script.ts";
import { publicExportDeclarations, type PublicExportDeclaration } from "./public-exports.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

/*
 * Class-pillar rules in their stable, deterministic emission order: exported-declaration
 * docs and file-name mismatch, then readonly candidates.
 */
export function analyseClassRules(file: SourceFile, source: string, codeSource: string, config: Config, findings: Finding[], parsed?: ParsedScript): void {
  analyseExportedDeclarations(file, source, codeSource, config, findings, parsed);
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
  // A normalized name match already lets a report user locate the class from the file name. An
  // alias counts too: `export { Foo as Bar }` in `bar.ts` already advertises the matching name, so
  // telling the reader to rename would undo an alignment they have made.
  const publicNames = declaration.exportedName === undefined ? [declaration.name] : [declaration.name, declaration.exportedName];
  if (publicNames.some((publicName) => normalizedIdentifier(publicName) === normalizedIdentifier(fileName))) {
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
