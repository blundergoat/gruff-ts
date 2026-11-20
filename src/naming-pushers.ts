// Shared "push a naming finding at this line" helpers. Used both by the per-line walker in
// line-rules.ts and by the parameter walker in analyser.ts. Stable metadata.surface distinguishes
// call sites while every finding uses the same fingerprint identity.
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import type { Config, Finding } from "./types.ts";

/**
 * Stable label for the call-site that emitted a naming finding. Surfaces in `metadata.surface`
 * so downstream tooling can split per-pillar reports by origin without re-running the analyser.
 */
export type NamingSurface = "declaration" | "parameter" | "destructure";

/**
 * Checks whether a short name qualifies for a naming.short-variable advisory.
 * Names longer than two characters and i, j and k are exempt.
 *
 * @param file - supplies the display path for the advisory
 * @param line - source line to report with the advisory
 * @param name - identifier to check for sufficient length or an exemption
 * @param config - supplies accepted abbreviations, checked against the lowercased name
 * @param findings - receives the stable advisory when the name fails the check
 * @param surface - records whether the name came from a declaration, parameter or destructure
 * @param loopBodyLineCount - for-of body code-line count. At most 10 exempts the name. Undefined gives no loop exemption.
 * @returns - returns nothing. Appends an advisory to findings when the name is too short and has no exemption.
 */
export function pushShortVariableAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface, loopBodyLineCount?: number): void {
  if (loopBodyLineCount !== undefined && loopBodyLineCount <= 10) {
    return;
  }
  if (name.length > 2 || ["i", "j", "k"].includes(name) || config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.short-variable",
      message: `Variable \`${name}\` is too short to explain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a name that describes the domain role.",
      metadata: { surface },
    }),
  );
}

/**
 * Checks for generic or numbered placeholder names, including built-in numbered stems.
 *
 * @param file - supplies the display path for the advisory
 * @param line - source line to report with the advisory
 * @param name - identifier to check against the placeholder rules
 * @param config - supplies configured placeholders for full-name and numbered-stem checks
 * @param findings - receives the advisory with stable variant metadata when a placeholder matches
 * @param surface - records whether the name came from a declaration, parameter or destructure
 * @returns - returns nothing. Appends one advisory for a matched placeholder and leaves findings unchanged otherwise.
 */
export function pushIdentifierQualityAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  const variant = identifierQualityVariant(name, config.placeholderNames);
  if (!variant) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.identifier-quality",
      message: `Identifier \`${name}\` is a ${variant} name that does not explain domain intent.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use an identifier that names the domain role.",
      metadata: { identifierName: name, variant, surface },
    }),
  );
}

// Returns generic when the lowercased name is in placeholderNames. Otherwise checks for a numbered placeholder.
// A numbered name ends in digits after a stem made of ASCII letters, underscores or dollar signs.
// Returns numbered when that lowercased stem is in either placeholder set. Undefined means no identifier-quality advisory.
function identifierQualityVariant(name: string, placeholderNames: Set<string>): string | undefined {
  if (placeholderNames.has(name.toLowerCase())) {
    return "generic";
  }
  const numbered = name.match(/^([A-Za-z_$]+)[0-9]+$/);
  const numberedStem = numbered?.[1]?.toLowerCase() ?? "";
  if (numberedStem && (placeholderNames.has(numberedStem) || NUMBERED_PLACEHOLDER_STEMS.has(numberedStem))) {
    return "numbered";
  }
  return undefined;
}

const NUMBERED_PLACEHOLDER_STEMS = new Set([
  "arg",
  "bar",
  "baz",
  "data",
  "fixture",
  "foo",
  "item",
  "mock",
  "obj",
  "object",
  "param",
  "stub",
  "temp",
  "test",
  "thing",
  "tmp",
  "value",
  "var",
]);
