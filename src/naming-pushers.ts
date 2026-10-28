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

/*
 * Allows the standard `i`, `j`, `k` loop counters and anything on `acceptedAbbreviations`. Reports
 * `naming.short-variable` for any other one or two character name as a stable advisory finding.
 * `loopBodyLineCount` is the for-of caller's signal: when the binding came from a `for (const X of
 * Y) { … }` head and the body spans ≤ 10 lines, the rule suppresses the finding because the name's
 * lifetime is locally obvious. Other call sites (declaration, parameter, destructure) pass undefined.
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

/*
 * Reports `naming.identifier-quality` when a name resolves to a generic variant via
 * `identifierQualityVariant` (placeholder names from config, or built-in low-info forms like `data`).
 * The stable `variant` metadata lets downstream tools group by category.
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

// Returns `"generic"` for low-information names from the configured set, `"numbered"` for
// numbered placeholder stems such as `foo1` / `mock2`, or undefined when the name is acceptable.
// Domain tokens with meaningful digits (`adr020`, `step0`, `V110`) are not placeholder names.
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
