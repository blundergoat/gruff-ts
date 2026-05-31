// Shared "push a naming finding at this line" helpers. Used both by the per-line walker in
// line-rules.ts and by the parameter / interface-field walkers in cli.ts and class-rules.ts. Stable
// metadata.surface distinguishes call sites while every finding uses the same fingerprint identity.
import { type SourceFile } from "./discovery.ts";
import { makeFinding } from "./findings.ts";
import { escapeRegex } from "./findings-helpers.ts";
import type { Config, Finding } from "./types.ts";

/**
 * Stable label for the call-site that emitted a naming finding. Surfaces in `metadata.surface`
 * so downstream tooling can split per-pillar reports by origin without re-running the analyser.
 */
export type NamingSurface = "declaration" | "parameter" | "destructure" | "interface-field";

/*
 * Negative-framed booleans (disableX, noX, preventX, …) read as double negations at call sites.
 * `negativeBooleanAllowed` is the user-curated exemption list. Reports the stable
 * `naming.negative-boolean` finding.
 */
export function pushNegativeBooleanAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (!/^(?:disable|no|not|prevent|skip|disallow)[A-Z]/.test(name)) {
    return;
  }
  if (config.negativeBooleanAllowed.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.negative-boolean",
      message: `Boolean identifier \`${name}\` is framed as a negation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Invert the framing so callers do not read a double negation.",
      metadata: { identifierName: name, surface },
    }),
  );
}

/*
 * Booleans should announce their boolean-ness with an `is`/`has`/`can`/… prefix. The accepted set
 * lives in `config.booleanPrefixes` so projects can tune it. Reports the stable
 * `naming.boolean-prefix` finding.
 */
export function pushBooleanPrefixAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (hasBooleanPrefix(name, config.booleanPrefixes) || isAcceptedBooleanStateName(name) || isAcceptedContractBooleanName(name, config, surface)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.boolean-prefix",
      message: `Boolean identifier \`${name}\` should use an intent-revealing prefix.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use a prefix such as is, has, can, should, or will.",
      metadata: { identifierName: name, surface },
    }),
  );
}

const ACCEPTED_BOOLEAN_STATE_NAMES = new Set(["acknowledged", "exists", "validated", "detected", "resolved", "selected", "installed"]);
const ACCEPTED_BOOLEAN_STATE_SUFFIXES = ["Available", "Required", "Validated", "Detected", "Resolved", "Selected", "Installed"];
// Some booleans are state adjectives rather than predicate phrases. Keep this list deliberately
// narrow so vague local names such as `ready` or `enabled` still get the maintainability prompt.
function isAcceptedBooleanStateName(name: string): boolean {
  return ACCEPTED_BOOLEAN_STATE_NAMES.has(name.toLowerCase()) || ACCEPTED_BOOLEAN_STATE_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

// CLI option bags, DTOs, and schema fields often must expose exact external key names such as
// `verbose` or `ok`. Limit the exact-name exemption to contract fields so ordinary locals still
// need predicate-style names.
function isAcceptedContractBooleanName(name: string, config: Config, surface: NamingSurface): boolean {
  return surface === "interface-field" && config.acceptedBooleanNames.has(name.toLowerCase());
}

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

const BOOLEAN_PREFIX_REGEX_CACHE = new WeakMap<Set<string>, RegExp | null>();

// Tests the cached prefix regex from `booleanPrefixRegex`. A null regex (empty prefix set) is
// treated as "no rule configured" so the boolean-prefix check fires only when configured.
function hasBooleanPrefix(name: string, prefixes: Set<string>): boolean {
  const regex = booleanPrefixRegex(prefixes);
  return regex !== null && regex.test(name);
}

// Cached per prefix Set via a WeakMap so each rule pass reuses the compiled regex instead of
// rebuilding it for every identifier. The trailing `[A-Z_]` requirement keeps single-letter
// names like `is` from falsely matching the prefix-followed-by-name pattern.
function booleanPrefixRegex(prefixes: Set<string>): RegExp | null {
  if (BOOLEAN_PREFIX_REGEX_CACHE.has(prefixes)) {
    return BOOLEAN_PREFIX_REGEX_CACHE.get(prefixes) ?? null;
  }
  const escaped = [...prefixes].map(escapeRegex);
  const regex = prefixes.size === 0 ? null : new RegExp(`^(?:${escaped.join("|")})[A-Z_]`);
  BOOLEAN_PREFIX_REGEX_CACHE.set(prefixes, regex);
  return regex;
}
