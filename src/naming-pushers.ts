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
  if (hasBooleanPrefix(name, config.booleanPrefixes) || isAcceptedBooleanStateName(name)) {
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
// narrow so vague names such as `ready` or `enabled` still get the maintainability prompt.
function isAcceptedBooleanStateName(name: string): boolean {
  return ACCEPTED_BOOLEAN_STATE_NAMES.has(name.toLowerCase()) || ACCEPTED_BOOLEAN_STATE_SUFFIXES.some((suffix) => name.endsWith(suffix));
}

/*
 * Allows the standard `i`, `j`, `k` loop counters and anything on `acceptedAbbreviations`. Reports
 * `naming.short-variable` for any other one or two character name as a stable advisory finding.
 */
export function pushShortVariableAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
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

/*
 * Reports `naming.abbreviation` when the name is on `abbreviationDenylist` and not on the user's
 * `acceptedAbbreviations` allowlist. `surface` distinguishes parameter / variable / interface-field
 * — same stable rule contract, different metadata, so consumers can filter on origin.
 */
export function pushAbbreviationAt(file: SourceFile, line: number, name: string, config: Config, findings: Finding[], surface: NamingSurface): void {
  if (config.rules.get("naming.abbreviation")?.enabled !== true) {
    return;
  }
  if (config.acceptedAbbreviations.has(name.toLowerCase())) {
    return;
  }
  if (!config.abbreviationDenylist.has(name.toLowerCase())) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId: "naming.abbreviation",
      message: `Identifier \`${name}\` uses an opaque abbreviation.`,
      filePath: file.displayPath,
      line,
      severity: "advisory",
      pillar: "naming",
      confidence: "medium",
      symbol: name,
      remediation: "Use the full domain term or add the abbreviation to allowlists.acceptedAbbreviations.",
      metadata: { identifierName: name, surface },
    }),
  );
}

// Returns `"generic"` for low-information names from the configured set, `"numbered"` for
// `foo1` / `bar2` style trailing-digit identifiers, or undefined when the name is acceptable.
// The variant string lands in finding metadata so consumers can split the two failure modes.
function identifierQualityVariant(name: string, placeholderNames: Set<string>): string | undefined {
  if (placeholderNames.has(name.toLowerCase())) {
    return "generic";
  }
  if (/^[A-Za-z_$]+[0-9]+$/.test(name)) {
    return "numbered";
  }
  return undefined;
}

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
