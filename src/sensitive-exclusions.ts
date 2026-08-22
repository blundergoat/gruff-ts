// Sensitive-data suppression: the `sensitiveExclusions:` config section, its validator, its matcher,
// and the audit counter that publishes one row per configured entry.
//
// The section is deliberately separate from every other config surface so the prohibition on
// matching a finding's message or detected value is structural rather than a conditional a later
// edit can lose (FAMILY-CONTRACT.md, search: `### 13a. Sensitive exclusions`). Scope is exactly one
// rule id in exactly one project-relative file, optionally narrowed to one symbol, and a reviewed
// reason is mandatory. Nothing here reads finding text, so no suppression can depend on secret
// material (FAMILY-CONTRACT.md, search: `## 5. Secret-preview & redaction semantics`).
import { arrayValue, isString, objectValue, SUGGEST_EDIT_CONFIG } from "./config-parse.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { isKnownRuleId, isPillarName, rulePillar } from "./profiles.ts";
import type { Finding, SensitiveExclusion, SuppressionSummary } from "./types.ts";

// The only keys an entry may carry. Anything else - `message_contains`, `messageContains`, `value`,
// `preview` included - fails, so value matching cannot re-enter through an unreviewed key name.
const SENSITIVE_EXCLUSION_KEYS: readonly string[] = ["rule", "path", "symbol", "reason"];

// The one pillar this section governs; a rule from any other pillar is a different review decision.
const SENSITIVE_EXCLUSION_PILLAR = "sensitive-data";

// Characters that turn an exact rule id into a wildcard, glob, or regular expression. Any of them
// would let one entry claim rules the user never enumerated.
const RULE_SELECTOR_CHARACTERS = /[*?[\]{}()|+^$\\]/;

// Characters that turn an exact file path into a glob. A path glob suppresses findings in files
// nobody listed, which is the blanket suppression this section exists to prevent.
const PATH_GLOB_CHARACTERS = /[*?[\]{}]/;

const SUGGEST_EXACT_SCOPE = "Each `sensitiveExclusions:` entry needs exactly one `rule:` id, one project-relative `path:`, and a non-empty `reason:`; add a separate entry for every file you mean to exclude.";

/**
 * Reads and validates the user's `sensitiveExclusions:` section before any scan runs.
 *
 * Every rejection is a fatal config error naming the entry index and the offending key, because a
 * malformed suppression that loaded silently would hide sensitive findings the user believes are
 * still reported. An entry whose scope matches no finding is accepted and reports zero, so fixing
 * the underlying problem never breaks a build.
 *
 * @param parsedConfig The parsed config document; a missing section means no suppressions.
 * @returns Validated entries in declaration order, which is also their audit-row order.
 */
export function parseSensitiveExclusions(parsedConfig: Record<string, unknown>): SensitiveExclusion[] {
  // A missing section is the common case and means the user suppresses nothing.
  if (!("sensitiveExclusions" in parsedConfig)) {
    return [];
  }
  const section = parsedConfig.sensitiveExclusions;
  // A non-list value cannot carry the per-entry scope and rationale the section requires.
  if (!Array.isArray(section)) {
    throw new ConfigLoadError("Config key `sensitiveExclusions` must be a list of exclusion entries.", SUGGEST_EXACT_SCOPE);
  }
  const exclusions = arrayValue(section).map((entry, index) => parseSensitiveExclusionEntry(entry, index));
  assertUniqueSensitiveScopes(exclusions);
  return exclusions;
}

// Validates one entry's keys, rule, path, symbol, and reason in that order. Unknown keys are
// rejected first so a `message_contains` or `value` key is reported as itself rather than masked by
// a later complaint about a sibling field. Throws ConfigLoadError for every rejection.
function parseSensitiveExclusionEntry(entryValue: unknown, index: number): SensitiveExclusion {
  const entry = objectValue(entryValue);
  // Only a mapping can carry the named scope keys; a bare string would hide which field is meant.
  if (!entry) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}]\` must be a mapping with \`rule\`, \`path\`, and \`reason\` keys.`, SUGGEST_EXACT_SCOPE);
  }
  assertNoUnsupportedKeys(entry, index);
  return {
    rule: validatedExclusionRule(entry.rule, index),
    path: validatedExclusionPath(entry.path, index),
    ...(entry.symbol === undefined ? {} : { symbol: validatedExclusionSymbol(entry.symbol, index) }),
    reason: validatedExclusionReason(entry.reason, index),
  };
}

/*
 * Rejects every key outside {rule, path, symbol, reason}. This is the structural half of the
 * value-matching prohibition: `message_contains`, `messageContains`, `value`, and `preview` fail
 * here by name, and so does any future key that would match against finding text. Throws
 * ConfigLoadError naming the offending key.
 */
function assertNoUnsupportedKeys(entry: Record<string, unknown>, index: number): void {
  // Each supplied key is checked so the error names the exact key the user must delete.
  for (const key of Object.keys(entry)) {
    if (!SENSITIVE_EXCLUSION_KEYS.includes(key)) {
      throw new ConfigLoadError(
        `Config key \`sensitiveExclusions[${index}].${key}\` is not supported; a sensitive exclusion accepts only ${SENSITIVE_EXCLUSION_KEYS.join(", ")}.`,
        "Remove the key. Message, value, and preview matching are rejected on purpose so a suppression can never depend on the detected secret.",
      );
    }
  }
}

/*
 * Validates `rule` as exactly one sensitive-data rule id. Rejects a missing or empty value, a
 * wildcard/glob/regex selector, a pillar name, an id outside the catalogue, and a real rule from
 * another pillar - each one either widens the declared scope or names a rule this section cannot
 * govern. Throws ConfigLoadError naming `sensitiveExclusions[<index>].rule`.
 */
function validatedExclusionRule(configuredRule: unknown, index: number): string {
  const rule = requiredExclusionString(configuredRule, index, "rule");
  // A selector metacharacter would let one entry claim rules the user never enumerated.
  if (RULE_SELECTOR_CHARACTERS.test(rule)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].rule\` must be one exact rule id; ${JSON.stringify(rule)} contains a wildcard, glob, or regular-expression character.`, SUGGEST_EXACT_SCOPE);
  }
  // A pillar name is a whole-pillar selector wearing a rule id.
  if (isPillarName(rule)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].rule\` must be one exact rule id, not the pillar ${JSON.stringify(rule)}.`, SUGGEST_EXACT_SCOPE);
  }
  // A typo must fail loudly instead of silently suppressing nothing forever.
  if (!isKnownRuleId(rule)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].rule\` names unknown rule id ${JSON.stringify(rule)}.`, "Use a rule id from `gruff-ts list-rules --format=json`; the id must match the catalogue exactly.");
  }
  // A known rule from another pillar belongs to a different review decision, not this section.
  if (rulePillar(rule) !== SENSITIVE_EXCLUSION_PILLAR) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].rule\` names ${JSON.stringify(rule)}, which is outside the ${SENSITIVE_EXCLUSION_PILLAR} pillar; this section governs sensitive-data rules only.`, "Disable or retune a non-sensitive rule under `rules:` instead.");
  }
  return rule;
}

/*
 * Validates `path` as one exact project-relative file path. Rejects a missing or empty value, an
 * absolute path, a `..` traversal, and a glob, so the entry names a file inside the analysed project
 * that a reviewer can open. Throws ConfigLoadError naming `sensitiveExclusions[<index>].path`.
 */
function validatedExclusionPath(configuredPath: unknown, index: number): string {
  const path = normalisedExclusionPath(requiredExclusionString(configuredPath, index, "path"));
  // An absolute path leaks the author's machine layout and escapes the analysed project.
  if (path.startsWith("/") || /^[A-Za-z]:\//.test(path)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].path\` must be project-relative; ${JSON.stringify(path)} is absolute.`, SUGGEST_EXACT_SCOPE);
  }
  // A traversal segment points outside the project the user asked gruff to analyse.
  if (path === ".." || path.startsWith("../") || path.includes("/../") || path.endsWith("/..")) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].path\` must stay inside the project; ${JSON.stringify(path)} contains \`..\`.`, SUGGEST_EXACT_SCOPE);
  }
  // A glob suppresses findings across files nobody enumerated.
  if (PATH_GLOB_CHARACTERS.test(path)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].path\` must be one exact file path; ${JSON.stringify(path)} contains a glob character.`, SUGGEST_EXACT_SCOPE);
  }
  return path;
}

// Validates an optional `symbol`, which narrows the scope where a rule stamps one. A supplied but
// empty value cannot narrow anything, so it fails instead of silently widening back to the file.
function validatedExclusionSymbol(configuredSymbol: unknown, index: number): string {
  return requiredExclusionString(configuredSymbol, index, "symbol");
}

// Validates the mandatory `reason`. An unexplained suppression is unreviewable, and whitespace is
// not an explanation, so both fail before the scan starts.
function validatedExclusionReason(configuredReason: unknown, index: number): string {
  return requiredExclusionString(configuredReason, index, "reason");
}

/*
 * Shared narrowing for the four string-valued keys. Throws ConfigLoadError naming
 * `sensitiveExclusions[<index>].<key>` for a missing, non-string, or whitespace-only value, so the
 * user sees the exact field to fix. Returns the trimmed text.
 */
function requiredExclusionString(configuredValue: unknown, index: number, key: string): string {
  const location = `sensitiveExclusions[${index}].${key}`;
  // A missing key cannot describe the scope or rationale the section requires.
  if (configuredValue === undefined) {
    throw new ConfigLoadError(`Config key \`${location}\` is required.`, SUGGEST_EXACT_SCOPE);
  }
  // A non-string value has no meaning for a rule id, a path, a symbol, or a rationale.
  if (!isString(configuredValue)) {
    throw new ConfigLoadError(`Config key \`${location}\` must be a string; got ${JSON.stringify(configuredValue)}.`, SUGGEST_EDIT_CONFIG);
  }
  const trimmedText = configuredValue.trim();
  // An empty or whitespace-only value is indistinguishable from an omitted one at review time.
  if (trimmedText.length === 0) {
    throw new ConfigLoadError(`Config key \`${location}\` must be a non-empty string.`, SUGGEST_EXACT_SCOPE);
  }
  return trimmedText;
}

// Normalises a configured path to the same form findings carry, so a Windows-style separator or a
// leading `./` cannot make an otherwise correct entry match nothing.
function normalisedExclusionPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

/*
 * Rejects a second entry claiming a scope an earlier entry already claims. Two entries over one
 * (rule, path, symbol) would split the audit count arbitrarily between them, so neither row would
 * report what it actually suppressed. Throws ConfigLoadError naming the duplicate entry's index.
 */
function assertUniqueSensitiveScopes(exclusions: readonly SensitiveExclusion[]): void {
  const claimedScopes = new Map<string, number>();
  // Entries are checked in declaration order so the error names the later duplicate, not the first.
  for (const [index, exclusion] of exclusions.entries()) {
    const scope = sensitiveExclusionScopeKey(exclusion);
    const firstIndex = claimedScopes.get(scope);
    if (firstIndex !== undefined) {
      const symbolClause = exclusion.symbol === undefined ? "" : " for symbol " + JSON.stringify(exclusion.symbol);
      throw new ConfigLoadError(
        `Config key \`sensitiveExclusions[${index}]\` is a duplicate of \`sensitiveExclusions[${firstIndex}]\`: both claim rule ${JSON.stringify(exclusion.rule)} in ${JSON.stringify(exclusion.path)}${symbolClause}.`,
        "Merge the two rationales into one entry so its suppression count describes the whole scope.",
      );
    }
    claimedScopes.set(scope, index);
  }
}

// Builds the identity of one declared scope. JSON encoding keeps the three parts unambiguous, so two
// different scopes can never collide onto one key.
function sensitiveExclusionScopeKey(exclusion: SensitiveExclusion): string {
  return JSON.stringify([exclusion.rule, exclusion.path, exclusion.symbol ?? null]);
}

/**
 * Result of applying the user's sensitive exclusions to one scan.
 *
 * Stable contract: `findings` is what the report, the score, and the exit code see, while `suppressions` always carries one
 * row per configured entry, including entries that matched nothing, so a suppression is counted
 * rather than silently invisible.
 */
export interface SensitiveExclusionResult {
  findings: Finding[];
  suppressions: SuppressionSummary[];
}

/**
 * Removes the findings the user's reviewed exclusions claim, and counts what each one suppressed.
 *
 * Stable contract: a finding is suppressed only when its rule id, its project-relative display path, and - when the
 * entry supplies one - its symbol all match exactly. The same rule in another file and another rule
 * in the same file both keep reporting. No sensitive-data rule stamps a symbol today, so an entry
 * carrying `symbol` legitimately matches nothing and reports zero.
 *
 * @param findings Every finding produced by the scan, in report order.
 * @param exclusions Validated entries in declaration order.
 * @returns The surviving findings and one audit row per configured entry.
 */
export function partitionSensitiveExclusions(findings: readonly Finding[], exclusions: readonly SensitiveExclusion[]): SensitiveExclusionResult {
  const suppressions = exclusions.map((exclusion, index) => initialSuppressionSummary(exclusion, index));
  const kept: Finding[] = [];
  // Each finding is matched against the entries in declaration order so the first claimant counts it.
  for (const finding of findings) {
    const matchedIndex = exclusions.findIndex((exclusion) => sensitiveExclusionMatches(exclusion, finding));
    const summary = suppressions[matchedIndex];
    // An unmatched finding keeps its place in the report, the score, and the exit code.
    if (!summary) {
      kept.push(finding);
      continue;
    }
    summary.suppressed += 1;
  }
  return { findings: kept, suppressions };
}

// Starts one entry's audit row at zero. `paths` is a single-element list and `symbol` is null when
// absent, which is the family row shape (gruff-rs/src/report.rs, search: `struct SuppressionSummary`).
function initialSuppressionSummary(exclusion: SensitiveExclusion, index: number): SuppressionSummary {
  return {
    index,
    rule: exclusion.rule,
    paths: [exclusion.path],
    symbol: exclusion.symbol ?? null,
    reason: exclusion.reason,
    suppressed: 0,
  };
}

// Exact match on rule id, then on the finding's own display path, then on symbol when the entry
// narrows to one. Stable contract: comparing the finding's stored display path is what keeps the
// result independent of the directory the caller ran gruff from.
function sensitiveExclusionMatches(exclusion: SensitiveExclusion, finding: Finding): boolean {
  if (finding.ruleId !== exclusion.rule) {
    return false;
  }
  if (finding.filePath !== exclusion.path) {
    return false;
  }
  return exclusion.symbol === undefined || finding.symbol === exclusion.symbol;
}

/**
 * Totals what every configured exclusion suppressed, for the one human-readable line on text output.
 *
 * @param suppressions Audit rows from `partitionSensitiveExclusions`.
 * @returns The number of suppressed findings; zero means the text line is omitted entirely.
 */
export function totalSuppressedFindings(suppressions: readonly SuppressionSummary[]): number {
  return suppressions.reduce((total, summary) => total + summary.suppressed, 0);
}
