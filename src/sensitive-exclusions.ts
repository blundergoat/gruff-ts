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
 * Validates the config's sensitiveExclusions section before scanning; an absent section returns no entries.
 * Invalid sections or entries throw ConfigLoadError with the relevant config location; duplicate scopes are rejected.
 * Entries need not match a finding; unmatched entries remain valid and receive zero suppression counts.
 *
 * @param parsedConfig - parsed config document supplying the optional sensitiveExclusions list
 * @returns validated entries in declaration and audit-row order, or an empty list when the section is absent or explicitly empty
 * @throws {ConfigLoadError} - when the section is not a list, an entry is invalid, or two entries claim one scope
 */
export function parseSensitiveExclusions(parsedConfig: Record<string, unknown>): SensitiveExclusion[] {
  // A missing section configures no sensitive exclusions.
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

// Checks entryValue in key, rule, path, optional symbol and reason order, using index to locate the entry in config errors.
// Returns normalized fields. Unknown keys are rejected first so a message_contains or value key is reported before a sibling field error.
// An omitted symbol lets the exclusion apply regardless of symbol for the configured rule and path.
//
// @throws {ConfigLoadError} - when the entry is not a mapping, has an unsupported key, or any field fails validation
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

/**
 * Rejects unsupported fields so an exclusion cannot use detected secret text as a match condition.
 *
 * @param entry - exclusion whose keys are checked without changing the entry
 * @param index - exclusion position used in the config diagnostic
 * @returns nothing after checking that the entry uses only supported keys
 * @throws {ConfigLoadError} - when entry contains any key other than rule, path, symbol or reason.
 */
function assertNoUnsupportedKeys(entry: Record<string, unknown>, index: number): void {
  // Identify the first unsupported field so the user knows where to amend the config.
  for (const key of Object.keys(entry)) {
    if (!SENSITIVE_EXCLUSION_KEYS.includes(key)) {
      throw new ConfigLoadError(
        `Config key \`sensitiveExclusions[${index}].${key}\` is not supported; a sensitive exclusion accepts only ${SENSITIVE_EXCLUSION_KEYS.join(", ")}.`,
        "Remove the key. Message, value, and preview matching are rejected on purpose so a suppression can never depend on the detected secret.",
      );
    }
  }
}

/**
 * Validates one sensitive-data rule id for an exclusion; selectors and pillar names would widen its scope.
 * Missing, non-string, blank, unknown, and other-pillar values throw ConfigLoadError identifying the entry's rule field.
 *
 * @param configuredRule - raw config rule id to trim and validate against the catalogue
 * @param index - entry position used in config errors
 * @returns the trimmed sensitive-data rule id
 * @throws {ConfigLoadError} - when the rule is missing, non-string, blank, a selector, a pillar, unknown, or outside sensitive-data
 */
function validatedExclusionRule(configuredRule: unknown, index: number): string {
  const rule = requiredExclusionString(configuredRule, index, "rule");
  // A selector metacharacter would let one entry claim rules the user never enumerated.
  if (RULE_SELECTOR_CHARACTERS.test(rule)) {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].rule\` must be one exact rule id; ${JSON.stringify(rule)} contains a wildcard, glob, or regular-expression character.`, SUGGEST_EXACT_SCOPE);
  }
  // A pillar name would suppress a whole category instead of one reviewed rule.
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
 * @throws {ConfigLoadError} when the path is missing, non-string, blank, absolute, uses `..`, or has a glob character.
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

// A configured symbol limits an exclusion to findings tagged with it. The caller skips this helper when the symbol is omitted.
// Returns configuredSymbol trimmed. Undefined, non-string, or blank input throws ConfigLoadError. index locates the entry in config errors.
function validatedExclusionSymbol(configuredSymbol: unknown, index: number): string {
  return requiredExclusionString(configuredSymbol, index, "symbol");
}

// Returns configuredReason trimmed for the suppression audit; index identifies its entry in config errors.
// Throws ConfigLoadError for a missing, non-string, empty, or whitespace-only reason; every suppression needs an explanation.
function validatedExclusionReason(configuredReason: unknown, index: number): string {
  return requiredExclusionString(configuredReason, index, "reason");
}

/**
 * Shared narrowing for the four string-valued keys. Throws ConfigLoadError naming
 * `sensitiveExclusions[<index>].<key>` for a missing, non-string, or whitespace-only value, so the
 * user sees the exact field to fix. Returns the trimmed text.
 *
 * @param configuredValue - raw config field value to validate and trim
 * @param index - entry position used in config errors
 * @param key - field name used in config errors
 * @returns trimmed, non-empty field text
 * @throws {ConfigLoadError} - when the value is missing, is not a string, or is empty or only whitespace
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
  // Blank text leaves reviewers with no scope or rationale for this field.
  if (trimmedText.length === 0) {
    throw new ConfigLoadError(`Config key \`${location}\` must be a non-empty string.`, SUGGEST_EXACT_SCOPE);
  }
  return trimmedText;
}

// Returns the configured exclusion path with forward slashes and one leading current-directory prefix removed for exact matching.
// A path consisting only of that prefix becomes empty and matches no file path.
function normalisedExclusionPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

/**
 * Rejects duplicate rule, path, and symbol scopes because the first matching entry would receive all suppression credit.
 * The error identifies the later entry so the user can merge the two rationales.
 *
 * @param exclusions - entries checked in declaration order. Two entries with the same rule and path and no symbol conflict.
 * @returns nothing after checking that each configured scope is claimed once
 * @throws {ConfigLoadError} - when a later entry repeats an earlier entry's rule, path, and symbol
 */
function assertUniqueSensitiveScopes(exclusions: readonly SensitiveExclusion[]): void {
  const claimedScopes = new Map<string, number>();
  // Declaration order lets the error identify the later entry as the duplicate and point to the earlier claim.
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

// Returns a stable duplicate-check key by JSON-encoding the exclusion's rule, path, and symbol as separate fields.
// An omitted symbol is encoded as null and identifies the file-wide scope for that rule.
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
 * Apply reviewed sensitive-data exclusions before baseline filtering so claimed findings never affect the score or exit code.
 * Stable contract: rule ID, display path, and any supplied symbol must match exactly. Current sensitive-data rules supply no symbol.
 *
 * @param findings - scan findings to check against the exclusions in report order
 * @param exclusions - validated entries checked in declaration order, with the first match claiming each finding
 * @returns Surviving findings in input order and one audit row per entry, including entries that suppressed nothing.
 */
export function partitionSensitiveExclusions(findings: readonly Finding[], exclusions: readonly SensitiveExclusion[]): SensitiveExclusionResult {
  const suppressions = exclusions.map((exclusion, index) => initialSuppressionSummary(exclusion, index));
  const kept: Finding[] = [];
  // Each finding is matched against the entries in declaration order so the first claimant counts it.
  for (const finding of findings) {
    const matchedIndex = exclusions.findIndex((exclusion) => sensitiveExclusionMatches(exclusion, finding));
    const summary = suppressions[matchedIndex];
    // A finding no entry claims stays eligible for later reporting, scoring, and exit-code checks.
    if (!summary) {
      kept.push(finding);
      continue;
    }
    summary.suppressed += 1;
  }
  return { findings: kept, suppressions };
}

// Reason on each sensitive-data `builtInTestPath[...]` audit row; every port publishes these exact words (FAMILY-CONTRACT.md section 13a).
export const BUILT_IN_TEST_PATH_REASON = "Test, fixture and example files hold sample credentials, so sensitive-data rules skip them by path.";

// Reason on each security `builtInTestPath[...]` audit row, since a test calls insecure APIs on purpose; every port publishes these exact words.
export const BUILT_IN_SECURITY_TEST_PATH_REASON = "Test, fixture and example files exercise insecure calls on purpose, so security rules skip them by path.";

// The family's fixture-PII rule, which keeps reading test paths; gruff-ts has no rule with this id.
const BUILT_IN_TEST_PATH_EXEMPT_RULE = "sensitive-data.pii-test-fixture";

// Directory names, compared case-insensitively, that make a path test code, e.g. `__tests__/` or `Fixtures/`.
const BUILT_IN_TEST_PATH_DIRECTORIES = new Set(["test", "tests", "__tests__", "spec", "testdata", "fixtures", "examples"]);

// Matches a whole base name that marks a test file in any family language, e.g. `login.spec.ts` or `keys_test.go`.
// `[^\n]` rather than `.`: JavaScript's `.` also refuses \r, U+2028 and U+2029, which the other four ports accept.
const BUILT_IN_TEST_FILE_NAME = /^(?:[^\n]*_test\.go|test_[^\n]*\.py|[^\n]*_test\.py|[^\n]*Test\.php|[^\n]*\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs))$/;

// Returns true when a finding's display path matches a built-in directory or file name convention for tests, fixtures, or examples.
export function isBuiltInTestPath(displayPath: string): boolean {
  const segments = displayPath.replaceAll("\\", "/").split("/");
  const baseName = segments.pop() ?? "";
  // Any directory on the path, compared case-insensitively, or the file name alone can mark test code.
  return segments.some((directory) => BUILT_IN_TEST_PATH_DIRECTORIES.has(directory.toLowerCase())) || BUILT_IN_TEST_FILE_NAME.test(baseName);
}

// Reports whether the test-path class covers a rule: every sensitive-data rule but the fixture-PII rule, and every security rule.
function isSkippedOnTestPaths(ruleId: string): boolean {
  // Security rules are skipped whole, because a test exercises insecure calls on purpose.
  if (ruleId.startsWith("security.")) {
    return true;
  }
  return ruleId.startsWith("sensitive-data.") && ruleId !== BUILT_IN_TEST_PATH_EXEMPT_RULE;
}

// Filters findings by test path and returns survivors with a copy of suppressions plus one audit row per skipped file and rule.
//
// A user scanning a project with sample keys or a deliberate `eval` in `__tests__/` sees `builtInTestPath[...]` rows instead of findings.
// Every gruff-ts sensitive-data and security rule is covered, including pii-pattern, under FAMILY-CONTRACT.md section 13a.
export function applyBuiltInTestPathSkip(findings: readonly Finding[], suppressions: readonly SuppressionSummary[]): SensitiveExclusionResult {
  const skippedCountByFileAndRule = new Map<string, { path: string; rule: string; count: number }>();
  const kept: Finding[] = [];
  // Each finding either stays in the report or is folded into its file's audit row.
  for (const finding of findings) {
    // Only the two pillars' findings in test code are skipped, and never the family's fixture-PII rule.
    if (isSkippedOnTestPaths(finding.ruleId) && isBuiltInTestPath(finding.filePath)) {
      const fileAndRuleKey = `${finding.filePath}\u0000${finding.ruleId}`;
      const skipped = skippedCountByFileAndRule.get(fileAndRuleKey) ?? { path: finding.filePath, rule: finding.ruleId, count: 0 };
      skipped.count += 1;
      skippedCountByFileAndRule.set(fileAndRuleKey, skipped);
      continue;
    }
    kept.push(finding);
  }
  const rows = [...suppressions];
  // Built-in rows are numbered among themselves, from 0, so the index means the same thing in every port.
  const skippedFilesAndRules = [...skippedCountByFileAndRule.values()].sort(
    (left, right) => compareUtf8Bytes(left.path, right.path) || compareUtf8Bytes(left.rule, right.rule),
  );
  // One row per file and rule, which text output shows as `builtInTestPath[src/keys.spec.ts] sensitive-data.aws-access-key: 2`.
  for (const [offset, skipped] of skippedFilesAndRules.entries()) {
    rows.push({
      index: offset,
      rule: skipped.rule,
      paths: [skipped.path],
      symbol: null,
      reason: skipped.rule.startsWith("security.") ? BUILT_IN_SECURITY_TEST_PATH_REASON : BUILT_IN_TEST_PATH_REASON,
      suppressed: skipped.count,
      source: "built-in",
    });
  }
  return { findings: kept, suppressions: rows };
}

// Compares left with right by UTF-8 bytes for test-path row ordering (FAMILY-CONTRACT.md section 13a).
// Returns a negative number, zero, or a positive number when left's bytes sort before, equal, or sort after right's bytes.
// JavaScript's own `<` compares UTF-16 units, which can change the relative order of paths containing supplementary characters.
function compareUtf8Bytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

// Returns exclusion's zero-count audit row; index is its configured position. `paths` is a single-element list and `symbol` is null when
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

// Returns true when the finding has the exclusion's exact rule ID and display path.
// A specified symbol must match exactly. Omitting it leaves every finding in that rule and file eligible.
// The stable contract uses the stored display path so matching is independent of the caller's working directory.
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
 * Totals suppression counts across audit rows for the human-readable text summary.
 *
 * @param suppressions - audit rows whose suppressed counts contribute to the text summary
 * @returns the number of suppressed findings; zero means the text line is omitted entirely
 */
export function totalSuppressedFindings(suppressions: readonly SuppressionSummary[]): number {
  return suppressions.reduce((total, summary) => total + summary.suppressed, 0);
}
