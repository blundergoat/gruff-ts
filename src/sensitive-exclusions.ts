// Implements `sensitiveExclusions:` config validation, matching, built-in test-path skips, and suppression audit rows.
//
// Kept structurally separate from other config surfaces so matching never inspects finding text or secret values (FAMILY-CONTRACT section 13a):
// - each configured exclusion targets exactly one sensitive-data rule ID, one project-relative path, an optional symbol, and a mandatory reason;
// - produces deterministic audit rows surfaced across JSON, text, summary, SARIF, and hook envelopes.
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

/**
 * Checks entry fields in key, rule, path, optional symbol, and reason order; unknown keys fail first before sibling field errors.
 * An omitted symbol lets the exclusion apply regardless of symbol for the configured rule and path.
 *
 * @param entryValue - raw config entry expected to be a mapping with rule, path, optional symbol, and reason
 * @param index - entry position used to locate the exclusion in config errors
 * @returns normalized fields for the exclusion, omitting symbol when not configured
 * @throws {ConfigLoadError} - when the entry is not a mapping, has an unsupported key, or any field fails validation
 */
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

/**
 * Validates one exact project-relative file path, so a reviewer can open the one file the exclusion covers.
 * Rejects the project root, absolute paths, `..` traversal and globs.
 *
 * @param configuredPath - raw config path field to normalise and validate as a project-relative file path
 * @param index - entry position used to name `sensitiveExclusions[<index>].path` in config errors
 * @returns normalised project-relative file path with forward slashes and no leading `./` segments
 * @throws {ConfigLoadError} - when the path is missing, non-string, blank, root-only, absolute, uses `..`, or has a glob character
 */
function validatedExclusionPath(configuredPath: unknown, index: number): string {
  const path = normalisedExclusionPath(requiredExclusionString(configuredPath, index, "path"));
  // A bare `.` or `./` resolves to the project root rather than one reviewed file.
  if (path.length === 0 || path === ".") {
    throw new ConfigLoadError(`Config key \`sensitiveExclusions[${index}].path\` must name a specific project-relative file, not the project root.`, SUGGEST_EXACT_SCOPE);
  }
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

/**
 * Validates a configured symbol that limits an exclusion to matching tagged findings; the caller skips this helper when omitted.
 *
 * @param configuredSymbol - raw config symbol field to validate and trim
 * @param index - entry position used to locate the entry in config errors
 * @returns trimmed non-empty symbol name
 * @throws {ConfigLoadError} - when configuredSymbol is undefined, non-string, or blank
 */
function validatedExclusionSymbol(configuredSymbol: unknown, index: number): string {
  return requiredExclusionString(configuredSymbol, index, "symbol");
}

/**
 * Validates the mandatory explanation for a suppression audit entry because every exclusion needs a non-empty rationale.
 *
 * @param configuredReason - raw config reason field to validate and trim for the suppression audit
 * @param index - entry position used to identify the entry in config errors
 * @returns trimmed non-empty reason text for the suppression audit
 * @throws {ConfigLoadError} - when configuredReason is missing, non-string, empty, or whitespace-only
 */
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

/**
 * Normalises a configured exclusion path for exact matching by converting separators and stripping any repeated leading `./` prefixes.
 *
 * @param path - configured exclusion path before slash and prefix normalisation
 * @returns path with backslashes replaced by forward slashes and all leading `./` prefixes removed
 */
function normalisedExclusionPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^(?:\.\/)+/, "");
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

/**
 * Builds a stable duplicate-check key by JSON-encoding an exclusion's rule, path, and symbol as separate fields.
 * An omitted symbol is encoded as null and identifies the file-wide scope for that rule.
 *
 * @param exclusion - validated exclusion whose scope fields form the key
 * @returns stable JSON array key encoding rule, path, and symbol (or null when omitted)
 */
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

/**
 * Checks whether a finding's display path matches a built-in directory or file name convention for tests, fixtures, or examples.
 *
 * @param displayPath - finding display path to check across directory segments and base file name
 * @returns true when any directory segment or the base file name matches the built-in test-path conventions
 */
export function isBuiltInTestPath(displayPath: string): boolean {
  const segments = displayPath.replaceAll("\\", "/").split("/");
  const baseName = segments.pop() ?? "";
  // Any directory on the path, compared case-insensitively, or the file name alone can mark test code.
  return segments.some((directory) => BUILT_IN_TEST_PATH_DIRECTORIES.has(directory.toLowerCase())) || BUILT_IN_TEST_FILE_NAME.test(baseName);
}

/**
 * Reports whether the test-path skip class covers a rule: every security rule and every sensitive-data rule except the fixture-PII rule.
 *
 * @param ruleId - rule identifier on a finding being evaluated for built-in test-path skipping
 * @returns true for security rules and sensitive-data rules other than the exempt fixture-PII rule
 */
function isSkippedOnTestPaths(ruleId: string): boolean {
  // Security rules are skipped whole, because a test exercises insecure calls on purpose.
  if (ruleId.startsWith("security.")) {
    return true;
  }
  return ruleId.startsWith("sensitive-data.") && ruleId !== BUILT_IN_TEST_PATH_EXEMPT_RULE;
}

/**
 * Filters findings in test paths so projects with sample keys or `eval` in `__tests__/` report `builtInTestPath[...]` rows instead of findings.
 * Every gruff-ts sensitive-data and security rule is covered, including pii-pattern, under FAMILY-CONTRACT.md section 13a.
 *
 * @param findings - findings to partition between surviving report items and built-in test-path skips
 * @param suppressions - existing user-exclusion audit rows copied before appending built-in skip rows
 * @returns surviving findings in input order and a copy of suppressions plus one sorted built-in audit row per skipped file and rule
 */
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

/**
 * Compares two strings by UTF-8 bytes for test-path row ordering (FAMILY-CONTRACT.md section 13a),
 * avoiding JavaScript `<` UTF-16 unit ordering on supplementary characters.
 *
 * @param left - first string to encode and compare as UTF-8 bytes
 * @param right - second string to encode and compare as UTF-8 bytes
 * @returns negative, zero, or positive integer when left's UTF-8 bytes sort before, equal, or after right's
 */
function compareUtf8Bytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

/**
 * Builds an exclusion's zero-count audit row in the family row shape (`gruff-rs/src/report.rs`, search: `struct SuppressionSummary`),
 * with `paths` as a single-element list and `symbol` set to null when absent.
 *
 * @param exclusion - validated exclusion whose rule, path, optional symbol, and reason populate the row
 * @param index - configured declaration position recorded on the audit row
 * @returns zero-count SuppressionSummary row for the configured exclusion
 */
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

/**
 * Matches a finding against an exclusion by exact rule ID, stored display path, and optional symbol; an omitted symbol matches any symbol.
 * Stable contract: matching uses the stored display path so results are independent of working directory, and any specified symbol must match.
 *
 * @param exclusion - validated exclusion specifying the exact rule, path, and optional symbol
 * @param finding - finding checked for exact rule ID, display path, and optional symbol match
 * @returns true when rule ID, display path, and any specified symbol match the exclusion
 */
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
