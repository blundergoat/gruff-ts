/*
 * Updates a 0.5 project config for 0.6 when the user runs `migrate-config`.
 *
 * YAML edits keep surrounding comments and settings; JSON rewrites the document when a change is needed:
 * - moves per-command exit gates to `failOn` and drops obsolete secret previews;
 * - prunes retired 0.5 rules, allowlist keys, and sensitive exclusions;
 * - pins `schemaVersion` and validates the migrated config through the 0.6 loader before returning.
 */
import { validateParsedConfig } from "./config.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { arrayValue, isString, objectValue, parseYamlConfig, SUGGEST_EDIT_CONFIG } from "./config-parse.ts";
import { isKnownRuleId } from "./profiles.ts";

// The one schema version this build reads; a migrated file that named another would be refused on the next run.
const SCHEMA_VERSION = "gruff-ts.config.v0.1";

/** One rewrite the migration applied, as a line a user can read against their own file. */
export interface ConfigMigrationChange {
  line: number;
  description: string;
}

/*
 * The result of migrating one configuration file.
 *
 * `text` is what the CLI can write to the destination. An empty `changes` list means no settings needed updating.
 */
export interface ConfigMigration {
  text: string;
  changes: ConfigMigrationChange[];
}

// The removed redaction key, dropped with any block it carries. Section 5 makes category markers unconditional.
const REMOVED_ALLOWLIST_KEY = "secretPreviews";

// The per-command exit gate's former spelling; as a scalar the same key is the 0.6 display floor and stays put.
const RENAMED_GATE_KEY = "minimumSeverity";

// The seven allowlist keys read only by retired 0.5 rules (UPGRADING.md item 24); removed during migration while real typos stay rejected.
const RETIRED_ALLOWLIST_KEYS: ReadonlySet<string> = new Set([
  "acceptedBooleanNames",
  "acceptedCasingPairs",
  "bannedGenericNames",
  "booleanPrefixes",
  "hungarianPrefixes",
  "knownAcronyms",
  "negativeBooleanAllowed",
]);

// The 40 rules retired in 0.6.0 under ADR-021 (UPGRADING.md items 21, 24, and 26). Only known retired ids are
// pruned automatically so genuine typos in `rules:` or `sensitiveExclusions:` still fail validation loudly.
const RETIRED_0_5_RULE_IDS: ReadonlySet<string> = new Set([
  "complexity.cognitive",
  "design.deep-relative-import",
  "docs.magic-threshold-without-rationale",
  "docs.stale-comment",
  "docs.useless-docblock",
  "modernisation.loose-equality",
  "modernisation.nullish-coalescing-candidate",
  "modernisation.object-spread-candidate",
  "modernisation.optional-chaining-candidate",
  "modernisation.public-property",
  "naming.acronym-case",
  "naming.boolean-prefix",
  "naming.generic-function",
  "naming.generic-parameter",
  "naming.hungarian-notation",
  "naming.inconsistent-casing",
  "naming.negative-boolean",
  "security.floating-promise",
  "security.github-actions-broad-permissions",
  "security.insecure-random",
  "security.process-exec",
  "security.proto-access",
  "security.risky-lifecycle-script",
  "sensitive-data.hardcoded-env-value",
  "sensitive-data.high-entropy-string",
  "test-quality.conditional-logic",
  "test-quality.exception-type-only",
  "test-quality.magic-number-assertion",
  "test-quality.mock-only-test",
  "test-quality.no-assertions",
  "test-quality.no-throw-only-test",
  "test-quality.only-skip",
  "test-quality.sleep-in-test",
  "test-quality.snapshot-only-test",
  "waste.commented-out-code",
  "waste.console-log",
  "waste.empty-function",
  "waste.redundant-boolean-cast",
  "waste.redundant-variable",
  "waste.unused-parameter",
]);

/** Active YAML block tracked while scanning lines so pruning only touches matching child sections. */
interface ActiveYamlSection {
  name: "allowlists" | "rules" | "profileRules" | "sensitiveExclusions";
  childIndent: number;
  headerMigratedIndex: number;
  keptEntryCount: number;
  removedEntryCount: number;
}

/**
 * Converts legacy settings for `migrate-config` and returns the changes the CLI can show during a dry run.
 * Validates the migrated result against the 0.6 loader before returning so broken output is never written.
 *
 * @param original - the whole config file. Empty YAML has no settings yet, while empty JSON is invalid.
 * @param format - syntax selected by the config file's extension. An omitted format uses YAML.
 * @param baseDirectory - optional directory used to resolve relative `profile:` references during validation.
 * @returns the destination text and one entry per rewrite. An empty change list means the settings were current.
 * @throws {ConfigLoadError} when the input cannot be parsed, contains conflicting migration keys, or fails 0.6 validation after migration.
 */
export function migrateConfigText(original: string, format: "yaml" | "json" = "yaml", baseDirectory?: string): ConfigMigration {
  // An editor may add a byte-order mark. Strip it before parsing the selected file format.
  const source = original.replace(/^\uFEFF/u, "");
  return format === "json" ? migrateJsonConfig(source, baseDirectory) : migrateYamlConfig(source, original, baseDirectory);
}

/**
 * Rewrites legacy YAML lines in place because re-serializing through a YAML emitter would strip user comments and formatting,
 * then validates the rewritten document through the 0.6 loader.
 *
 * @param source - BOM-stripped YAML config text
 * @param original - untouched original text returned verbatim when zero rewrites apply
 * @param baseDirectory - optional directory used to resolve relative `profile:` references during validation
 * @returns Migrated YAML text and ordered change descriptions.
 * @throws {ConfigLoadError} when the input has conflicting keys, flow-style legacy keys survive, or 0.6 validation rejects the result.
 */
function migrateYamlConfig(source: string, original: string, baseDirectory?: string): ConfigMigration {
  const shouldRenameGate = hasLegacyCommandGate(parseYamlConfig(source));
  const lines = source.split(/\r?\n/u);
  const rootIndent = leadingSpaces(lines[nextContentLine(lines, 0)] ?? "");
  const changes: ConfigMigrationChange[] = [];
  const migrated: string[] = [];
  let activeSection: ActiveYamlSection | undefined;
  let profileChildIndent: number | undefined;
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? "";
    const indent = leadingSpaces(line);
    const trimmed = line.trim();
    const isContentLine = trimmed.length > 0 && !trimmed.startsWith("#");
    const isRootKey = indent === rootIndent && isContentLine;
    if (isRootKey) {
      finalizeEmptiedYamlSection(activeSection, migrated);
      activeSection = enterYamlSection(lines, index, migrated.length);
      profileChildIndent = enterYamlProfileBlock(lines, index);
    } else if (profileChildIndent !== undefined && isContentLine && indent === profileChildIndent) {
      // Inline `profile:` can carry its own nested `rules:` block whose retired 0.5 IDs must be pruned too.
      finalizeEmptiedYamlSection(activeSection, migrated);
      activeSection = enterYamlProfileRulesSection(lines, index, migrated.length);
    }

    const skipped = activeSection ? tryPruneYamlSectionEntry(activeSection, lines, index, changes) : 0;
    if (skipped > 0) {
      index += skipped;
      continue;
    }

    const renamed = isRootKey && shouldRenameGate
      ? line.replace(/^(\s*)(?:minimumSeverity|"minimumSeverity"|'minimumSeverity')(\s*:)/u, "$1failOn$2")
      : line;

    if (renamed !== line) {
      changes.push({ line: index + 1, description: `${RENAMED_GATE_KEY}: renamed to failOn:, which is the key that gates the exit code in 0.6` });
      migrated.push(renamed);
      index += 1;
      continue;
    }

    migrated.push(line);
    index += 1;
  }

  finalizeEmptiedYamlSection(activeSection, migrated);
  const result = withSchemaVersion(migrated, changes, original, rootIndent);
  const updated = parseYamlConfig(result.text);
  // A YAML key written in flow style can survive line-level removal. Stop before emitting unusable settings.
  if (objectValue(updated.minimumSeverity) !== undefined || Object.hasOwn(objectValue(updated.allowlists) ?? {}, REMOVED_ALLOWLIST_KEY)) {
    throw new ConfigLoadError("The legacy gate or allowlist could not be migrated safely.", SUGGEST_EDIT_CONFIG);
  }
  validateParsedConfig(updated, baseDirectory);
  return result;
}

const EMPTIED_SECTION_HEADER = /^(\s*["']?(?:allowlists|rules|sensitiveExclusions)["']?\s*:)(\s*(?:#.*)?)$/u;

/**
 * Rewrites an emptied `sensitiveExclusions:`, `allowlists:`, or `rules:` YAML header to `[]` or `{}` so the migrated YAML stays valid.
 *
 * @param section - section state closing at a new root key or end-of-file
 * @param migrated - mutable migrated lines array whose header line may be updated
 * @returns Nothing. Updates `migrated[section.headerMigratedIndex]` only when every entry in `section` was pruned.
 */
function finalizeEmptiedYamlSection(section: ActiveYamlSection | undefined, migrated: string[]): void {
  if (!section || section.removedEntryCount === 0 || section.keptEntryCount > 0) {
    return;
  }
  const headerLine = migrated[section.headerMigratedIndex];
  if (headerLine !== undefined) {
    const emptyLiteral = section.name === "sensitiveExclusions" ? "[]" : "{}";
    migrated[section.headerMigratedIndex] = headerLine.replace(EMPTIED_SECTION_HEADER, `$1 ${emptyLiteral}$2`);
  }
}

/**
 * Identifies whether a root YAML key opens a migratable block (`allowlists`, `rules`, or `sensitiveExclusions`) and records its child indentation.
 *
 * @param lines - split YAML source lines
 * @param index - current root key line index
 * @param headerMigratedIndex - index where this header line will be written in `migrated`
 * @returns Active section tracker when the root key has indented children, or undefined otherwise.
 */
function enterYamlSection(lines: string[], index: number, headerMigratedIndex: number): ActiveYamlSection | undefined {
  const header = lines[index] ?? "";
  const match = header.match(/^\s*(?:(allowlists|rules|sensitiveExclusions)|"(allowlists|rules|sensitiveExclusions)"|'(allowlists|rules|sensitiveExclusions)')\s*:\s*(?:#.*)?$/u);
  const sectionName = (match?.[1] ?? match?.[2] ?? match?.[3]) as ActiveYamlSection["name"] | undefined;
  if (!sectionName) {
    return undefined;
  }
  const childLineIndex = nextContentLine(lines, index + 1);
  const childIndent = leadingSpaces(lines[childLineIndex] ?? "");
  if (childIndent <= leadingSpaces(header)) {
    return undefined;
  }
  return { name: sectionName, childIndent, headerMigratedIndex, keptEntryCount: 0, removedEntryCount: 0 };
}

/**
 * Checks whether a root YAML key opens an inline `profile:` mapping and returns its direct-child indentation.
 *
 * @param lines - split YAML source lines
 * @param index - current root key line index
 * @returns Child indentation when `profile:` has indented mapping keys, or undefined otherwise.
 */
function enterYamlProfileBlock(lines: string[], index: number): number | undefined {
  const header = lines[index] ?? "";
  // Only a bare `profile:` header opens an inline profile; `profile: strict` names a built-in profile and has no rules to prune.
  if (!/^\s*(?:profile|"profile"|'profile')\s*:\s*(?:#.*)?$/u.test(header)) {
    return undefined;
  }
  const childLineIndex = nextContentLine(lines, index + 1);
  const childIndent = leadingSpaces(lines[childLineIndex] ?? "");
  return childIndent > leadingSpaces(header) ? childIndent : undefined;
}

/**
 * Identifies whether a direct child key under an inline YAML `profile:` block opens a `rules:` mapping.
 *
 * @param lines - split YAML source lines
 * @param index - current profile-child line index
 * @param headerMigratedIndex - index where this header line will be written in `migrated`
 * @returns Active `profileRules` section tracker when `rules:` has indented children, or undefined otherwise.
 */
function enterYamlProfileRulesSection(lines: string[], index: number, headerMigratedIndex: number): ActiveYamlSection | undefined {
  const header = lines[index] ?? "";
  // Only a `rules:` header inside the inline profile can hold rule entries to prune.
  if (!/^\s*(?:rules|"rules"|'rules')\s*:\s*(?:#.*)?$/u.test(header)) {
    return undefined;
  }
  const childLineIndex = nextContentLine(lines, index + 1);
  const childIndent = leadingSpaces(lines[childLineIndex] ?? "");
  // A `rules:` key with nothing indented under it has no entries to prune.
  if (childIndent <= leadingSpaces(header)) {
    return undefined;
  }
  return { name: "profileRules", childIndent, headerMigratedIndex, keptEntryCount: 0, removedEntryCount: 0 };
}

/**
 * Attempts to prune one retired entry at `index` inside the active YAML section (`allowlists`, `rules`, `profileRules`, or `sensitiveExclusions`).
 * Tracks kept vs removed entries so an emptied section header can be rewritten to `[]` or `{}`.
 *
 * @param section - active YAML section metadata, mutated with kept/removed counts
 * @param lines - full YAML lines array
 * @param index - current line index
 * @param changes - migration change log appended when an entry is pruned
 * @returns Number of lines skipped (0 when the line is kept).
 */
function tryPruneYamlSectionEntry(section: ActiveYamlSection, lines: string[], index: number, changes: ConfigMigrationChange[]): number {
  const line = lines[index] ?? "";
  const trimmed = line.trim();
  if (trimmed.length === 0 || trimmed.startsWith("#") || leadingSpaces(line) !== section.childIndent) {
    return 0;
  }
  if (section.name === "allowlists") {
    return pruneYamlAllowlistEntry(section, lines, index, changes);
  }
  // Top-level rules and an inline profile's rules are pruned the same way.
  if (section.name === "rules" || section.name === "profileRules") {
    return pruneYamlRuleEntry(section, lines, index, changes);
  }
  return pruneYamlSensitiveExclusionEntry(section, lines, index, changes);
}

/**
 * Drops `secretPreviews` or any retired 0.5 allowlist key and its indented children inside `allowlists:`.
 *
 * @param section - active `allowlists` tracker updated with kept/removed counts
 * @param lines - full YAML lines array
 * @param index - line index of one key inside `allowlists:`
 * @param changes - migration change log appended on removal
 * @returns Count of lines to skip, or 0 when the allowlist key is current.
 */
function pruneYamlAllowlistEntry(section: ActiveYamlSection, lines: string[], index: number, changes: ConfigMigrationChange[]): number {
  const key = yamlMappingKey(lines[index] ?? "");
  if (!key) {
    return 0;
  }
  if (key === REMOVED_ALLOWLIST_KEY) {
    section.removedEntryCount += 1;
    changes.push({ line: index + 1, description: `allowlists.${REMOVED_ALLOWLIST_KEY} removed; FAMILY-CONTRACT.md section 5 makes category markers unconditional` });
    return indentedBlockLength(lines, index);
  }
  if (RETIRED_ALLOWLIST_KEYS.has(key)) {
    section.removedEntryCount += 1;
    changes.push({ line: index + 1, description: `allowlists.${key} removed; only read by rules retired in 0.6.0` });
    return indentedBlockLength(lines, index);
  }
  section.keptEntryCount += 1;
  return 0;
}

/**
 * Drops a retired 0.5 rule block and its indented settings inside `rules:`.
 *
 * @param section - active `rules` tracker updated with kept/removed counts
 * @param lines - full YAML lines array
 * @param index - line index of one rule key inside `rules:`
 * @param changes - migration change log appended on removal
 * @returns Count of lines to skip, or 0 when the rule key is active or unrecognized (left for loader validation).
 */
function pruneYamlRuleEntry(section: ActiveYamlSection, lines: string[], index: number, changes: ConfigMigrationChange[]): number {
  const ruleId = yamlMappingKey(lines[index] ?? "");
  if (!ruleId) {
    return 0;
  }
  if (!isRetiredRuleId(ruleId)) {
    section.keptEntryCount += 1;
    return 0;
  }
  section.removedEntryCount += 1;
  const prefix = section.name === "profileRules" ? "profile.rules" : "rules";
  changes.push({ line: index + 1, description: `${prefix}.${ruleId} removed; rule retired in 0.6.0` });
  return indentedBlockLength(lines, index);
}

/**
 * Drops a YAML sequence entry under `sensitiveExclusions:` when its `rule:` names a rule retired in 0.6.0.
 *
 * @param section - active `sensitiveExclusions` tracker updated with kept/removed counts
 * @param lines - full YAML lines array
 * @param index - line index of one `- ...` sequence item
 * @param changes - migration change log appended on removal
 * @returns Count of lines to skip, or 0 when the entry stays.
 */
function pruneYamlSensitiveExclusionEntry(section: ActiveYamlSection, lines: string[], index: number, changes: ConfigMigrationChange[]): number {
  const line = lines[index] ?? "";
  if (!/^\s*-\s*/u.test(line)) {
    return 0;
  }
  const length = yamlSequenceItemLength(lines, index);
  const itemLines = lines.slice(index, index + length);
  const ruleId = yamlSequenceItemRuleId(itemLines);
  if (ruleId && isRetiredRuleId(ruleId)) {
    section.removedEntryCount += 1;
    changes.push({ line: index + 1, description: `sensitiveExclusions entry for ${ruleId} removed; rule retired in 0.6.0` });
    return length;
  }
  section.keptEntryCount += 1;
  return 0;
}

/**
 * Extracts an unquoted or quoted YAML mapping key from one indented key line.
 *
 * @param line - single YAML line expected to start with a mapping key and colon
 * @returns Unquoted key string, or undefined when the line is not a mapping key.
 */
function yamlMappingKey(line: string): string | undefined {
  const match = line.match(/^\s+(?:"([^"]+)"|'([^']+)'|([^:#\s][^:]*?))\s*:/u);
  const key = match?.[1] ?? match?.[2] ?? match?.[3];
  return key?.trim();
}

/**
 * Extracts the `rule:` scalar from a single YAML `sensitiveExclusions:` sequence item's lines.
 *
 * @param itemLines - lines spanning one `- ...` item inside `sensitiveExclusions:`
 * @returns Trimmed rule id string, or undefined when no `rule:` field is present.
 */
function yamlSequenceItemRuleId(itemLines: readonly string[]): string | undefined {
  for (const itemLine of itemLines) {
    const match = itemLine.match(/^\s*(?:-\s+)?(?:rule|"rule"|'rule')\s*:\s*(?:"([^"]+)"|'([^']+)'|([^#\s]+))/u);
    const ruleId = match?.[1] ?? match?.[2] ?? match?.[3];
    if (ruleId) {
      return ruleId.trim();
    }
  }
  return undefined;
}

/**
 * Reports whether `ruleId` is a known retired 0.5 rule that is no longer part of the 0.6.0 rule catalogue.
 *
 * @param ruleId - candidate rule identifier from a 0.5 configuration
 * @returns True when `ruleId` is retired and absent from the live catalogue; false otherwise.
 */
function isRetiredRuleId(ruleId: string): boolean {
  return RETIRED_0_5_RULE_IDS.has(ruleId) && !isKnownRuleId(ruleId);
}

/**
 * Migrates a JSON config: prunes retired allowlists, rules, inline profile rules and sensitive exclusions.
 * Stable contract: the result must pass 0.6 validation before it is returned, so the user never writes a config that will not load.
 *
 * @param source - BOM-stripped JSON config text
 * @param baseDirectory - optional directory used to resolve relative `profile:` references during validation
 * @returns Migrated JSON text and change descriptions (using line 1 for whole-document rewrites).
 * @throws {ConfigLoadError} when the input is malformed, keys conflict, or 0.6 validation rejects the result.
 */
function migrateJsonConfig(source: string, baseDirectory?: string): ConfigMigration {
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = objectValue(JSON.parse(source));
  } catch {
    throw new ConfigLoadError("The migration input is not valid JSON.", SUGGEST_EDIT_CONFIG);
  }
  if (!parsed) {
    throw new ConfigLoadError("The migration input must be a JSON object.", SUGGEST_EDIT_CONFIG);
  }
  const changes: ConfigMigrationChange[] = [];
  if (hasLegacyCommandGate(parsed)) {
    parsed.failOn = parsed.minimumSeverity;
    delete parsed.minimumSeverity;
    changes.push({ line: 1, description: "Renamed the per-command minimumSeverity mapping to failOn" });
  }
  pruneJsonAllowlists(parsed, changes);
  pruneJsonRules(parsed, changes);
  pruneJsonProfileRules(parsed, changes);
  pruneJsonSensitiveExclusions(parsed, changes);
  if (parsed.schemaVersion !== SCHEMA_VERSION) {
    parsed.schemaVersion = SCHEMA_VERSION;
    changes.push({ line: 1, description: `Set schemaVersion to ${SCHEMA_VERSION}` });
  }
  validateParsedConfig(parsed, baseDirectory);
  return { changes, text: changes.length > 0 ? `${JSON.stringify(parsed, null, 2)}\n` : source };
}

/**
 * Removes `secretPreviews` and retired 0.5 allowlist keys from a parsed JSON config object in place.
 *
 * @param parsed - mutable JSON config mapping
 * @param changes - change log appended with one entry per removed allowlist key
 * @returns Nothing. Mutates `parsed.allowlists` and `changes` in place.
 */
function pruneJsonAllowlists(parsed: Record<string, unknown>, changes: ConfigMigrationChange[]): void {
  const allowlists = objectValue(parsed.allowlists);
  if (!allowlists) {
    return;
  }
  if (Object.hasOwn(allowlists, REMOVED_ALLOWLIST_KEY)) {
    delete allowlists[REMOVED_ALLOWLIST_KEY];
    changes.push({ line: 1, description: `Removed allowlists.${REMOVED_ALLOWLIST_KEY}` });
  }
  for (const key of Object.keys(allowlists)) {
    if (RETIRED_ALLOWLIST_KEYS.has(key)) {
      delete allowlists[key];
      changes.push({ line: 1, description: `Removed allowlists.${key}; only read by rules retired in 0.6.0` });
    }
  }
}

/**
 * Removes retired 0.5 rule entries from a parsed JSON config's `rules` mapping in place.
 *
 * @param parsed - mutable JSON config mapping
 * @param changes - change log appended with one entry per removed rule id
 * @returns Nothing. Mutates `parsed.rules` and `changes` in place.
 */
function pruneJsonRules(parsed: Record<string, unknown>, changes: ConfigMigrationChange[]): void {
  const rules = objectValue(parsed.rules);
  if (!rules) {
    return;
  }
  for (const ruleId of Object.keys(rules)) {
    if (isRetiredRuleId(ruleId)) {
      delete rules[ruleId];
      changes.push({ line: 1, description: `Removed rules.${ruleId}; rule retired in 0.6.0` });
    }
  }
}

/**
 * Removes retired 0.5 rule entries from an inline JSON `profile.rules` mapping in place.
 *
 * @param parsed - mutable JSON config mapping
 * @param changes - change log appended with one entry per removed profile rule id
 * @returns Nothing. Mutates `parsed.profile.rules` and `changes` in place.
 */
function pruneJsonProfileRules(parsed: Record<string, unknown>, changes: ConfigMigrationChange[]): void {
  const profileRules = objectValue(objectValue(parsed.profile)?.rules);
  // A config without an inline `profile.rules` mapping has nothing to prune here.
  if (!profileRules) {
    return;
  }
  // Check each rule the inline profile configures.
  for (const ruleId of Object.keys(profileRules)) {
    // A rule retired in 0.6.0 is removed and reported, so the migrated file loads cleanly.
    if (isRetiredRuleId(ruleId)) {
      delete profileRules[ruleId];
      changes.push({ line: 1, description: `Removed profile.rules.${ruleId}; rule retired in 0.6.0` });
    }
  }
}

/**
 * Removes `sensitiveExclusions` items targeting retired 0.5 rules from a parsed JSON config in place.
 *
 * @param parsed - mutable JSON config mapping
 * @param changes - change log appended with one entry per removed exclusion
 * @returns Nothing. Mutates `parsed.sensitiveExclusions` and `changes` in place.
 */
function pruneJsonSensitiveExclusions(parsed: Record<string, unknown>, changes: ConfigMigrationChange[]): void {
  if (!Array.isArray(parsed.sensitiveExclusions)) {
    return;
  }
  const kept: unknown[] = [];
  for (const entry of arrayValue(parsed.sensitiveExclusions)) {
    const record = objectValue(entry);
    const ruleId = isString(record?.rule) ? record.rule.trim() : undefined;
    if (ruleId && isRetiredRuleId(ruleId)) {
      changes.push({ line: 1, description: `Removed sensitiveExclusions entry for ${ruleId}; rule retired in 0.6.0` });
      continue;
    }
    kept.push(entry);
  }
  parsed.sensitiveExclusions = kept;
}

/**
 * Tells migration whether the user set per-command gates under the old minimumSeverity key.
 *
 * @param parsed - parsed configuration object to inspect for legacy gate settings
 * @returns True when `minimumSeverity` defines command threshold overrides; false otherwise.
 * @throws {ConfigLoadError} if the two gate spellings conflict.
 */
function hasLegacyCommandGate(parsed: Record<string, unknown>): boolean {
  const hasCommandThresholds = objectValue(parsed.minimumSeverity) !== undefined;
  // A user who started upgrading by hand needs to reconcile both gate settings before continuing.
  if (hasCommandThresholds && "failOn" in parsed) {
    throw new ConfigLoadError("Both minimumSeverity and failOn define command gates.", "Combine the gates under failOn before migrating.");
  }
  return hasCommandThresholds;
}

/**
 * Counts how many lines belong to an indented YAML mapping entry (its header line plus all deeper child lines).
 *
 * @param lines - full YAML lines array
 * @param index - line index of the mapping entry header
 * @returns Number of lines covered by the entry (>= 1).
 */
function indentedBlockLength(lines: string[], index: number): number {
  const indent = leadingSpaces(lines[index] ?? "");
  let end = index + 1;
  for (let child = nextContentLine(lines, end); child < lines.length; child = nextContentLine(lines, end)) {
    if (leadingSpaces(lines[child] ?? "") <= indent) {
      break;
    }
    end = child + 1;
  }
  return end - index;
}

/**
 * Counts how many lines belong to one YAML sequence item starting with `- ` at `index`, stopping before the next sibling item or dedent.
 *
 * @param lines - full YAML lines array
 * @param index - line index of the `- ` sequence item opener
 * @returns Number of lines covered by the sequence item (>= 1).
 */
function yamlSequenceItemLength(lines: string[], index: number): number {
  const indent = leadingSpaces(lines[index] ?? "");
  let end = index + 1;
  for (let child = nextContentLine(lines, end); child < lines.length; child = nextContentLine(lines, end)) {
    const childLine = lines[child] ?? "";
    const childIndent = leadingSpaces(childLine);
    if (childIndent < indent || (childIndent === indent && /^\s*-\s*/u.test(childLine))) {
      break;
    }
    end = child + 1;
  }
  return end - index;
}

/**
 * Finds the next YAML setting or value that affects which block migration may edit.
 *
 * @param lines - YAML file lines to scan forward through
 * @param index - starting line index for the forward scan
 * @returns Index of the next non-empty, non-comment line, or `lines.length` when no settings remain.
 */
function nextContentLine(lines: string[], index: number): number {
  // Comments and blank lines can sit inside a block without changing which setting owns it.
  while (index < lines.length) {
    const content = (lines[index] ?? "").trim();
    // The first non-comment line gives migration the indentation of the user's next setting.
    if (content.length > 0 && !content.startsWith("#")) {
      break;
    }
    index += 1;
  }
  return index;
}

/**
 * Counts the indentation before a YAML key or sequence item.
 *
 * @param line - single YAML line whose leading indentation is measured
 * @returns Count of leading whitespace characters before the trimmed line content.
 */
function leadingSpaces(line: string): number {
  return line.length - line.trimStart().length;
}

/**
 * Reads the unquoted scalar value from a root-level `schemaVersion:` YAML line so valid unquoted configs stay untouched.
 *
 * @param line - single root-level YAML line starting with `schemaVersion:`
 * @returns Trimmed scalar value with optional inline comment and matching outer quotes removed.
 */
function yamlSchemaVersionValue(line: string): string {
  const raw = line.replace(/^\s*(?:schemaVersion|"schemaVersion"|'schemaVersion')\s*:\s*/u, "").trim();
  // Match a quoted scalar first so an inline `#` comment after the closing quote is ignored without altering quoted text.
  const quoted = /^"([^"]*)"(?:\s+#.*)?$|^'([^']*)'(?:\s+#.*)?$/u.exec(raw);
  if (quoted) {
    return quoted[1] ?? quoted[2] ?? "";
  }
  return raw.replace(/\s+#.*$/u, "").trim();
}

/**
 * Pin the schema version, inserting it at the top when the 0.5 file never named one.
 * Leaves already-current unquoted or quoted `schemaVersion: gruff-ts.config.v0.1` lines unchanged so `migrate-config --dry-run` is idempotent.
 *
 * @param lines - migrated lines, mutated in place to insert or replace schemaVersion
 * @param changes - the rewrite log, appended to when schemaVersion is inserted or its existing value differs from 0.6
 * @param original - the file as written, returned unchanged when nothing needed rewriting
 * @param rootIndent - column where root mapping keys begin
 * @returns text and the same changes array; text is original when no rewrites were recorded
 */
function withSchemaVersion(lines: string[], changes: ConfigMigrationChange[], original: string, rootIndent: number): ConfigMigration {
  const existing = lines.findIndex((line) => leadingSpaces(line) === rootIndent && /^\s*(?:schemaVersion|"schemaVersion"|'schemaVersion')\s*:/u.test(line));
  const pinned = `${" ".repeat(rootIndent)}schemaVersion: "${SCHEMA_VERSION}"`;

  // Older projects may have no schema key. Add one without requiring the user to format it by hand.
  if (existing < 0) {
    changes.push({ line: 1, description: `schemaVersion added as ${SCHEMA_VERSION}; every 0.6 loader requires it` });
    lines.unshift(pinned);
  // Only rewrite an existing schema line when its value differs from the current 0.6 schema version.
  } else if (yamlSchemaVersionValue(lines[existing] ?? "") !== SCHEMA_VERSION) {
    changes.push({ line: existing + 1, description: `schemaVersion pinned to ${SCHEMA_VERSION}` });
    lines[existing] = pinned;
  }

  return changes.length === 0 ? { text: original, changes } : { text: lines.join(original.includes("\r\n") ? "\r\n" : "\n"), changes };
}
