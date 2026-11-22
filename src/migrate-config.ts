/*
 * Updates a 0.5 project config for 0.6 when the user runs `migrate-config`.
 *
 * Moves per-command exit gates to `failOn` and drops the obsolete secret preview setting.
 * YAML keeps surrounding comments and settings. JSON is rewritten as a document when a change is needed.
 */
import { ConfigLoadError } from "./config-load-error.ts";
import { objectValue, parseYamlConfig, SUGGEST_EDIT_CONFIG } from "./config-parse.ts";

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

/**
 * Converts legacy settings for `migrate-config` and returns the changes the CLI can show during a dry run.
 *
 * @param original - the whole config file. Empty YAML has no settings yet, while empty JSON is invalid.
 * @param format - syntax selected by the config file's extension. An omitted format uses YAML.
 * @returns the destination text and one entry per rewrite. An empty change list means the settings were current.
 * @throws {ConfigLoadError} when the input cannot be parsed or contains conflicting migration keys.
 */
export function migrateConfigText(original: string, format: "yaml" | "json" = "yaml"): ConfigMigration {
  // An editor may add a byte-order mark. Strip it before parsing the selected file format.
  const source = original.replace(/^\uFEFF/u, "");
  return format === "json" ? migrateJsonConfig(source) : migrateYamlConfig(source, original);
}

// Rewrites only the YAML lines the loader identified as legacy keys, preserving user comments and other settings.
// @throws {ConfigLoadError} when the input has conflicting keys or the revised text still carries a legacy key.
function migrateYamlConfig(source: string, original: string): ConfigMigration {
  const shouldRenameGate = hasLegacyCommandGate(parseYamlConfig(source));
  const lines = source.split(/\r?\n/u);
  const rootIndent = leadingSpaces(lines[nextContentLine(lines, 0)] ?? "");
  const changes: ConfigMigrationChange[] = [];
  const migrated: string[] = [];
  // Until the scan enters an allowlists block, no line can be one of its settings.
  let allowlistEntryIndent: number | undefined;
  let index = 0;

  // Rewrite settings in place within the text so users can compare the two YAML files line by line.
  while (index < lines.length) {
    const line = lines[index] ?? "";
    const indent = leadingSpaces(line);
    const isRootKey = indent === rootIndent && line.trim().length > 0 && !line.trimStart().startsWith("#");
    // A new top-level setting ends the previous block. Blank lines and comments keep the current block open.
    if (isRootKey) {
      allowlistEntryIndent = allowlistChildIndent(lines, index);
    }
    const removedLineCount = indent === allowlistEntryIndent ? skippedBlockLength(lines, index) : 0;

    // The retired preview setting and its indented list go together so the user gets a readable config.
    if (removedLineCount > 0) {
      changes.push({ line: index + 1, description: `allowlists.${REMOVED_ALLOWLIST_KEY} removed; FAMILY-CONTRACT.md section 5 makes category markers unconditional` });
      index += removedLineCount;
      continue;
    }

    const renamed = isRootKey && shouldRenameGate
      ? line.replace(/^(\s*)(?:minimumSeverity|"minimumSeverity"|'minimumSeverity')(\s*:)/u, "$1failOn$2")
      : line;

    // A per-command map under the old key is the exit gate, which now has its own name.
    if (renamed !== line) {
      changes.push({ line: index + 1, description: `${RENAMED_GATE_KEY}: renamed to failOn:, which is the key that gates the exit code in 0.6` });
      migrated.push(renamed);
      index += 1;
      continue;
    }

    migrated.push(line);
    index += 1;
  }

  const result = withSchemaVersion(migrated, changes, original, rootIndent);
  const updated = parseYamlConfig(result.text);
  // For example, a YAML key written in flow style can survive a line edit. Stop before emitting unusable settings.
  if (objectValue(updated.minimumSeverity) !== undefined || Object.hasOwn(objectValue(updated.allowlists) ?? {}, REMOVED_ALLOWLIST_KEY)) {
    throw new ConfigLoadError("The legacy gate or allowlist could not be migrated safely.", SUGGEST_EDIT_CONFIG);
  }
  return result;
}

// Migrates JSON as a mapping. Its schema version and gate must be readable by the config loader.
// The change list uses line 1 for whole-document rewrites.
// @throws {ConfigLoadError} when the input is malformed or the legacy gate conflicts with an existing gate.
function migrateJsonConfig(source: string): ConfigMigration {
  let parsed: Record<string, unknown> | undefined;
  try {
    parsed = objectValue(JSON.parse(source));
  } catch {
    // A user may select a JSON file with a trailing comma copied from JavaScript.
    throw new ConfigLoadError("The migration input is not valid JSON.", SUGGEST_EDIT_CONFIG);
  }
  // The config must name settings. A JSON null or array supplies no mapping to migrate.
  if (!parsed) {
    throw new ConfigLoadError("The migration input must be a JSON object.", SUGGEST_EDIT_CONFIG);
  }
  const changes: ConfigMigrationChange[] = [];
  // Carry over per-command gates. A scalar minimumSeverity still represents a display floor.
  if (hasLegacyCommandGate(parsed)) {
    parsed.failOn = parsed.minimumSeverity;
    delete parsed.minimumSeverity;
    changes.push({ line: 1, description: "Renamed the per-command minimumSeverity mapping to failOn" });
  }
  const allowlists = objectValue(parsed.allowlists);
  // Files with no allowlists or no legacy preview entry have nothing to remove.
  if (allowlists && Object.hasOwn(allowlists, REMOVED_ALLOWLIST_KEY)) {
    delete allowlists[REMOVED_ALLOWLIST_KEY];
    changes.push({ line: 1, description: `Removed allowlists.${REMOVED_ALLOWLIST_KEY}` });
  }
  // A missing or older version needs the current version before the user can select the migrated file.
  if (parsed.schemaVersion !== SCHEMA_VERSION) {
    parsed.schemaVersion = SCHEMA_VERSION;
    changes.push({ line: 1, description: `Set schemaVersion to ${SCHEMA_VERSION}` });
  }
  return { changes, text: changes.length > 0 ? `${JSON.stringify(parsed, null, 2)}\n` : source };
}

// Tells migration whether the user set per-command gates under the old minimumSeverity key.
// @throws {ConfigLoadError} if the two gate spellings conflict.
function hasLegacyCommandGate(parsed: Record<string, unknown>): boolean {
  const hasCommandThresholds = objectValue(parsed.minimumSeverity) !== undefined;
  // A user who started upgrading by hand needs to reconcile both gate settings before continuing.
  if (hasCommandThresholds && "failOn" in parsed) {
    throw new ConfigLoadError("Both minimumSeverity and failOn define command gates.", "Combine the gates under failOn before migrating.");
  }
  return hasCommandThresholds;
}

// Finds the indentation of allowlists entries so migration can remove the retired setting within that block.
// Returns undefined when the current line starts another setting or the allowlists block has no children.
function allowlistChildIndent(lines: string[], index: number): number | undefined {
  const header = lines[index] ?? "";
  // Keep the user's other top-level settings outside the removal scope.
  if (!/^\s*(?:allowlists|"allowlists"|'allowlists')\s*:\s*(?:#.*)?$/u.test(header)) {
    return undefined;
  }
  const childIndent = leadingSpaces(lines[nextContentLine(lines, index + 1)] ?? "");
  return childIndent > leadingSpaces(header) ? childIndent : undefined;
}

/**
 * Counts the preview setting's YAML lines so migration can remove the full block.
 *
 * @param lines - the whole file, split on newlines
 * @param index - the line being considered
 * @returns the number of lines to drop, or zero when the user's current line should be kept
 */
function skippedBlockLength(lines: string[], index: number): number {
  const line = lines[index] ?? "";
  const match = /^\s+(?:secretPreviews|"secretPreviews"|'secretPreviews')\s*:/u.test(line);

  // A different setting in the user's allowlists block stays in the file.
  if (!match) {
    return 0;
  }

  const indent = leadingSpaces(line);
  let end = index + 1;
  // Include every nested preview entry, such as items a user listed on separate lines.
  for (let child = nextContentLine(lines, end); child < lines.length; child = nextContentLine(lines, end)) {
    // The next sibling setting belongs to the user and must survive the removal.
    if (leadingSpaces(lines[child] ?? "") <= indent) {
      break;
    }
    end = child + 1;
  }
  return end - index;
}

// Finds the next YAML setting or value that affects which block migration may edit.
// Returns the line count when no settings remain after the starting position.
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

// Counts the indentation before a YAML key or sequence item.
function leadingSpaces(line: string): number {
  return line.length - line.trimStart().length;
}

/**
 * Pin the schema version, inserting it at the top when the 0.5 file never named one.
 *
 * @param lines - migrated lines, mutated in place to insert or replace schemaVersion
 * @param changes - the rewrite log, appended to when schemaVersion is inserted or its existing line needs repinning
 * @param original - the file as written, returned unchanged when nothing needed rewriting
 * @param rootIndent - column where root mapping keys begin
 * @returns - text and the same changes array; text is original when no rewrites were recorded
 */
function withSchemaVersion(lines: string[], changes: ConfigMigrationChange[], original: string, rootIndent: number): ConfigMigration {
  const existing = lines.findIndex((line) => leadingSpaces(line) === rootIndent && /^\s*(?:schemaVersion|"schemaVersion"|'schemaVersion')\s*:/u.test(line));
  const pinned = `${" ".repeat(rootIndent)}schemaVersion: "${SCHEMA_VERSION}"`;

  // Older projects may have no schema key. Add one without requiring the user to format it by hand.
  if (existing < 0) {
    changes.push({ line: 1, description: `schemaVersion added as ${SCHEMA_VERSION}; every 0.6 loader requires it` });
    lines.unshift(pinned);
  // Bring an existing schema line into the format emitted for the current loader.
  } else if (lines[existing] !== pinned) {
    changes.push({ line: existing + 1, description: `schemaVersion pinned to ${SCHEMA_VERSION}` });
    lines[existing] = pinned;
  }

  return changes.length === 0 ? { text: original, changes } : { text: lines.join(original.includes("\r\n") ? "\r\n" : "\n"), changes };
}
