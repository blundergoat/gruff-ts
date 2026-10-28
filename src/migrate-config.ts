/*
 * Carries a 0.5 configuration forward to the 0.6 schema, out of place and line by line.
 *
 * Two keys moved in 0.6.0 and a user's committed file still spells them the old way: the per-command exit gate left
 * `minimumSeverity:` for `failOn:`, and `allowlists.secretPreviews` was removed outright because section 5 makes
 * category markers unconditional. A file carrying either is refused by the loader, so a user upgrading needs a way
 * across that does not mean re-typing their configuration.
 *
 * The rewrite is line-oriented rather than a parse-and-re-render, which keeps every comment, every blank line and
 * every value the user wrote exactly as written. Only the lines that must change are touched, and everything the
 * migration does not understand passes through untouched rather than being dropped as unrecognised.
 */
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
 * `text` is what the destination should contain; `changes` is empty when the input was already current, in which
 * case `text` is the input byte for byte.
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
 * Rewrite one configuration's text for the current schema, leaving everything the migration does not understand alone.
 *
 * @param original - the whole 0.5 configuration file, as written
 * @returns the migrated text and one entry per rewrite; no rewrites means the text is returned unchanged
 */
export function migrateConfigText(original: string): ConfigMigration {
  const lines = original.split("\n");
  const changes: ConfigMigrationChange[] = [];
  const migrated: string[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = lines[index] ?? "";
    const skipped = skippedBlockLength(lines, index);

    // The removed key takes its whole indented block with it, or an empty list stays behind meaning nothing.
    if (skipped > 0) {
      changes.push({ line: index + 1, description: `allowlists.${REMOVED_ALLOWLIST_KEY} removed; FAMILY-CONTRACT.md section 5 makes category markers unconditional` });
      index += skipped;
      dropEmptiedParent(migrated, lines, index);
      continue;
    }

    const renamed = renamedGateLine(lines, index);

    // A per-command map under the old key is the exit gate, which now has its own name.
    if (renamed !== null) {
      changes.push({ line: index + 1, description: `${RENAMED_GATE_KEY}: renamed to failOn:, which is the key that gates the exit code in 0.6` });
      migrated.push(renamed);
      index += 1;
      continue;
    }

    migrated.push(line);
    index += 1;
  }

  return withSchemaVersion(migrated, changes, original);
}

/**
 * Report how many lines the removed redaction key occupies, counting any block indented beneath it.
 *
 * Reads the lines it is given and writes nothing; the caller decides what to do with the length.
 *
 * @param lines - the whole file, split on newlines
 * @param index - the line being considered
 * @returns the number of lines to drop, or 0 when this line is not the removed key
 */
function skippedBlockLength(lines: string[], index: number): number {
  const line = lines[index] ?? "";
  const match = /^(\s+)secretPreviews\s*:/u.exec(line);

  // Only the nested allowlists entry is removed; a root key of the same name is not a thing any port ever wrote.
  if (match === null) {
    return 0;
  }

  const indent = (match[1] ?? "").length;
  let length = 1;

  while (index + length < lines.length && isDeeperThan(lines[index + length] ?? "", indent)) {
    length += 1;
  }

  return length;
}

/**
 * Rewrite the old gate key when it introduces a per-command block, and leave the scalar display floor alone.
 *
 * Reads the lines it is given and writes nothing; the rewritten line is returned rather than applied.
 *
 * @param lines - the whole file, split on newlines
 * @param index - the line being considered
 * @returns the rewritten line, or null when this line is not the old gate key in its block form
 */
function renamedGateLine(lines: string[], index: number): string | null {
  const line = lines[index] ?? "";
  const match = /^(\s*)minimumSeverity\s*:\s*(.*)$/u.exec(line);

  // A commented-out key is prose, and a key with a value on the same line is the 0.6 display floor.
  if (match === null || (match[2] ?? "").trim().length > 0) {
    return null;
  }

  const indent = (match[1] ?? "").length;

  // An empty block would be a key with nothing under it, which the loader reads as neither shape.
  return isDeeperThan(lines[index + 1] ?? "", indent) ? `${match[1] ?? ""}failOn:` : null;
}

/**
 * Drop the block header the removal just emptied, because a key with nothing under it is not a valid mapping.
 *
 * Only a header whose last child was removed is dropped: if any line still belongs to the block, or anything
 * follows it at a deeper indent, the header stays exactly as the user wrote it.
 *
 * @param migrated - the lines kept so far, whose tail may now be an emptied header
 * @param lines - the whole input, read ahead to see whether the block has any child left
 * @param index - the first input line after the removed block
 * @returns nothing; the emptied header is removed from `migrated` in place
 */
function dropEmptiedParent(migrated: string[], lines: string[], index: number): void {
  const header = migrated.at(-1) ?? "";

  // A header is a bare `key:` with no value; anything else is a line the user wants kept.
  if (!/^\s*[^\s#][^:]*:\s*$/u.test(header)) {
    return;
  }

  const headerIndent = header.length - header.trimStart().length;

  // A block that still has a child is not empty, so its header stays.
  if (isDeeperThan(lines[index] ?? "", headerIndent)) {
    return;
  }

  migrated.pop();
}

/** True when a line belongs to a block opened at the given indent, so blank lines inside one do not end it. */
function isDeeperThan(line: string, indent: number): boolean {
  return line.trim().length > 0 && line.length - line.trimStart().length > indent;
}

/**
 * Pin the schema version, inserting it at the top when the 0.5 file never named one.
 *
 * @param lines - the migrated lines so far
 * @param changes - the rewrites applied so far, appended to when the version moves
 * @param original - the file as written, returned unchanged when nothing needed rewriting
 * @returns the migration result
 */
function withSchemaVersion(lines: string[], changes: ConfigMigrationChange[], original: string): ConfigMigration {
  const existing = lines.findIndex((line) => /^schemaVersion\s*:/u.test(line));
  const pinned = `schemaVersion: "${SCHEMA_VERSION}"`;

  if (existing < 0) {
    changes.push({ line: 1, description: `schemaVersion added as ${SCHEMA_VERSION}; every 0.6 loader requires it` });
    lines.unshift(pinned);
  } else if ((lines[existing] ?? "").trim() !== pinned) {
    changes.push({ line: existing + 1, description: `schemaVersion pinned to ${SCHEMA_VERSION}` });
    lines[existing] = pinned;
  }

  return changes.length === 0 ? { text: original, changes } : { text: lines.join("\n"), changes };
}
