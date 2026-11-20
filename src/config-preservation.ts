// Best-effort field extraction for `gruff-ts init --force`. The strict loader in `config.ts`
// throws on schemaVersion mismatch (deliberate: pre-1.0 break, no migration shim), but the init
// migration path needs to lift `paths.ignore` and the per-command gate off whatever the user has on
// disk so regeneration does not silently clobber curated entries. This module exists because the
// strict validator is the wrong tool for that handoff - the next analyser load will run it.
import { objectValue, parseConfigFile } from "./config-parse.ts";
import type { FailThreshold, MinimumSeverityCommand } from "./types.ts";

// Carry-over bundle returned to `gruff-ts init --force`. Both fields are best-effort: empty
// values mean nothing was preserved, not that the existing config was empty.
interface PreservedConfigFields {
  ignoredPaths: string[];
  failOn: Map<MinimumSeverityCommand, FailThreshold>;
  sensitiveExclusions: PreservedSensitiveExclusion[];
}

// One carried-over `sensitiveExclusions:` entry. Kept as plain strings because regeneration only
// needs to re-emit what the user wrote; the strict parser validates it at the next analyser load.
interface PreservedSensitiveExclusion {
  rule: string;
  path: string;
  symbol?: string;
  reason: string;
}

/**
 * Recovers settings before init --force regenerates a config. Files without a schemaVersion can still supply settings.
 * The regeneration caller proceeds with empty fields if reading or parsing fails.
 *
 * @param configPath - path to the existing config to read
 * @returns - preserved ignore globs, command thresholds, and sensitive exclusions, with empty collections for unavailable entries
 * @throws {ConfigLoadError} - for a missing file, unsupported extension, invalid syntax, or a root value that is not a mapping
 * @throws {Error} - when another filesystem read error occurs
 */
export function extractPreservedConfigFields(configPath: string): PreservedConfigFields {
  const raw = parseConfigFile(configPath);
  return {
    ignoredPaths: extractIgnoredPaths(raw),
    failOn: extractFailOn(raw),
    sensitiveExclusions: extractSensitiveExclusions(raw),
  };
}

/**
 * Carries existing sensitive exclusions and their written reasons into the regenerated config.
 *
 * @param raw - parsed existing config that may contain a sensitiveExclusions list
 * @returns - entries with string rule, path, and reason fields and any string symbol, or an empty list when no entries qualify
 */
function extractSensitiveExclusions(raw: Record<string, unknown>): PreservedSensitiveExclusion[] {
  const entries = raw.sensitiveExclusions;
  if (!Array.isArray(entries)) {
    return [];
  }
  const preserved: PreservedSensitiveExclusion[] = [];
  for (const entry of entries) {
    const candidate = preservedSensitiveExclusion(entry);
    if (candidate !== undefined) {
      preserved.push(candidate);
    }
  }
  return preserved;
}

// Copies one existing sensitive exclusion for regeneration, keeping rule, path, reason, and a string symbol if supplied.
// Returns undefined for a non-mapping or when rule, path, or reason is missing or is not a string.
// The caller skips entries that return undefined.
function preservedSensitiveExclusion(entry: unknown): PreservedSensitiveExclusion | undefined {
  const block = objectValue(entry);
  if (!block) {
    return undefined;
  }
  const rule = block.rule;
  const path = block.path;
  const reason = block.reason;
  const symbol = block.symbol;
  if (typeof rule !== "string" || typeof path !== "string" || typeof reason !== "string") {
    return undefined;
  }
  return typeof symbol === "string" ? { rule, path, symbol, reason } : { rule, path, reason };
}

// Returns the glob strings from paths.ignore in the parsed existing config for regeneration.
// Skips non-string entries and returns an empty list when the ignore list is missing or has another shape.
function extractIgnoredPaths(raw: Record<string, unknown>): string[] {
  const ignore = objectValue(raw.paths)?.ignore;
  return Array.isArray(ignore) ? ignore.filter((entry): entry is string => typeof entry === "string") : [];
}

/**
 * Preserves valid per-command gates during config rewrites so that one invalid entry does not discard the others.
 *
 * @param raw - parsed file settings. Legacy minimumSeverity: supplies gates only when failOn supplies no mapping.
 * @returns - map from command to threshold, empty when there is no mapping or no valid entry
 */
function extractFailOn(raw: Record<string, unknown>): Map<MinimumSeverityCommand, FailThreshold> {
  const result = new Map<MinimumSeverityCommand, FailThreshold>();
  const block = objectValue(raw.failOn) ?? objectValue(raw.minimumSeverity);
  if (!block) {
    return result;
  }
  for (const [commandName, value] of Object.entries(block)) {
    addPreservedSeverityEntry(result, commandName, value);
  }
  return result;
}

// Returns nothing. Stores the existing config's failure threshold for the command in the destination map used for regeneration.
// An unsupported command or threshold leaves the destination map unchanged.
function addPreservedSeverityEntry(result: Map<MinimumSeverityCommand, FailThreshold>, commandName: string, rawThreshold: unknown): void {
  if (commandName !== "analyse" && commandName !== "summary" && commandName !== "report") {
    return;
  }
  if (rawThreshold !== "none" && rawThreshold !== "advisory" && rawThreshold !== "warning" && rawThreshold !== "error") {
    return;
  }
  result.set(commandName, rawThreshold);
}
