// Best-effort field extraction for `gruff-ts init --force`. The strict loader in `config.ts`
// throws on schemaVersion mismatch (deliberate: pre-1.0 break, no migration shim), but the init
// migration path needs to lift `paths.ignore` and `minimumSeverity` off whatever the user has on
// disk so regeneration does not silently clobber curated entries. This module exists because the
// strict validator is the wrong tool for that handoff - the next analyser load will run it.
import { objectValue, parseConfigFile } from "./config-parse.ts";
import type { FailThreshold, MinimumSeverityCommand } from "./types.ts";

// Carry-over bundle returned to `gruff-ts init --force`. Both fields are best-effort: empty
// values mean nothing was preserved, not that the existing config was empty.
interface PreservedConfigFields {
  ignoredPaths: string[];
  minimumSeverity: Map<MinimumSeverityCommand, FailThreshold>;
}

/*
 * Reads the existing config and returns its `paths.ignore` and `minimumSeverity` blocks. Pre-0.2.0
 * configs without `schemaVersion` succeed here (the strict gate is skipped) so the user's entries
 * survive `init --force`. Individual malformed entries inside the preserved blocks are dropped
 * rather than thrown - the strict validator runs at the next analyser load and surfaces errors
 * in the right place. Throws `ConfigLoadError` only on IO/parse failure of the file itself; the
 * caller handles that fallback to "preserve nothing" instead of blocking regeneration.
 */
export function extractPreservedConfigFields(configPath: string): PreservedConfigFields {
  const raw = parseConfigFile(configPath);
  return {
    ignoredPaths: extractIgnoredPaths(raw),
    minimumSeverity: extractMinimumSeverity(raw),
  };
}

// `paths.ignore` is a free-form list of glob strings. Non-string entries are dropped silently -
// the strict path enforces the same shape at the next analyser load.
function extractIgnoredPaths(raw: Record<string, unknown>): string[] {
  const ignore = objectValue(raw.paths)?.ignore;
  return Array.isArray(ignore) ? ignore.filter((entry): entry is string => typeof entry === "string") : [];
}

// Permissive minimumSeverity reader: each entry is filtered through the same vocabulary the strict
// validator checks (commands × thresholds). Anything off-vocabulary is dropped. The reason we
// don't throw here is so a typo in one entry does not nuke preservation of the other entries.
function extractMinimumSeverity(raw: Record<string, unknown>): Map<MinimumSeverityCommand, FailThreshold> {
  const result = new Map<MinimumSeverityCommand, FailThreshold>();
  const block = objectValue(raw.minimumSeverity);
  if (!block) {
    return result;
  }
  for (const [commandName, value] of Object.entries(block)) {
    addPreservedSeverityEntry(result, commandName, value);
  }
  return result;
}

// Per-entry filter: extracted so the outer loop stays linear and the NPath budget for the file
// extractor stays small. Both gates must pass before the entry lands in the preserved map.
function addPreservedSeverityEntry(result: Map<MinimumSeverityCommand, FailThreshold>, commandName: string, rawThreshold: unknown): void {
  if (commandName !== "analyse" && commandName !== "summary" && commandName !== "report") {
    return;
  }
  if (rawThreshold !== "none" && rawThreshold !== "advisory" && rawThreshold !== "warning" && rawThreshold !== "error") {
    return;
  }
  result.set(commandName, rawThreshold);
}
