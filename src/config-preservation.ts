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
    sensitiveExclusions: extractSensitiveExclusions(raw),
  };
}

/*
 * Carries `sensitiveExclusions:` through regeneration. Dropping these would silently re-enable
 * findings a reviewer had deliberately accepted with a written rationale, which is the opposite of
 * what a reason-bearing suppression is for - the user would have no signal that their exclusions
 * were gone. Entries missing a required field are dropped here and re-reported by the strict
 * parser at the next analyser load, where the diagnostic belongs.
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

// Per-entry filter, extracted so the outer loop stays linear. Only the four ratified keys survive;
// anything else the user wrote is a rejection case the strict parser must report, not a value to
// carry forward into a regenerated file.
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
