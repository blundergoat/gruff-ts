// Recovers supported settings when a user regenerates an older config with `init --force`.
//
// Keeps ignored paths, command gates, and valid sensitive exclusions with their reasons.
// Empty collections mean no usable entries were recovered for that setting.
import { objectValue, parseConfigFile } from "./config-parse.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { parseSensitiveExclusions } from "./sensitive-exclusions.ts";
import type { FailThreshold, MinimumSeverityCommand, SensitiveExclusion } from "./types.ts";

// Settings recovered for `init --force`. Each empty collection leaves the new config with its generated settings.
interface PreservedConfigFields {
  ignoredPaths: string[];
  failOn: Map<MinimumSeverityCommand, FailThreshold>;
  sensitiveExclusions: SensitiveExclusion[];
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
 * @param raw - parsed config. An absent or empty sensitiveExclusions list supplies no exclusions to carry forward.
 * @returns validated exclusion scopes in order. An invalid entry contributes no exclusion.
 * @throws unexpected errors from the exclusion validator.
 */
function extractSensitiveExclusions(raw: Record<string, unknown>): SensitiveExclusion[] {
  const entries = raw.sensitiveExclusions;
  // Some older projects have no exclusion list to carry over.
  if (!Array.isArray(entries)) {
    return [];
  }
  const preserved: SensitiveExclusion[] = [];
  const seen = new Set<string>();
  // Review each entry separately so one malformed scope does not discard the user's other exclusions.
  for (const entry of entries) {
    try {
      const [candidate] = parseSensitiveExclusions({ sensitiveExclusions: [entry] });
      // A validator result without a scope adds nothing to the regenerated file.
      if (candidate === undefined) {
        continue;
      }
      const scope = JSON.stringify([candidate.rule, candidate.path, candidate.symbol]);
      // A pasted duplicate keeps the first scope and its original written reason.
      if (!seen.has(scope)) {
        preserved.push(candidate);
        seen.add(scope);
      }
    } catch (error) {
      // A user might have left an exclusion's scope incomplete. Skip invalid config entries and surface unexpected failures.
      if (!(error instanceof ConfigLoadError)) {
        throw error;
      }
    }
  }
  return preserved;
}

/**
 * Extracts glob strings from `paths.ignore` in a parsed config for regeneration, skipping non-string entries.
 *
 * @param raw - parsed existing config mapping to inspect for a `paths.ignore` list
 * @returns glob strings from `paths.ignore`, or an empty list when missing or not an array
 */
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

/**
 * Stores an existing config's failure threshold for a supported command in the destination map used for regeneration.
 *
 * @param result - destination map mutated with the validated command threshold when both inputs are supported
 * @param commandName - command name key from the parsed config; only `analyse`, `summary`, and `report` are accepted
 * @param rawThreshold - candidate threshold value; only `none`, `advisory`, `warning`, and `error` are stored
 * @returns Nothing. Leaves `result` unchanged when the command or threshold is unsupported.
 */
function addPreservedSeverityEntry(result: Map<MinimumSeverityCommand, FailThreshold>, commandName: string, rawThreshold: unknown): void {
  if (commandName !== "analyse" && commandName !== "summary" && commandName !== "report") {
    return;
  }
  if (rawThreshold !== "none" && rawThreshold !== "advisory" && rawThreshold !== "warning" && rawThreshold !== "error") {
    return;
  }
  result.set(commandName, rawThreshold);
}
