// Resolves the project settings used by analyse, summary, report, and hook.
//
// Starts with built-in defaults and layers on settings from the user's project, profile, and command flags.
// Invalid settings produce a startup error before the user relies on the requested scan or exit gate.
import { existsSync } from "node:fs";
import { basename, dirname, isAbsolute, join } from "node:path";
import { arrayValue, isString, objectValue, parseConfigFile, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE } from "./config-parse.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { BUILT_IN_PROFILES, builtInProfileNames, DEFAULT_PROFILE_NAME, isKnownRuleId, ruleOptionKeys } from "./profiles.ts";
import { ruleDefaultEnabled } from "./rules.ts";
import { applyExecutionSelectors } from "./selectors.ts";
import { parseSensitiveExclusions } from "./sensitive-exclusions.ts";
import type { AnalysisOptions, Config, DeepScanBudgetOverride, FailThreshold, InlineProfileSpec, MinimumSeverityCommand, ProfileDefinition, ProfileRuleSetting, ProfileSpec, Severity } from "./types.ts";

// Represents one validated per-rule override before it joins the user's effective configuration.
//
// Optional fields preserve the difference between an omitted setting and an explicit value.
type RuleOverride = Config["rules"] extends Map<string, infer RuleOverrideValue> ? RuleOverrideValue : never;

const DEFAULT_CONFIG_FILES = [".gruff-ts.yaml", ".gruff.json", ".gruff.yaml", ".gruff.yml"] as const;

/*
 * Every key a `.gruff-ts.yaml` may carry, at the root and inside the two blocks that take a fixed set.
 *
 * A key outside these sets is refused rather than ignored: a misspelled `sensitivExclusions:` or `minimumSeverty:`
 * that loads silently is a setting the user believes is in force and is not, which is the one configuration failure
 * a reader cannot see by looking at their own file.
 */
const KNOWN_ROOT_KEYS: ReadonlySet<string> = new Set([
  "schemaVersion", "profile", "deepScanBudget", "minimumSeverity", "failOn", "paths", "allowlists", "rules", "sensitiveExclusions",
]);
const KNOWN_PATHS_KEYS: ReadonlySet<string> = new Set(["ignore"]);
const KNOWN_ALLOWLISTS_KEYS: ReadonlySet<string> = new Set([
  "acceptedAbbreviations", "acceptedClassFilePairs", "placeholderNames", "trackingTokens",
  // Recognised only so the loader can refuse it by name with section 5's explanation, rather than as an unknown key.
  "secretPreviews",
]);
const LEGACY_SECRET_PREVIEWS_ERROR = 'Config key "allowlists.secretPreviews" is removed in 0.6.0: FAMILY-CONTRACT.md section 5 makes category markers unconditional, so the key authorises nothing; delete it from the configuration.';
const LEGACY_MINIMUM_SEVERITY_ERROR = 'Config key "minimumSeverity" is the display floor in 0.6.0 and takes one severity, not a per-command map; move the per-command exit gate to "failOn", which is the key that gates the exit code.';
// Pinned-corpus size and scan-cost measurements set these paired defaults because either line count
// or byte count can make deep parsing disproportionately expensive while ordinary source stays below both.
export const DEEP_SCAN_DEFAULT_MAX_LINES = 20_000;
export const DEEP_SCAN_DEFAULT_MAX_BYTES = 2_000_000;

// Creates the complete zero-config behavior used when a user runs Gruff without custom settings.
// User and profile values may overlay these defaults later; the schema version remains fixed for this release.
function defaultConfig(): Config {
  return {
    schemaVersion: "gruff-ts.config.v0.1",
    ignoredPaths: [],
    acceptedAbbreviations: new Set(["age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url"]),
    acceptedClassFilePairs: new Set(),
    placeholderNames: new Set(["foo", "bar", "baz", "tmp", "temp", "thing", "stuff", "data", "value", "item"]),
    trackingTokens: [],
    minimumSeverity: new Map(),
    rules: new Map(),
    deepScanBudget: {
      enabled: true,
      maxLines: DEEP_SCAN_DEFAULT_MAX_LINES,
      maxBytes: DEEP_SCAN_DEFAULT_MAX_BYTES,
      override: "default",
    },
    sensitiveExclusions: [],
  };
}

// Resolves a user-supplied config or profile path against the caller's base directory.
// Absolute paths remain unchanged so CLI and config-file references behave consistently.
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Returns effective analysis settings after layering the config file, profile, CLI budget, and rule selectors over the defaults.
// The project root anchors discovery and profile resolution. CLI options can choose or skip a file and override the profile.
// A missing default file leaves the built-in settings as the starting point. Read, parse, and validation errors stop loading.
function loadConfig(projectRoot: string, options: AnalysisOptions): Config {
  const config = defaultConfig();
  const path = options.shouldSkipConfig ? undefined : selectedConfigPath(projectRoot, options);
  const parsedConfig: Record<string, unknown> = path ? parseConfigFile(path, options.config ?? basename(path)) : {};
  // Schema and supported-key checks apply to selected files. Zero-config use needs no file.
  if (path) {
    applyConfigValues(config, parsedConfig);
  }
  applyProfile(config, options, parsedConfig, projectRoot);
  applyDeepScanBudgetOverride(config, options.deepScanBudget);
  // The execution selectors choose which rules run, so they narrow the catalogue last, after every other source.
  applyExecutionSelectors(config, options.execution);
  return config;
}

// Returns nothing. Fills missing rule entries in the effective config from the selected profile and merges its ignore paths.
// Selects the CLI profile before the parsed file's profile, even when file loading is skipped.
// Resolves the initial file reference from the project root. Profile configuration errors stop loading.
function applyProfile(config: Config, options: AnalysisOptions, parsedConfig: Record<string, unknown>, projectRoot: string): void {
  const configuredProfile = options.profile !== undefined ? options.profile : parsedConfig.profile;
  // When both sources omit a profile, the current defaults and explicit settings carry forward.
  if (configuredProfile === undefined) {
    return;
  }
  applyProfileUnderlay(config, resolveProfile(parseProfileSpec(configuredProfile), projectRoot));
}

// Returns nothing. Fills the effective config's missing rule entries from the resolved profile.
// Profile ignore paths join explicit ignores so either user choice keeps a path out of the scan.
function applyProfileUnderlay(config: Config, definition: ProfileDefinition): void {
  for (const [ruleId, setting] of definition.rules) {
    // An existing rule entry came from the user's top-level config and must remain authoritative.
    if (!config.rules.has(ruleId)) {
      config.rules.set(ruleId, profileRuleToConfig(setting));
    }
  }
  // Empty profile ignores leave the user's current scan surface unchanged.
  if (definition.ignoredPaths.length > 0) {
    config.ignoredPaths = [...new Set([...config.ignoredPaths, ...definition.ignoredPaths])];
  }
}

// Converts one profile rule into the shape used during analysis.
// Omitted fields stay absent, while missing options become an empty map for callers that enumerate them.
function profileRuleToConfig(setting: ProfileRuleSetting): RuleOverride {
  return {
    ...(setting.enabled !== undefined ? { enabled: setting.enabled } : {}),
    ...(setting.threshold !== undefined ? { threshold: setting.threshold } : {}),
    ...(setting.severity !== undefined ? { severity: setting.severity } : {}),
    options: setting.options ?? new Map(),
  };
}

// Returns the effective built-in, file-backed, or inline profile, with child overrides taking precedence.
// Uses the project root for initial relative paths and starts a new visit chain when none is supplied.
// References stay local. Config errors can report invalid profiles or use the visit chain to explain inheritance cycles.
function resolveProfile(spec: ProfileSpec, projectRoot: string, chain: string[] = []): ProfileDefinition {
  if (typeof spec === "string") {
    return resolveProfileRef(spec, projectRoot, chain);
  }
  return resolveInlineProfile(spec, projectRoot, chain);
}

// Returns the resolved profile for a bundled name or a local file reference.
// Bundled names take precedence. A leading ./ selects a file, resolved from the supplied directory.
// File resolution uses the visit chain to detect cycles and can fail with a config error.
function resolveProfileRef(ref: string, projectRoot: string, chain: string[]): ProfileDefinition {
  const builtIn = BUILT_IN_PROFILES.get(ref) ?? BUILT_IN_PROFILES.get(`gruff.${ref}`);
  // A bundled match receives its own rule map and ignore list so collection edits cannot alter the preset.
  if (builtIn) {
    return cloneProfileDefinition(builtIn);
  }
  return resolveProfileFile(ref, projectRoot, chain);
}

// Returns a local profile with its inherited settings resolved before analysis.
// Resolves the reference from the supplied directory and uses the file's own directory for relative bases.
// The visit chain tracks ancestor paths for cycle detection. Other filesystem read errors propagate.
// @throws {ConfigLoadError} - if a profile file is missing or invalid, or inheritance revisits a path in the chain.
function resolveProfileFile(ref: string, projectRoot: string, chain: string[]): ProfileDefinition {
  const path = absolutize(projectRoot, ref);
  assertNoProfileCycle(path, chain);
  // A missing user-selected file cannot safely fall back to a different profile.
  if (!existsSync(path)) {
    throw new ConfigLoadError(
      `Profile extends file not found: ${path}.`,
      `Point \`extends:\` (or --profile) at an existing .yaml/.yml/.json profile file, or use a built-in name: ${builtInProfileNames().join(", ")}.`,
    );
  }
  return resolveInlineProfile(inlineSpecFromObject(parseConfigFile(path)), dirname(path), [...chain, path]);
}

// Returns the inline profile with its overrides applied to the resolved base.
// Resolves relative bases from the supplied directory, which contains the profile file for file-backed profiles. The visit chain detects cycles.
// Omitted extends selects the recommended profile. Invalid base profiles or child rules can stop loading with ConfigLoadError.
function resolveInlineProfile(spec: InlineProfileSpec, projectRoot: string, chain: string[]): ProfileDefinition {
  const base = resolveProfileRef(spec.extends ?? DEFAULT_PROFILE_NAME, projectRoot, chain);
  return overlayProfile(base, spec);
}

// Returns a new profile with inline settings taking precedence over the resolved base field by field.
// A supplied ignore list replaces the base list. Omission inherits it.
// Throws ConfigLoadError when a child rule ID is outside the catalogue.
function overlayProfile(base: ProfileDefinition, spec: InlineProfileSpec): ProfileDefinition {
  const rules = new Map(base.rules);
  // Each child rule may override only the fields the user supplied while retaining inherited fields.
  for (const [ruleId, setting] of Object.entries(spec.rules ?? {})) {
    assertKnownProfileRule(ruleId);
    rules.set(ruleId, mergeRuleSetting(rules.get(ruleId), setting));
  }
  const ignoredPaths = spec.ignoredPaths !== undefined ? [...spec.ignoredPaths] : [...base.ignoredPaths];
  return { name: base.name, rules, ignoredPaths };
}

// Merges one inherited rule setting with the user's child fields.
// Explicit false and zero values win, while omitted fields continue to inherit.
// Without a parent setting, the result contains only the child fields.
function mergeRuleSetting(parent: ProfileRuleSetting | undefined, child: ProfileRuleSetting): ProfileRuleSetting {
  return { ...parent, ...child };
}

// Returns a copy of the resolved profile with its own rule map and ignore list. The rule settings inside the map remain shared.
// Use this for bundled profiles whose shared definitions must remain stable across commands.
function cloneProfileDefinition(definition: ProfileDefinition): ProfileDefinition {
  return { name: definition.name, rules: new Map(definition.rules), ignoredPaths: [...definition.ignoredPaths] };
}

// Returns nothing after checking the profile path against the active resolution chain to prevent recursive loading from looping.
// Throws with the visit order so users can find and break the extends cycle.
// @throws {ConfigLoadError} - when the key is already in the chain of profile paths being resolved.
function assertNoProfileCycle(key: string, chain: string[]): void {
  // A repeated path means the user's profile chain has returned to a file already being resolved.
  if (chain.includes(key)) {
    throw new ConfigLoadError(
      `Profile inheritance cycle detected: ${[...chain, key].join(" -> ")}.`,
      "Break the `extends:` cycle so each profile in the chain is reached only once.",
    );
  }
}

// Returns nothing after checking the profile's rule identifier against the catalogue before it can affect analysis.
// Throws for unknown names so users do not mistake a typo for applied policy.
// @throws {ConfigLoadError} - when the rule id is not in the gruff-ts rule catalogue.
function assertKnownProfileRule(ruleId: string): void {
  // A name outside the rule catalogue cannot produce the behavior the user requested.
  if (!isKnownRuleId(ruleId)) {
    throw new ConfigLoadError(
      `Unknown rule id in profile: ${JSON.stringify(ruleId)}.`,
      "Use a rule id from `gruff-ts list-rules`; profile `rules:` keys must match the catalogue exactly.",
    );
  }
}

// Converts the user's parsed profile value into a named/file reference or inline profile.
// An empty mapping leaves base selection to the profile resolver.
// @throws {ConfigLoadError} - for a value outside string or mapping, a non-string extends, or a rule mapping that fails field validation.
function parseProfileSpec(configuredProfile: unknown): ProfileSpec {
  // A string preserves the exact built-in name or local path the user selected.
  if (typeof configuredProfile === "string") {
    return configuredProfile;
  }
  const block = objectValue(configuredProfile);
  // A non-string value with another shape cannot identify a profile, so config loading stops.
  if (!block) {
    throw new ConfigLoadError(
      "`profile:` must be a built-in name, a profile file path, or a mapping with `extends:` and overrides.",
      SUGGEST_EDIT_CONFIG,
    );
  }
  return inlineSpecFromObject(block);
}

// Returns the overrides read from a parsed inline or file-backed profile mapping.
// Without an extends field, resolution uses the recommended profile. Extra top-level fields have no effect.
// @throws {ConfigLoadError} - when extends is supplied with a non-string value or a rule mapping fails field validation.
function inlineSpecFromObject(block: Record<string, unknown>): InlineProfileSpec {
  const spec: InlineProfileSpec = {};
  // A supplied base must name a built-in profile or local profile file.
  if ("extends" in block) {
    // Non-string bases cannot resolve to the profile the user intended.
    if (!isString(block.extends)) {
      throw new ConfigLoadError("`profile.extends` must be a string: a built-in name or a relative profile file path.", SUGGEST_EDIT_CONFIG);
    }
    spec.extends = block.extends;
  }
  const rulesBlock = objectValue(block.rules);
  // Without a rules mapping, the profile adds no rule overrides.
  if (rulesBlock) {
    spec.rules = profileRulesFromBlock(rulesBlock);
  }
  // An ignoredPaths key replaces inherited ignores. A non-list value or a list without strings clears them.
  if ("ignoredPaths" in block) {
    spec.ignoredPaths = arrayValue(block.ignoredPaths).filter(isString);
  }
  return spec;
}

// Returns rule settings from the parsed profile rules mapping. Entries with other shapes contribute no override.
// Shares field validation with direct config and propagates ConfigLoadError for invalid fields. Rule IDs are checked during overlay.
function profileRulesFromBlock(rulesBlock: Record<string, unknown>): Record<string, ProfileRuleSetting> {
  const rules: Record<string, ProfileRuleSetting> = {};
  // A non-mapping entry is skipped so that the other rule entries can still be validated.
  for (const [ruleId, value] of Object.entries(rulesBlock)) {
    const rule = objectValue(value);
    // A rule mapping can still supply valid scalar fields when its options value has the wrong shape.
    if (rule) {
      rules[ruleId] = ruleConfigValue(ruleId, rule);
    }
  }
  return rules;
}

// Selects the explicit `--config` path or the first supported project-root config file.
// An explicit path means what the user typed, relative to the launch directory as scan targets are.
// No match means the user chose or inherited zero-config behavior, not an error.
function selectedConfigPath(projectRoot: string, options: AnalysisOptions): string | undefined {
  return options.config ? absolutize(process.cwd(), options.config) : defaultConfigPath(projectRoot);
}

// Returns nothing. Updates the effective config from the parsed file before applying profiles and CLI overrides.
// Checks the schema and supported keys first, then validates each section. A ConfigLoadError stops loading on a rejected setting.
function applyConfigValues(config: Config, parsedConfig: Record<string, unknown>): void {
  applySchemaVersionConfig(parsedConfig);
  assertKnownKeys(parsedConfig, KNOWN_ROOT_KEYS, "");
  assertKnownKeys(objectValue(parsedConfig.paths), KNOWN_PATHS_KEYS, "paths.");
  assertKnownKeys(objectValue(parsedConfig.allowlists), KNOWN_ALLOWLISTS_KEYS, "allowlists.");
  applyDeepScanBudgetConfig(config, parsedConfig);
  applyDisplayFloorConfig(config, parsedConfig);
  applyFailOnConfig(config, parsedConfig);
  applyPathConfig(config, parsedConfig);
  applyAllowlistConfig(config, parsedConfig);
  applyRuleConfig(config, parsedConfig);
  config.sensitiveExclusions = parseSensitiveExclusions(parsedConfig);
}

/**
 * Validates config key names before analysis because an ignored typo would leave a setting out of force.
 * The error names the first rejected key and gives a stable, sorted list of accepted keys.
 *
 * @param block - config mapping to validate. An omitted block is allowed.
 * @param known - permitted unprefixed key names for the block
 * @param prefix - config path prefix shown before key names in the diagnostic
 * @returns nothing. Validation continues for an omitted block or one whose keys are all recognised.
 * @throws {ConfigLoadError} - the block contains a key outside the known set
 */
function assertKnownKeys(block: Record<string, unknown> | undefined, known: ReadonlySet<string>, prefix: string): void {
  // A missing or non-mapping section supplies no keys here, so the caller can continue its other config checks.
  if (!block) {
    return;
  }
  const unknownKey = Object.keys(block).find((key) => !known.has(key));
  if (unknownKey === undefined) {
    return;
  }
  const rejected = JSON.stringify(prefix + unknownKey);
  const accepted = [...known].sort().map((key) => prefix + key).join(", ");
  throw new ConfigLoadError(`Unknown config key ${rejected}. Valid keys: ${accepted}.`, SUGGEST_EDIT_CONFIG);
}

// Applies the user's configured line and byte limits before analysis so the report can explain any truncated checks.
// Omitted settings inherit the current budget. Null values are invalid.
// @throws {ConfigLoadError} for an invalid budget mapping, unknown key, or invalid enabled flag or limit.
function applyDeepScanBudgetConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const rawBudget = parsedConfig.deepScanBudget;
  // A project with no budget block keeps the current limits.
  if (rawBudget === undefined) {
    return;
  }
  const budget = objectValue(rawBudget);
  // An explicit null does not select a budget. Users who want unlimited analysis can set enabled to false.
  if (!budget) {
    throw new ConfigLoadError('Config key "deepScanBudget" must be a mapping.', SUGGEST_EDIT_CONFIG);
  }
  const allowedKeys = new Set(["enabled", "maxLines", "maxBytes"]);
  const unknownKey = Object.keys(budget).find((key) => !allowedKeys.has(key));
  // A typo such as maxLine could make a user think a limit is in effect when it was ignored.
  if (unknownKey) {
    throw new ConfigLoadError(`Unknown deepScanBudget key: ${JSON.stringify(unknownKey)}. Valid keys: enabled, maxLines, maxBytes.`, SUGGEST_EDIT_CONFIG);
  }
  // A user can change just the line or byte limit and keep the inherited enabled setting.
  const enabled = budget.enabled === undefined ? config.deepScanBudget.enabled : budget.enabled;
  // An explicit null or string gives the user an error with the accepted settings.
  if (typeof enabled !== "boolean") {
    throw new ConfigLoadError('Config key "deepScanBudget.enabled" must be true or false.', SUGGEST_EDIT_CONFIG);
  }
  const maxLines = positiveBudgetLimit(budget.maxLines, "maxLines", config.deepScanBudget.maxLines);
  const maxBytes = positiveBudgetLimit(budget.maxBytes, "maxBytes", config.deepScanBudget.maxBytes);
  config.deepScanBudget = { enabled, maxLines, maxBytes, override: "config" };
}

// Returns the configured scan bound once validated as a safe positive integer, or the caller's fallback when omitted.
// The key identifies the line or byte limit to fix in the config error.
// @throws {ConfigLoadError} - when the limit is set but is not a number, not a safe integer, or not greater than zero.
function positiveBudgetLimit(configuredLimit: unknown, key: "maxLines" | "maxBytes", fallback: number): number {
  if (configuredLimit === undefined) {
    return fallback;
  }
  if (typeof configuredLimit !== "number" || !Number.isSafeInteger(configuredLimit) || configuredLimit <= 0) {
    throw new ConfigLoadError(`Config key "deepScanBudget.${key}" must be a positive integer.`, SUGGEST_EDIT_CONFIG);
  }
  return configuredLimit;
}

// Returns nothing. Applies a CLI budget choice to the effective config. An absent choice leaves the existing budget in effect.
// Enabling sets both limits from the CLI. Disabling turns off the budget and retains the existing limits.
// Either choice records the CLI as the source.
function applyDeepScanBudgetOverride(config: Config, override: DeepScanBudgetOverride | undefined): void {
  if (!override) {
    return;
  }
  config.deepScanBudget = override.enabled
    ? { enabled: true, maxLines: override.maxLines, maxBytes: override.maxBytes, override: "cli" }
    : { ...config.deepScanBudget, enabled: false, override: "cli" };
}

// Returns nothing after checking the parsed configuration's required schema version before any user setting affects the scan.
// Throws with migration guidance for missing or unsupported versions; the supported value already matches the default config.
// @throws {ConfigLoadError} - when schemaVersion is missing or is any value other than "gruff-ts.config.v0.1".
function applySchemaVersionConfig(parsedConfig: Record<string, unknown>): void {
  const schemaVersion = parsedConfig.schemaVersion;
  // A missing version leaves Gruff unable to know which configuration contract the user intended.
  if (schemaVersion === undefined) {
    throw new ConfigLoadError('Config must include `schemaVersion: gruff-ts.config.v0.1` at the top.', SUGGEST_INIT_FORCE);
  }
  // Any other version is unsupported and must not be interpreted as the current schema.
  if (schemaVersion !== "gruff-ts.config.v0.1") {
    throw new ConfigLoadError(`Unsupported schemaVersion: ${JSON.stringify(schemaVersion)}. Supported: "gruff-ts.config.v0.1".`, SUGGEST_INIT_FORCE);
  }
}

/**
 * Sets the report's display floor. Existing per-command gates must move to failOn to keep their build behavior.
 *
 * @param config - effective config whose display floor is updated
 * @param parsedConfig - file settings that may supply a minimumSeverity value
 * @returns - nothing. Updates the effective config in place when a valid floor is supplied.
 * @throws {ConfigLoadError} - when minimumSeverity is a mapping or a supplied value other than advisory, warning, or error
 */
function applyDisplayFloorConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const configuredFloor = parsedConfig.minimumSeverity;
  // An omitted key leaves the current display floor in effect.
  if (configuredFloor === undefined) {
    return;
  }
  if (objectValue(configuredFloor)) {
    throw new ConfigLoadError(LEGACY_MINIMUM_SEVERITY_ERROR, "Rename the `minimumSeverity:` mapping to `failOn:`, and set `minimumSeverity:` to one severity if you also want a display floor.");
  }
  if (configuredFloor !== "advisory" && configuredFloor !== "warning" && configuredFloor !== "error") {
    throw new ConfigLoadError(`Config key "minimumSeverity" must be one of: advisory, warning, error. Got: ${JSON.stringify(configuredFloor)}.`, SUGGEST_EDIT_CONFIG);
  }
  config.displayFloor = configuredFloor;
}

// Loads a project's per-command exit gates so a developer and CI can get the same result without repeating `--fail-on`.
// @throws {ConfigLoadError} for a non-mapping, an unknown command, or an invalid threshold.
function applyFailOnConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  // Omitting failOn keeps the current command thresholds.
  if (parsedConfig.failOn === undefined) {
    return;
  }
  const block = objectValue(parsedConfig.failOn);
  // A bare `failOn: warning` gives no command to gate. Ask the user to name one, such as analyse.
  if (!block) {
    throw new ConfigLoadError('Config key "failOn" must be a mapping of commands to thresholds.', SUGGEST_EDIT_CONFIG);
  }
  // Apply each gate so a project can fail analyse at warning while allowing summary to exit successfully.
  for (const [commandName, value] of Object.entries(block)) {
    config.minimumSeverity.set(assertGatedCommand(commandName), parseFailThresholdConfig(value));
  }
}

// Returns the unchanged failOn command name after checking that it supports a configured exit threshold.
// Throws for dashboard and unknown names because they cannot provide the gate the configuration implies.
// @throws {ConfigLoadError} - when commandName is dashboard or any name other than analyse, summary, or report.
function assertGatedCommand(commandName: string): MinimumSeverityCommand {
  // Dashboard has no --fail-on behavior, so accepting it would promise users a gate that cannot run.
  if (commandName === "dashboard") {
    throw new ConfigLoadError('Unknown command in failOn: "dashboard". The dashboard subcommand does not currently expose a --fail-on flag; configuring its threshold is not supported.', "Remove the `dashboard:` line from `failOn:` in `.gruff-ts.yaml`, or open an issue if dashboard should gate.");
  }
  // These are the only commands whose user-facing exit status supports a configured minimum severity.
  if (commandName === "analyse" || commandName === "summary" || commandName === "report") {
    return commandName;
  }
  throw new ConfigLoadError(`Unknown command in failOn: ${JSON.stringify(commandName)}. Valid keys: analyse, summary, report.`, SUGGEST_EDIT_CONFIG);
}

// Returns the configured exit threshold after checking it against the CLI's accepted values.
// Unsupported values fail with the accepted choices instead of silently changing the user's CI gate.
// @throws {ConfigLoadError} - when the configured threshold is not none, advisory, warning, or error.
function parseFailThresholdConfig(configuredThreshold: unknown): FailThreshold {
  // CLI resolution receives none as an explicit gate choice, distinct from an omitted threshold.
  if (configuredThreshold === "none" || configuredThreshold === "advisory" || configuredThreshold === "warning" || configuredThreshold === "error") {
    return configuredThreshold;
  }
  throw new ConfigLoadError(`FailThreshold must be one of: advisory, warning, error, none. Got: ${JSON.stringify(configuredThreshold)}.`, SUGGEST_EDIT_CONFIG);
}

// Returns the configured threshold for one command during CLI option resolution.
// Missing values mean the user did not override that command, so callers continue to the binary default.
function minimumSeverityFor(config: Config, command: MinimumSeverityCommand): FailThreshold | undefined {
  return config.minimumSeverity.get(command);
}

// Returns nothing. Replaces the effective config's path exclusions with strings from the parsed paths.ignore list.
// A missing list, a non-list value, or a list with no strings clears these config-based exclusions.
function applyPathConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const paths = objectValue(parsedConfig.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);
}

// Returns nothing. Updates the effective config from the parsed allowlists, lowercasing supplied naming values for matching.
// A present naming or tracking key replaces its setting. A non-list value or a list with no strings clears it. Omitted keys keep their settings.
// @throws {ConfigLoadError} - when allowlists.secretPreviews is present or a tracking token string is an invalid regular expression.
function applyAllowlistConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const allowlists = objectValue(parsedConfig.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  // A supplied abbreviation list replaces the defaults, including when the user intentionally supplies an empty list.
  if (allowlists && "acceptedAbbreviations" in allowlists) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  // Even an empty legacy list stops loading because category redaction markers are unconditional.
  if (allowlists && "secretPreviews" in allowlists) {
    throw new ConfigLoadError(LEGACY_SECRET_PREVIEWS_ERROR, "Delete the `allowlists.secretPreviews:` entry from `.gruff-ts.yaml`; nothing replaces it.");
  }
  applyNamingAllowlist(config, allowlists, "acceptedClassFilePairs");
  applyNamingAllowlist(config, allowlists, "placeholderNames");
  // Tracking tokens are project vocabulary, so none ship by default. Each supplied string becomes a case-insensitive pattern.
  if (allowlists && "trackingTokens" in allowlists) {
    config.trackingTokens = arrayValue(allowlists.trackingTokens).filter(isString).map((pattern) => trackingTokenPattern(pattern));
  }
}

// Returns a case-insensitive regular expression for a pattern from allowlists.trackingTokens.
// @throws {ConfigLoadError} - Invalid syntax stops config loading and identifies the entry to fix or remove.
function trackingTokenPattern(pattern: string): RegExp {
  try {
    return new RegExp(pattern, "i");
  } catch {
    throw new ConfigLoadError(`Config key "allowlists.trackingTokens" holds an invalid regular expression: ${JSON.stringify(pattern)}.`, "Fix or remove that entry in `.gruff-ts.yaml`.");
  }
}

// Returns nothing. Replaces the effective config's naming set for the selected key with lowercase strings from the parsed allowlists.
// A supplied value with no usable strings clears the selected set.
function applyNamingAllowlist(config: Config, allowlists: Record<string, unknown> | undefined, key: "acceptedClassFilePairs" | "placeholderNames"): void {
  // If the section or selected key is missing, the current set stays in effect.
  if (!allowlists || !(key in allowlists)) {
    return;
  }
  config[key] = new Set(arrayValue(allowlists[key]).filter(isString).map((value) => value.toLowerCase()));
}

// Returns nothing. Applies per-rule overrides from the parsed rules mapping to the effective config.
// Unset fields in a supplied rule use their defaults.
// @throws {ConfigLoadError} - when a rule mapping names an unknown rule, has an unknown key, or fails field validation.
function applyRuleConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const rules = objectValue(parsedConfig.rules);
  // Without a rules mapping, the effective config adds no file overrides from this section.
  if (!rules) {
    return;
  }
  for (const [ruleId, value] of Object.entries(rules)) {
    const rule = objectValue(value);
    // A non-mapping entry has no supported rule fields and therefore contributes no override.
    if (!rule) {
      continue;
    }
    // A misspelled id would otherwise sit in the map as a silent no-op the user believes is policy.
    if (!isKnownRuleId(ruleId)) {
      throw new ConfigLoadError(
        `Unknown rule id: ${JSON.stringify(ruleId)}.`,
        "Use a rule id from `gruff-ts list-rules`; `rules:` keys must match the catalogue exactly.",
      );
    }
    config.rules.set(ruleId, ruleConfigValue(ruleId, rule));
  }
}

// Every key a rule block may carry; a sibling port's `thresholds:` map is not one of them.
const RULE_BLOCK_KEYS: ReadonlySet<string> = new Set(["enabled", "options", "severity", "threshold"]);

// Option keys that switch a rule on or off for a wider scope, such as the tag rules' `everyCallable`; every other option is numeric.
const BOOLEAN_RULE_OPTION_KEYS: ReadonlySet<string> = new Set(["everyCallable"]);

// Returns an override from the supplied rule block. Direct config and profiles share this field-validation path.
// The rule ID selects accepted options and identifies the rule in errors. Without an options mapping, callers use option defaults.
// Throws ConfigLoadError for unknown block keys or values that fail field or option-entry checks.
function ruleConfigValue(ruleId: string, rule: Record<string, unknown>): RuleOverride {
  // A key alongside threshold that gruff-ts does not read, such as a sibling port's spelling, is refused, not ignored.
  assertKnownKeys(rule, RULE_BLOCK_KEYS, `rules.${ruleId}.`);
  assertRuleThresholdConfig(rule);
  assertRuleEnabledConfig(rule);
  const ruleOverride: RuleOverride = { options: validatedRuleOptions(ruleId, rule.options) };
  applyRuleEnabledConfig(ruleOverride, rule);
  applyRuleThresholdConfig(ruleOverride, rule);
  applyRuleSeverityConfig(ruleOverride, rule);
  return ruleOverride;
}

// Returns nothing after validating the rule block's explicit enabled setting before it can change the user's scan.
// Missing means inherit. It throws on YAML words such as no because only true and false can reliably control the rule.
// @throws {ConfigLoadError} - when the rule block sets enabled to a non-boolean value.
function assertRuleEnabledConfig(rule: Record<string, unknown>): void {
  // A supplied non-boolean would otherwise look like a successful enable or disable choice while doing nothing.
  if ("enabled" in rule && typeof rule.enabled !== "boolean") {
    throw new ConfigLoadError(
      `Rule config key "enabled" must be true or false; got ${JSON.stringify(rule.enabled)}.`,
      "YAML 1.2 treats `no`/`off`/`yes`/`on` as strings - write `enabled: true` or `enabled: false`.",
    );
  }
}

// Returns nothing after checking the rule block's optional threshold and severity overrides independently before analysis.
// Omitted fields keep their inherited settings. Invalid overrides identify the exact field to correct.
// @throws {ConfigLoadError} - when threshold is nonnumeric or severity is outside advisory, warning, and error.
function assertRuleThresholdConfig(rule: Record<string, unknown>): void {
  // A supplied threshold must be numeric to define a meaningful rule boundary for the user.
  if ("threshold" in rule && typeof rule.threshold !== "number") {
    throw new ConfigLoadError('Rule config key "threshold" must be numeric.', SUGGEST_EDIT_CONFIG);
  }
  // A supplied severity must use the report severity names that --fail-on compares against.
  if ("severity" in rule && !isSeverity(rule.severity)) {
    throw new ConfigLoadError('Rule config key "severity" must be "advisory", "warning", or "error".', SUGGEST_EDIT_CONFIG);
  }
}

// Returns nothing. Copies an explicit enabled choice from the configured rule entry into the supplied rule override.
// Missing values preserve the profile or descriptor behavior the user already selected.
function applyRuleEnabledConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // Only an explicit boolean represents a user choice to enable or disable the rule.
  if (typeof rule.enabled === "boolean") {
    ruleOverride.enabled = rule.enabled;
  }
}

// Returns nothing. Copies a numeric threshold from the configured rule entry into the supplied rule override.
function applyRuleThresholdConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // A missing or nonnumeric setting leaves the override untouched, preserving the inherited threshold when no override exists.
  if (typeof rule.threshold === "number") {
    ruleOverride.threshold = rule.threshold;
  }
}

// Returns nothing. Copies a supported severity from the configured rule entry into the supplied rule override.
// Missing or unsupported values leave the inherited severity untouched.
function applyRuleSeverityConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // Only a supported severity can change how the finding appears and affects exit thresholds.
  if (isSeverity(rule.severity)) {
    ruleOverride.severity = rule.severity;
  }
}

// Returns validated options from optionsValue for ruleId, using that rule's public option catalogue.
// Undefined, null, arrays and non-object values return an empty map, leaving the rule's option defaults in use.
// @throws {ConfigLoadError} - when an option name is not one the rule accepts, or its value has the wrong type.
function validatedRuleOptions(ruleId: string, optionsValue: unknown): Map<string, number | boolean> {
  const options = new Map<string, number | boolean>();
  const configuredOptions = objectValue(optionsValue);
  // No options mapping means this rule uses its documented option defaults.
  if (!configuredOptions) {
    return options;
  }
  const acceptedKeys = ruleOptionKeys(ruleId);
  // Every supplied option must be both supported by the rule and of its type before analysis uses it.
  for (const [name, option] of Object.entries(configuredOptions)) {
    // Reject unknown keys first so a typo is reported as the typo, not as a type error.
    if (!acceptedKeys.includes(name)) {
      const accepted = acceptedKeys.length > 0 ? `accepts options: ${acceptedKeys.join(", ")}` : "accepts no options";
      throw new ConfigLoadError(`Unknown option ${JSON.stringify(name)} for rule ${ruleId}; the rule ${accepted}.`, SUGGEST_EDIT_CONFIG);
    }
    options.set(name, ruleOptionValue(ruleId, name, option));
  }
  return options;
}

// Returns option unchanged after name selects boolean or numeric validation; ruleId identifies the rule in errors.
// @throws {ConfigLoadError} - when a switch is not a boolean, or a numeric option is not a number.
function ruleOptionValue(ruleId: string, name: string, option: unknown): number | boolean {
  const isSwitch = BOOLEAN_RULE_OPTION_KEYS.has(name);
  // A switch takes only true or false, so a YAML word such as yes cannot look like a choice that does nothing.
  if (isSwitch && typeof option === "boolean") {
    return option;
  }
  // A numeric option takes only a number, because nothing else can define the boundary the user intended.
  if (!isSwitch && typeof option === "number") {
    return option;
  }
  const expected = isSwitch ? "true or false" : "numeric";
  throw new ConfigLoadError(`Rule config option ${JSON.stringify(name)} for ${ruleId} must be ${expected}; got ${JSON.stringify(option)}.`, SUGGEST_EDIT_CONFIG);
}

// Returns the first existing candidate path under the project root for zero-argument config discovery.
// Returns undefined when no candidate exists, so loading starts from the built-in defaults.
function defaultConfigPath(projectRoot: string): string | undefined {
  // Config names are checked in documented priority order so users get a deterministic selection.
  for (const fileName of DEFAULT_CONFIG_FILES) {
    const candidate = join(projectRoot, fileName);
    // Discovery selects one path. The loader handles reading and validation.
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// Returns whether one rule should run for the user's scan.
// If the effective config has no enabled override for the rule, it runs unless its descriptor disables it by default.
function ruleEnabled(config: Config, ruleId: string): boolean {
  return config.rules.get(ruleId)?.enabled ?? ruleDefaultEnabled(ruleId);
}

// Returns the configured threshold for one rule or the caller's documented default.
// Rules use this during analysis so omitted user settings behave consistently.
function threshold(config: Config, ruleId: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.threshold ?? defaultValue;
}

// Returns the configured severity for one rule or the descriptor default shown to users.
// Rules use this when building findings so report severity and exit behavior stay aligned.
function ruleSeverity(config: Config, ruleId: string, defaultSeverity: Severity): Severity {
  return config.rules.get(ruleId)?.severity ?? defaultSeverity;
}

// Looks up the named numeric option for the selected rule in the effective config.
// Returns its numeric value, or the caller's default when the option is missing or has another type.
function optionNumber(config: Config, ruleId: string, name: string, defaultValue: number): number {
  const option = config.rules.get(ruleId)?.options.get(name);
  return typeof option === "number" ? option : defaultValue;
}

// Looks up a named switch for the selected rule in the effective config, such as everyCallable for a tag rule.
// Returns its boolean value, or the caller's default when the option is missing or has another type.
function optionBoolean(config: Config, ruleId: string, name: string, isOnByDefault: boolean): boolean {
  const option = config.rules.get(ruleId)?.options.get(name);
  return typeof option === "boolean" ? option : isOnByDefault;
}

// Checks whether a parsed config value belongs to the public severity vocabulary.
// Load-time validation and rule application share this guard so users see one consistent set of accepted values.
function isSeverity(configValue: unknown): configValue is Severity {
  return configValue === "advisory" || configValue === "warning" || configValue === "error";
}

export { defaultConfigPath, loadConfig, minimumSeverityFor, optionBoolean, optionNumber, resolveProfile, ruleEnabled, ruleSeverity, threshold };
