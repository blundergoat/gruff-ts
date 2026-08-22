// Configuration loading turns CLI and config-file choices into validated analyzer settings.
//
// Users get predictable defaults or an actionable startup error; syntax parsing and value narrowing live in `config-parse.ts`.
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { arrayValue, isString, objectValue, parseConfigFile, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE } from "./config-parse.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { BUILT_IN_PROFILES, builtInProfileNames, DEFAULT_PROFILE_NAME, isKnownRuleId, ruleOptionKeys } from "./profiles.ts";
import { parseSensitiveExclusions } from "./sensitive-exclusions.ts";
import type { AnalysisOptions, Config, DeepScanBudgetOverride, FailThreshold, InlineProfileSpec, MinimumSeverityCommand, ProfileDefinition, ProfileRuleSetting, ProfileSpec, Severity } from "./types.ts";

// Represents one validated per-rule override before it joins the user's effective configuration.
//
// Optional fields preserve the difference between an omitted setting and an explicit value.
type RuleOverride = Config["rules"] extends Map<string, infer RuleOverrideValue> ? RuleOverrideValue : never;

const DEFAULT_CONFIG_FILES = [".gruff-ts.yaml", ".gruff.json", ".gruff.yaml", ".gruff.yml"] as const;
const LEGACY_SECRET_PREVIEWS_ERROR = 'Config key "allowlists.secretPreviews" only accepts an empty list; remove all configured entries because secret previews no longer suppress findings.';
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
    bannedGenericNames: new Set(["process", "handle", "doit", "run", "execute", "manage"]),
    acceptedBooleanNames: new Set(["all", "apply", "check", "dev", "enabled", "force", "fresh", "harness", "json", "ok", "verbose", "yes"]),
    acceptedClassFilePairs: new Set(),
    acceptedCasingPairs: new Set(),
    booleanPrefixes: new Set(["is", "has", "can", "should", "does", "did", "was", "will", "may", "in", "scan", "supports", "requires", "allow", "check", "enable", "exclude", "include", "omit", "skip", "with", "without"]),
    hungarianPrefixes: new Set(["str", "obj", "arr", "bool", "int", "num"]),
    placeholderNames: new Set(["foo", "bar", "baz", "tmp", "temp", "thing", "stuff", "data", "value", "item"]),
    negativeBooleanAllowed: new Set(["nostore", "nofollow", "noreferrer", "noscript", "noindex"]),
    knownAcronyms: new Set(["url", "http", "https", "id", "xml", "json", "html", "css", "api", "sql", "db", "io", "ui", "uuid", "ip", "tcp", "udp", "ast", "cli", "npm"]),
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

// Resolves a user-supplied config or profile path from the project root.
// Absolute paths remain unchanged so CLI and config-file references behave consistently.
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Builds the effective configuration before analysis by combining defaults, an optional file, and the selected profile.
// Missing default files mean zero-config use; malformed or unsupported values become actionable CLI errors.
function loadConfig(projectRoot: string, options: AnalysisOptions): Config {
  const config = defaultConfig();
  const path = options.shouldSkipConfig ? undefined : selectedConfigPath(projectRoot, options);
  const parsedConfig: Record<string, unknown> = path ? parseConfigFile(path) : {};
  // A selected path means the user supplied or owns a config file whose values must be applied.
  if (path) {
    applyConfigValues(config, parsedConfig);
  }
  applyProfile(config, options, parsedConfig, projectRoot);
  applyDeepScanBudgetOverride(config, options.deepScanBudget);
  return config;
}

// Applies the profile beneath explicit config values, with the CLI profile taking precedence over the file profile.
// No selected profile keeps the user's zero-config result unchanged; `--no-config --profile …` still applies the CLI choice.
function applyProfile(config: Config, options: AnalysisOptions, parsedConfig: Record<string, unknown>, projectRoot: string): void {
  const configuredProfile = options.profile !== undefined ? options.profile : parsedConfig.profile;
  // No CLI or file profile means the user's explicit settings and built-in defaults are already complete.
  if (configuredProfile === undefined) {
    return;
  }
  applyProfileUnderlay(config, resolveProfile(parseProfileSpec(configuredProfile), projectRoot));
}

// Adds a resolved profile only where the user has not already configured a rule.
// Profile ignore paths join explicit ignores so either user choice keeps a path out of the scan.
function applyProfileUnderlay(config: Config, definition: ProfileDefinition): void {
  // Each profile rule is considered independently so explicit user overrides always win.
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

// Resolves a built-in, file, or inline profile into one child-wins definition used before analysis.
// The visit chain reports inheritance cycles as config errors; profile references stay local and never fetch or execute anything.
function resolveProfile(spec: ProfileSpec, projectRoot: string, chain: string[] = []): ProfileDefinition {
  // A string is the user-facing built-in name or local file reference; an object is already an inline profile.
  if (typeof spec === "string") {
    return resolveProfileRef(spec, projectRoot, chain);
  }
  return resolveInlineProfile(spec, projectRoot, chain);
}

// Resolves a user's profile name to a bundled preset or treats it as a local file path.
// Built-in short names win over same-named files; users can prefix a file with `./` to select it explicitly.
function resolveProfileRef(ref: string, projectRoot: string, chain: string[]): ProfileDefinition {
  const builtIn = BUILT_IN_PROFILES.get(ref) ?? BUILT_IN_PROFILES.get(`gruff.${ref}`);
  // A bundled match gives users an isolated copy that later overlays cannot mutate globally.
  if (builtIn) {
    return cloneProfileDefinition(builtIn);
  }
  return resolveProfileFile(ref, projectRoot, chain);
}

// Loads a local profile file and resolves its inheritance before analysis starts.
// Throws an actionable config error for a missing file or inheritance cycle instead of starting a partial scan.
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

// Resolves an inline profile's base and then applies the user's child overrides.
// Missing `extends` selects the recommended profile, preserving the documented default.
function resolveInlineProfile(spec: InlineProfileSpec, projectRoot: string, chain: string[]): ProfileDefinition {
  const base = resolveProfileRef(spec.extends ?? DEFAULT_PROFILE_NAME, projectRoot, chain);
  return overlayProfile(base, spec);
}

// Overlays one inline profile on its resolved base, with the user's child values winning field by field.
// A supplied ignore list replaces the base list; omission inherits it.
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
function mergeRuleSetting(parent: ProfileRuleSetting | undefined, child: ProfileRuleSetting): ProfileRuleSetting {
  return { ...parent, ...child };
}

// Copies a resolved profile before user overlays mutate its rules or ignore paths.
// Use this for bundled profiles whose shared definitions must remain stable across commands.
function cloneProfileDefinition(definition: ProfileDefinition): ProfileDefinition {
  return { name: definition.name, rules: new Map(definition.rules), ignoredPaths: [...definition.ignoredPaths] };
}

// Stops a repeated profile path before recursive loading can loop.
// Throws with the visit order so users can find and break the `extends` cycle.
function assertNoProfileCycle(key: string, chain: string[]): void {
  // A repeated path means the user's profile chain has returned to a file already being resolved.
  if (chain.includes(key)) {
    throw new ConfigLoadError(
      `Profile inheritance cycle detected: ${[...chain, key].join(" -> ")}.`,
      "Break the `extends:` cycle so each profile in the chain is reached only once.",
    );
  }
}

// Validates one profile rule name before it can affect analysis.
// Throws for unknown names so users do not mistake a typo for applied policy.
function assertKnownProfileRule(ruleId: string): void {
  // A name outside the rule catalogue cannot produce the behavior the user requested.
  if (!isKnownRuleId(ruleId)) {
    throw new ConfigLoadError(
      `Unknown rule id in profile: ${JSON.stringify(ruleId)}.`,
      "Use a rule id from `gruff-ts list-rules`; profile `rules:` keys must match the catalogue exactly.",
    );
  }
}

// Converts the user's parsed `profile` value into a named/file reference or inline profile.
// Throws during loading for unsupported shapes so analysis never starts with a partially understood profile.
function parseProfileSpec(configuredProfile: unknown): ProfileSpec {
  // A string preserves the exact built-in name or local path the user selected.
  if (typeof configuredProfile === "string") {
    return configuredProfile;
  }
  const block = objectValue(configuredProfile);
  // A non-string value must be an object before its profile fields can be interpreted.
  if (!block) {
    throw new ConfigLoadError(
      "`profile:` must be a built-in name, a profile file path, or a mapping with `extends:` and overrides.",
      SUGGEST_EDIT_CONFIG,
    );
  }
  return inlineSpecFromObject(block);
}

// Reads the supported fields from an inline or file-backed profile after parsing.
// Throws for invalid field shapes; unrelated top-level metadata remains inert.
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
  // A valid rules mapping contributes per-rule profile settings; omission means no rule delta.
  if (rulesBlock) {
    spec.rules = profileRulesFromBlock(rulesBlock);
  }
  // A supplied ignore list replaces the inherited list, including when the user intentionally provides an empty list.
  if ("ignoredPaths" in block) {
    spec.ignoredPaths = arrayValue(block.ignoredPaths).filter(isString);
  }
  return spec;
}

// Builds validated rule settings for an inline profile before it joins the effective configuration.
// Reusing top-level validation gives users the same errors in profile and direct config forms.
function profileRulesFromBlock(rulesBlock: Record<string, unknown>): Record<string, ProfileRuleSetting> {
  const rules: Record<string, ProfileRuleSetting> = {};
  // Each user-supplied rule is narrowed independently so one malformed entry cannot become a partial override.
  for (const [ruleId, value] of Object.entries(rulesBlock)) {
    const rule = objectValue(value);
    // Only mapping-shaped settings can describe the rule controls users see in configuration.
    if (rule) {
      rules[ruleId] = ruleConfigValue(ruleId, rule);
    }
  }
  return rules;
}

// Selects the explicit `--config` path or the first supported project-root config file.
// No match means the user chose or inherited zero-config behavior, not an error.
function selectedConfigPath(projectRoot: string, options: AnalysisOptions): string | undefined {
  return options.config ? absolutize(projectRoot, options.config) : defaultConfigPath(projectRoot);
}

// Applies each top-level config section in its stable loading order before analysis.
// Schema validation runs first, then user thresholds, paths, allowlists, rule overrides, and reviewed sensitive exclusions become available to downstream commands.
function applyConfigValues(config: Config, parsedConfig: Record<string, unknown>): void {
  applySchemaVersionConfig(parsedConfig);
  applyDeepScanBudgetConfig(config, parsedConfig);
  applyMinimumSeverityConfig(config, parsedConfig);
  applyPathConfig(config, parsedConfig);
  applyAllowlistConfig(config, parsedConfig);
  applyRuleConfig(config, parsedConfig);
  config.sensitiveExclusions = parseSensitiveExclusions(parsedConfig);
}

// Loads the optional paired line/byte budget. Either bound can trigger degradation, so both limits
// remain present even when a user changes only one of them.
// Throws ConfigLoadError when the mapping, keys, enabled flag, or numeric limits are invalid.
function applyDeepScanBudgetConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const rawBudget = parsedConfig.deepScanBudget;
  if (rawBudget === undefined) {
    return;
  }
  const budget = objectValue(rawBudget);
  if (!budget) {
    throw new ConfigLoadError('Config key "deepScanBudget" must be a mapping.', SUGGEST_EDIT_CONFIG);
  }
  const allowedKeys = new Set(["enabled", "maxLines", "maxBytes"]);
  const unknownKey = Object.keys(budget).find((key) => !allowedKeys.has(key));
  if (unknownKey) {
    throw new ConfigLoadError(`Unknown deepScanBudget key: ${JSON.stringify(unknownKey)}. Valid keys: enabled, maxLines, maxBytes.`, SUGGEST_EDIT_CONFIG);
  }
  const enabled = budget.enabled ?? config.deepScanBudget.enabled;
  if (typeof enabled !== "boolean") {
    throw new ConfigLoadError('Config key "deepScanBudget.enabled" must be true or false.', SUGGEST_EDIT_CONFIG);
  }
  const maxLines = positiveBudgetLimit(budget.maxLines, "maxLines", config.deepScanBudget.maxLines);
  const maxBytes = positiveBudgetLimit(budget.maxBytes, "maxBytes", config.deepScanBudget.maxBytes);
  config.deepScanBudget = { enabled, maxLines, maxBytes, override: "config" };
}

// Rejects zero, fractions, and unsafe values because a scan bound must be an exact positive count.
// Throws ConfigLoadError when a configured limit is not a safe positive integer.
function positiveBudgetLimit(configuredLimit: unknown, key: "maxLines" | "maxBytes", fallback: number): number {
  if (configuredLimit === undefined) {
    return fallback;
  }
  if (typeof configuredLimit !== "number" || !Number.isSafeInteger(configuredLimit) || configuredLimit <= 0) {
    throw new ConfigLoadError(`Config key "deepScanBudget.${key}" must be a positive integer.`, SUGGEST_EDIT_CONFIG);
  }
  return configuredLimit;
}

// The CLI override is atomic and therefore wins over every value loaded from the config file.
function applyDeepScanBudgetOverride(config: Config, override: DeepScanBudgetOverride | undefined): void {
  if (!override) {
    return;
  }
  config.deepScanBudget = override.enabled
    ? { enabled: true, maxLines: override.maxLines, maxBytes: override.maxBytes, override: "cli" }
    : { ...config.deepScanBudget, enabled: false, override: "cli" };
}

// Validates the required config schema before any user setting affects the scan.
// Throws with migration guidance for missing or unsupported versions; the supported value already matches the default config.
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

// Loads per-command failure thresholds so users can set consistent CI behavior in configuration.
// An omitted block preserves CLI or binary defaults; invalid command names and values fail before analysis.
function applyMinimumSeverityConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const block = objectValue(parsedConfig.minimumSeverity);
  // No mapping means the user did not set command-specific failure thresholds.
  if (!block) {
    return;
  }
  // Each configured command receives its validated threshold for later CLI precedence handling.
  for (const [commandName, value] of Object.entries(block)) {
    config.minimumSeverity.set(assertMinimumSeverityCommand(commandName), parseFailThresholdConfig(value));
  }
}

// Validates one `minimumSeverity` command name before it can define the user's exit behavior.
// Throws for dashboard and unknown names because they cannot provide the gate the configuration implies.
function assertMinimumSeverityCommand(commandName: string): MinimumSeverityCommand {
  // Dashboard has no `--fail-on` behavior, so accepting it would promise users a gate that cannot run.
  if (commandName === "dashboard") {
    throw new ConfigLoadError('Unknown command in minimumSeverity: "dashboard". The dashboard subcommand does not currently expose a --fail-on flag; configuring its threshold is not supported.', "Remove the `dashboard:` line from `minimumSeverity:` in `.gruff-ts.yaml`, or open an issue if dashboard should gate.");
  }
  // These are the only commands whose user-facing exit status supports a configured minimum severity.
  if (commandName === "analyse" || commandName === "summary" || commandName === "report") {
    return commandName;
  }
  throw new ConfigLoadError(`Unknown command in minimumSeverity: ${JSON.stringify(commandName)}. Valid keys: analyse, summary, report.`, SUGGEST_EDIT_CONFIG);
}

// Converts one configured failure threshold into the family vocabulary used by CLI exits.
// Unsupported values fail with the accepted choices instead of silently changing the user's CI gate.
function parseFailThresholdConfig(configuredThreshold: unknown): FailThreshold {
  // Only the four documented values can define when a user's command exits unsuccessfully.
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

// Loads the paths users want excluded from analysis.
// Missing, empty, or non-string entries produce an empty list, leaving no config-based path exclusions.
function applyPathConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const paths = objectValue(parsedConfig.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);
}

// Loads naming exceptions and the inert legacy secret-preview key before rules run.
// Naming values become lowercase for stable matching; non-empty secret previews fail because they can no longer hide findings.
function applyAllowlistConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const allowlists = objectValue(parsedConfig.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  // A supplied abbreviation list replaces the defaults, including when the user intentionally supplies an empty list.
  if (allowlists && "acceptedAbbreviations" in allowlists) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  // Users may retain the generated empty key, but any legacy value must fail before it can hide a finding.
  if (allowlists && "secretPreviews" in allowlists) {
    assertLegacySecretPreviewsAreEmpty(allowlists.secretPreviews);
  }
  applyNamingAllowlist(config, allowlists, "bannedGenericNames");
  applyNamingAllowlist(config, allowlists, "acceptedBooleanNames");
  applyNamingAllowlist(config, allowlists, "acceptedClassFilePairs");
  applyNamingAllowlist(config, allowlists, "acceptedCasingPairs");
  applyNamingAllowlist(config, allowlists, "booleanPrefixes");
  applyNamingAllowlist(config, allowlists, "hungarianPrefixes");
  applyNamingAllowlist(config, allowlists, "placeholderNames");
  applyNamingAllowlist(config, allowlists, "negativeBooleanAllowed");
  applyNamingAllowlist(config, allowlists, "knownAcronyms");
}

// Validates the obsolete secret-preview key while generated configs still include it.
// Missing is handled by the caller and exact `[]` is inert; every supplied alternative throws the same value-independent config error.
function assertLegacySecretPreviewsAreEmpty(configuredSecretPreviews: unknown): void {
  // An exact empty array means the retired setting cannot change the user's findings.
  if (Array.isArray(configuredSecretPreviews) && configuredSecretPreviews.length === 0) {
    return;
  }
  throw new ConfigLoadError(
    LEGACY_SECRET_PREVIEWS_ERROR,
    "Keep `allowlists.secretPreviews: []` until a future release removes the obsolete key.",
  );
}

// Applies one naming allowlist as a complete replacement for its built-in values.
// Missing keys preserve defaults; an explicit empty list lets users remove every built-in entry.
function applyNamingAllowlist(config: Config, allowlists: Record<string, unknown> | undefined, key: "bannedGenericNames" | "acceptedBooleanNames" | "acceptedClassFilePairs" | "acceptedCasingPairs" | "booleanPrefixes" | "hungarianPrefixes" | "placeholderNames" | "negativeBooleanAllowed" | "knownAcronyms"): void {
  // A missing allowlist section or key means the user wants the current defaults unchanged.
  if (!allowlists || !(key in allowlists)) {
    return;
  }
  config[key] = new Set(arrayValue(allowlists[key]).filter(isString).map((value) => value.toLowerCase()));
}

// Loads the user's per-rule enabled, threshold, severity, and numeric option overrides.
// Missing fields retain defaults. It throws on unknown rules or malformed settings before the scan can misrepresent the user's policy.
function applyRuleConfig(config: Config, parsedConfig: Record<string, unknown>): void {
  const rules = objectValue(parsedConfig.rules);
  // No rules mapping means the user accepts the effective profile and descriptor defaults.
  if (!rules) {
    return;
  }
  // Each configured rule is validated independently before joining the settings used by analysis.
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

// Builds one effective rule override after validating every user-supplied field.
// Use this shared path for direct config and profile rules so both surfaces return the same errors.
function ruleConfigValue(ruleId: string, rule: Record<string, unknown>): RuleOverride {
  assertRuleThresholdConfig(rule);
  assertRuleEnabledConfig(rule);
  const ruleOverride: RuleOverride = { options: validatedRuleOptions(ruleId, rule.options) };
  applyRuleEnabledConfig(ruleOverride, rule);
  applyRuleThresholdConfig(ruleOverride, rule);
  applyRuleSeverityConfig(ruleOverride, rule);
  return ruleOverride;
}

// Validates an explicit rule-enabled value before it can change the user's scan.
// Missing means inherit. It throws on YAML words such as `no` because only true and false can reliably control the rule.
function assertRuleEnabledConfig(rule: Record<string, unknown>): void {
  // A supplied non-boolean would otherwise look like a successful enable or disable choice while doing nothing.
  if ("enabled" in rule && typeof rule.enabled !== "boolean") {
    throw new ConfigLoadError(
      `Rule config key "enabled" must be true or false; got ${JSON.stringify(rule.enabled)}.`,
      "YAML 1.2 treats `no`/`off`/`yes`/`on` as strings - write `enabled: true` or `enabled: false`.",
    );
  }
}

// Validates optional threshold and severity fields independently before analysis.
// Missing fields inherit rule defaults. It throws on malformed supplied values with the exact setting users must correct.
function assertRuleThresholdConfig(rule: Record<string, unknown>): void {
  // A supplied threshold must be numeric to define a meaningful rule boundary for the user.
  if ("threshold" in rule && typeof rule.threshold !== "number") {
    throw new ConfigLoadError('Rule config key "threshold" must be numeric.', SUGGEST_EDIT_CONFIG);
  }
  // A supplied severity must use the report and `--fail-on` vocabulary users see elsewhere.
  if ("severity" in rule && !isSeverity(rule.severity)) {
    throw new ConfigLoadError('Rule config key "severity" must be "advisory", "warning", or "error".', SUGGEST_EDIT_CONFIG);
  }
}

// Applies a validated enabled choice to the rule settings used by analysis.
// Missing values preserve the profile or descriptor behavior the user already selected.
function applyRuleEnabledConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // Only an explicit boolean represents a user choice to enable or disable the rule.
  if (typeof rule.enabled === "boolean") {
    ruleOverride.enabled = rule.enabled;
  }
}

// Applies a validated numeric threshold to the user's effective rule settings.
// Missing values preserve the profile or descriptor threshold.
function applyRuleThresholdConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // Only a numeric value can replace the threshold analysis will use.
  if (typeof rule.threshold === "number") {
    ruleOverride.threshold = rule.threshold;
  }
}

// Applies a validated severity to the user's effective rule settings.
// Missing or unsupported values leave the inherited severity untouched.
function applyRuleSeverityConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  // Only a supported severity can change how the finding appears and affects exit thresholds.
  if (isSeverity(rule.severity)) {
    ruleOverride.severity = rule.severity;
  }
}

// Builds the numeric options for one rule after checking its public option catalogue.
// Missing options become an empty map. It throws on unknown names or non-numeric values so users never rely on an ignored tuning.
function validatedRuleOptions(ruleId: string, optionsValue: unknown): Map<string, number> {
  const options = new Map<string, number>();
  const configuredOptions = objectValue(optionsValue);
  // No options mapping means this rule uses its documented option defaults.
  if (!configuredOptions) {
    return options;
  }
  const acceptedKeys = ruleOptionKeys(ruleId);
  // Every supplied option must be both supported by the rule and numeric before analysis uses it.
  for (const [name, option] of Object.entries(configuredOptions)) {
    // Reject unknown keys first so a typo is reported as the typo, not as a type error.
    if (!acceptedKeys.includes(name)) {
      const accepted = acceptedKeys.length > 0 ? `accepts options: ${acceptedKeys.join(", ")}` : "accepts no options";
      throw new ConfigLoadError(`Unknown option ${JSON.stringify(name)} for rule ${ruleId}; the rule ${accepted}.`, SUGGEST_EDIT_CONFIG);
    }
    // A supported option with a non-numeric value cannot define the boundary the user intended.
    if (typeof option !== "number") {
      throw new ConfigLoadError(`Rule config option ${JSON.stringify(name)} for ${ruleId} must be numeric; got ${JSON.stringify(option)}.`, SUGGEST_EDIT_CONFIG);
    }
    options.set(name, option);
  }
  return options;
}

// Finds the first supported project-root configuration file for zero-argument discovery.
// No file means the user receives built-in defaults rather than a missing-config error.
function defaultConfigPath(projectRoot: string): string | undefined {
  // Config names are checked in documented priority order so users get a deterministic selection.
  for (const fileName of DEFAULT_CONFIG_FILES) {
    const candidate = join(projectRoot, fileName);
    // The first existing file becomes the single config source for this command.
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// Returns whether one rule should run for the user's scan.
// Missing config means enabled, matching the descriptor default used by zero-config analysis.
function ruleEnabled(config: Config, ruleId: string): boolean {
  return config.rules.get(ruleId)?.enabled ?? true;
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

// Returns one numeric rule option or the caller's documented default.
// Missing rules, option maps, or names all mean the user left that tuning unchanged.
function optionNumber(config: Config, ruleId: string, name: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.options.get(name) ?? defaultValue;
}

// Checks whether a parsed config value belongs to the public severity vocabulary.
// Load-time validation and rule application share this guard so users see one consistent set of accepted values.
function isSeverity(configValue: unknown): configValue is Severity {
  return configValue === "advisory" || configValue === "warning" || configValue === "error";
}

export { defaultConfigPath, loadConfig, minimumSeverityFor, optionNumber, resolveProfile, ruleEnabled, ruleSeverity, threshold };
