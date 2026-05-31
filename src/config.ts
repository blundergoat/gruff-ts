// Config loading, defaults, validation, merging, and profile resolution. The zero-dependency
// YAML-subset parser, the file reader, and the value-narrowing helpers live in `config-parse.ts`.
import { existsSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { arrayValue, isString, objectValue, parseConfigFile, SUGGEST_EDIT_CONFIG, SUGGEST_INIT_FORCE } from "./config-parse.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { BUILT_IN_PROFILES, builtInProfileNames, DEFAULT_PROFILE_NAME, isKnownRuleId } from "./profiles.ts";
import type { AnalysisOptions, Config, FailThreshold, InlineProfileSpec, MinimumSeverityCommand, ProfileDefinition, ProfileRuleSetting, ProfileSpec, Severity } from "./types.ts";

type RuleOverride = Config["rules"] extends Map<string, infer RuleOverrideValue> ? RuleOverrideValue : never;

const DEFAULT_CONFIG_FILES = [".gruff-ts.yaml", ".gruff.json", ".gruff.yaml", ".gruff.yml"] as const;

// Built-in defaults applied before any user config overlays. The string lists here (accepted
// abbreviations, banned generic names, boolean prefixes, …) are the stable rule contract - they
// shape what every gruff scan emits by default and changing them shifts the public rule surface.
// schemaVersion is fixed at `gruff-ts.config.v0.1` as the schema invariant for this release.
function defaultConfig(): Config {
  return {
    schemaVersion: "gruff-ts.config.v0.1",
    ignoredPaths: [],
    acceptedAbbreviations: new Set(["age", "app", "cb", "db", "fn", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url"]),
    secretPreviews: new Set(),
    bannedGenericNames: new Set(["process", "handle", "doit", "run", "execute", "manage"]),
    acceptedBooleanNames: new Set(["all", "apply", "check", "dev", "enabled", "force", "fresh", "harness", "json", "ok", "verbose", "yes"]),
    booleanPrefixes: new Set(["is", "has", "can", "should", "does", "did", "was", "will", "may", "in", "scan", "supports", "requires", "allow", "check", "enable", "exclude", "include", "omit", "skip", "with", "without"]),
    hungarianPrefixes: new Set(["str", "obj", "arr", "bool", "int", "num"]),
    placeholderNames: new Set(["foo", "bar", "baz", "tmp", "temp", "thing", "stuff", "data", "value", "item"]),
    negativeBooleanAllowed: new Set(["nostore", "nofollow", "noreferrer", "noscript", "noindex"]),
    knownAcronyms: new Set(["url", "http", "https", "id", "xml", "json", "html", "css", "api", "sql", "db", "io", "ui", "uuid", "ip", "tcp", "udp", "ast", "cli", "npm"]),
    minimumSeverity: new Map(),
    rules: new Map(),
  };
}

// Anchors a relative CLI argument against the project root; absolute paths pass through unchanged.
function absolutize(projectRoot: string, path: string): string {
  return isAbsolute(path) ? path : join(projectRoot, path);
}

// Reads the YAML config from disk (if any) and overlays user values onto `defaultConfig`. `shouldSkipConfig`
// is the explicit opt-out; missing default file is silent (returns defaults) so projects without
// `.gruff-ts.yaml` work zero-config. Throws on malformed YAML - the caller surfaces it as a fatal CLI error.
function loadConfig(projectRoot: string, options: AnalysisOptions): Config {
  const config = defaultConfig();
  const path = options.shouldSkipConfig ? undefined : selectedConfigPath(projectRoot, options);
  const raw: Record<string, unknown> = path ? parseConfigFile(path) : {};
  if (path) {
    applyConfigValues(config, raw);
  }
  applyProfile(config, options, raw, projectRoot);
  return config;
}

/*
 * Applies the profile layer UNDER the top-level config sections. Precedence (highest first): the CLI
 * `--profile` flag, then a config-file `profile:` block, then the profile's own `extends:` chain, then
 * the built-in default `gruff.recommended`. The flattened profile only fills rules the top-level
 * `rules:` block did not already set, so an explicit per-rule override always wins over the profile.
 * When neither the flag nor the config names a profile this is a no-op, because the implicit default
 * `recommended` flattens to an empty delta - the contract that keeps `--profile recommended` and a
 * zero-config scan byte-identical. `--no-config` skips the file but the CLI `--profile` still applies.
 */
function applyProfile(config: Config, options: AnalysisOptions, raw: Record<string, unknown>, projectRoot: string): void {
  const rawSpec = options.profile !== undefined ? options.profile : raw.profile;
  if (rawSpec === undefined) {
    return;
  }
  applyProfileUnderlay(config, resolveProfile(parseProfileSpec(rawSpec), projectRoot));
}

// Lays a flattened profile under the already-applied top-level config: each rule the top-level
// `rules:` block did not set takes the profile's value; profile ignored paths union with `paths.ignore`.
function applyProfileUnderlay(config: Config, definition: ProfileDefinition): void {
  for (const [ruleId, setting] of definition.rules) {
    if (!config.rules.has(ruleId)) {
      config.rules.set(ruleId, profileRuleToConfig(setting));
    }
  }
  if (definition.ignoredPaths.length > 0) {
    config.ignoredPaths = [...new Set([...config.ignoredPaths, ...definition.ignoredPaths])];
  }
}

// Converts a profile rule setting into the loaded-config rule shape. `options` is always a map in the
// config value, so an absent profile options field becomes an empty map. Conditional spreads keep the
// absent-vs-undefined distinction required under exactOptionalPropertyTypes.
function profileRuleToConfig(setting: ProfileRuleSetting): RuleOverride {
  return {
    ...(setting.enabled !== undefined ? { enabled: setting.enabled } : {}),
    ...(setting.threshold !== undefined ? { threshold: setting.threshold } : {}),
    ...(setting.severity !== undefined ? { severity: setting.severity } : {}),
    options: setting.options ?? new Map(),
  };
}

/*
 * Resolves a profile spec into a flattened ProfileDefinition (a delta from the descriptor defaults).
 * Documented precedence the callers depend on, highest first: the CLI `--profile` flag, the config
 * `profile:` block, the `extends:` base chain, and the built-in default `gruff.recommended`. This
 * function owns only the `extends:` flattening; `loadConfig` applies the result under the top-level
 * config sections via `applyProfileUnderlay`.
 *
 * Flattening is child-wins and deterministic: a child profile's per-rule fields override the parent's
 * same-rule fields (last assignment wins for a repeated key), and a child `ignoredPaths` array
 * replaces - does not concatenate - the parent's. `chain` carries the ordered, already-visited file
 * paths so a cycle (A extends B extends A) is rejected with a message naming both in order, instead of
 * recursing until the stack overflows.
 *
 * Throws ConfigLoadError on: a missing `extends:` file, a rule id not in RULE_DESCRIPTORS, or an
 * inheritance cycle. Every failure surfaces at config-load time, never at scan time. File paths only:
 * `extends:` never fetches a remote URL or runs a shell.
 */
function resolveProfile(spec: ProfileSpec, projectRoot: string, chain: string[] = []): ProfileDefinition {
  if (typeof spec === "string") {
    return resolveProfileRef(spec, projectRoot, chain);
  }
  return resolveInlineProfile(spec, projectRoot, chain);
}

// Resolves a string ref: a built-in name returns its bundled definition (terminal, no extends); any
// other string is treated as a relative profile file path (no built-in match, no network, no shell).
// The canonical built-in names are `gruff.minimal` / `gruff.recommended` / `gruff.strict`; the bare
// short forms (`minimal`, `recommended`, `strict`) are accepted as aliases for CLI ergonomics, so a
// built-in always wins over a same-named extensionless file - point `--profile` at `./name` for a file.
function resolveProfileRef(ref: string, projectRoot: string, chain: string[]): ProfileDefinition {
  const builtIn = BUILT_IN_PROFILES.get(ref) ?? BUILT_IN_PROFILES.get(`gruff.${ref}`);
  if (builtIn) {
    return cloneProfileDefinition(builtIn);
  }
  return resolveProfileFile(ref, projectRoot, chain);
}

// Loads and resolves a profile file, treating its parsed top-level mapping as an inline profile
// spec. A missing file or a cycle caught by the chain guard throws ConfigLoadError at load time.
function resolveProfileFile(ref: string, projectRoot: string, chain: string[]): ProfileDefinition {
  const path = absolutize(projectRoot, ref);
  assertNoProfileCycle(path, chain);
  if (!existsSync(path)) {
    throw new ConfigLoadError(
      `Profile extends file not found: ${path}.`,
      `Point \`extends:\` (or --profile) at an existing .yaml/.yml/.json profile file, or use a built-in name: ${builtInProfileNames().join(", ")}.`,
    );
  }
  return resolveInlineProfile(inlineSpecFromObject(parseConfigFile(path)), projectRoot, [...chain, path]);
}

// Resolves the base (the `extends:` target, defaulting to gruff.recommended) and overlays this spec's
// rule and path overrides on top with child-wins semantics.
function resolveInlineProfile(spec: InlineProfileSpec, projectRoot: string, chain: string[]): ProfileDefinition {
  const base = resolveProfileRef(spec.extends ?? DEFAULT_PROFILE_NAME, projectRoot, chain);
  return overlayProfile(base, spec);
}

// Overlays a child inline spec on a resolved base. Per-rule fields merge (child wins field-by-field);
// the child `ignoredPaths` array replaces the base's when present, else the base's is inherited.
function overlayProfile(base: ProfileDefinition, spec: InlineProfileSpec): ProfileDefinition {
  const rules = new Map(base.rules);
  for (const [ruleId, setting] of Object.entries(spec.rules ?? {})) {
    assertKnownProfileRule(ruleId);
    rules.set(ruleId, mergeRuleSetting(rules.get(ruleId), setting));
  }
  const ignoredPaths = spec.ignoredPaths !== undefined ? [...spec.ignoredPaths] : [...base.ignoredPaths];
  return { name: base.name, rules, ignoredPaths };
}

// Field-level child-wins merge for one rule's settings: spread the parent then the child so every key
// the child sets (including `enabled: false`) overrides the parent while unset child keys inherit. Both
// inputs are built with conditional spreads upstream, so neither carries explicit-undefined keys that
// would clobber an inherited value.
function mergeRuleSetting(parent: ProfileRuleSetting | undefined, child: ProfileRuleSetting): ProfileRuleSetting {
  return { ...parent, ...child };
}

// Defensive copy so overlays never mutate a shared built-in definition's rule map or ignore list.
function cloneProfileDefinition(definition: ProfileDefinition): ProfileDefinition {
  return { name: definition.name, rules: new Map(definition.rules), ignoredPaths: [...definition.ignoredPaths] };
}

// Guards the `extends:` chain against cycles, naming the whole chain in visit order so the user can
// see both ends of the loop. A revisited `key` throws ConfigLoadError before the recursion repeats.
function assertNoProfileCycle(key: string, chain: string[]): void {
  if (chain.includes(key)) {
    throw new ConfigLoadError(
      `Profile inheritance cycle detected: ${[...chain, key].join(" -> ")}.`,
      "Break the `extends:` cycle so each profile in the chain is reached only once.",
    );
  }
}

// Validates a user profile rule id against the catalogue so a typo never silently no-ops at scan
// time: an id outside RULE_DESCRIPTORS throws ConfigLoadError at load time.
function assertKnownProfileRule(ruleId: string): void {
  if (!isKnownRuleId(ruleId)) {
    throw new ConfigLoadError(
      `Unknown rule id in profile: ${JSON.stringify(ruleId)}.`,
      "Use a rule id from `gruff-ts list-rules`; profile `rules:` keys must match the catalogue exactly.",
    );
  }
}

/*
 * Parses the raw `profile:` value (from YAML/JSON or the CLI flag) into a typed ProfileSpec. A string
 * is a built-in name or file path; a mapping is an inline spec. Throws ConfigLoadError on any other
 * shape so a malformed `profile:` block surfaces as a clean config error, not a downstream crash.
 */
function parseProfileSpec(rawSpec: unknown): ProfileSpec {
  if (typeof rawSpec === "string") {
    return rawSpec;
  }
  const block = objectValue(rawSpec);
  if (!block) {
    throw new ConfigLoadError(
      "`profile:` must be a built-in name, a profile file path, or a mapping with `extends:` and overrides.",
      SUGGEST_EDIT_CONFIG,
    );
  }
  return inlineSpecFromObject(block);
}

// Extracts the supported inline-profile keys (`extends`, `rules`, `ignoredPaths`) from a parsed
// mapping; other keys such as a `schemaVersion` on a shared profile file are ignored so it reads the
// same as an embedded block. A bad `extends` type or malformed override throws ConfigLoadError here.
function inlineSpecFromObject(block: Record<string, unknown>): InlineProfileSpec {
  const spec: InlineProfileSpec = {};
  if ("extends" in block) {
    if (!isString(block.extends)) {
      throw new ConfigLoadError("`profile.extends` must be a string: a built-in name or a relative profile file path.", SUGGEST_EDIT_CONFIG);
    }
    spec.extends = block.extends;
  }
  const rulesBlock = objectValue(block.rules);
  if (rulesBlock) {
    spec.rules = profileRulesFromBlock(rulesBlock);
  }
  if ("ignoredPaths" in block) {
    spec.ignoredPaths = arrayValue(block.ignoredPaths).filter(isString);
  }
  return spec;
}

// Builds the per-rule settings map for an inline profile, reusing the same validation as the
// top-level `rules:` block (`ruleConfigValue` throws on a non-numeric threshold or bad severity).
function profileRulesFromBlock(rulesBlock: Record<string, unknown>): Record<string, ProfileRuleSetting> {
  const rules: Record<string, ProfileRuleSetting> = {};
  for (const [ruleId, value] of Object.entries(rulesBlock)) {
    const rule = objectValue(value);
    if (rule) {
      rules[ruleId] = ruleConfigValue(rule);
    }
  }
  return rules;
}

// Explicit `--config` wins; otherwise look for the first supported config at the project root. Returning
// undefined means "no config" - callers must treat that as "use defaults", not as an error.
function selectedConfigPath(projectRoot: string, options: AnalysisOptions): string | undefined {
  return options.config ? absolutize(projectRoot, options.config) : defaultConfigPath(projectRoot);
}

// Top-level sections applied in a fixed order: schemaVersion → minimumSeverity → paths → allowlists
// → rules. schemaVersion runs first because every later parse depends on the contract version it
// declares, and minimumSeverity runs next so CLI consumers reading it during normalizeOptions see
// a populated map. Order does not affect correctness today but the stable application order keeps
// later overrides predictable if interdependencies are added.
function applyConfigValues(config: Config, raw: Record<string, unknown>): void {
  applySchemaVersionConfig(raw);
  applyMinimumSeverityConfig(config, raw);
  applyPathConfig(config, raw);
  applyAllowlistConfig(config, raw);
  applyRuleConfig(config, raw);
}

/*
 * Validates the required `schemaVersion` top-level field. Pre-1.0 break: configs missing the field
 * or carrying any other version string are rejected (throws with a documented error listing the
 * supported version) because there is no migration shim under the no-legacy-compat contract. The
 * function does not mutate the loaded config because the only supported value matches
 * `defaultConfig().schemaVersion` already; future versions would extend the union and require a
 * write here. The schema invariant is fixed at `gruff-ts.config.v0.1`.
 */
function applySchemaVersionConfig(raw: Record<string, unknown>): void {
  const schemaVersion = raw.schemaVersion;
  if (schemaVersion === undefined) {
    throw new ConfigLoadError('Config must include `schemaVersion: gruff-ts.config.v0.1` at the top.', SUGGEST_INIT_FORCE);
  }
  if (schemaVersion !== "gruff-ts.config.v0.1") {
    throw new ConfigLoadError(`Unsupported schemaVersion: ${JSON.stringify(schemaVersion)}. Supported: "gruff-ts.config.v0.1".`, SUGGEST_INIT_FORCE);
  }
}

// Parses the `minimumSeverity:` block into a Map keyed by command name. Validation throws on
// `dashboard` specifically (no `--fail-on` flag exists for it), on unknown command keys, and on
// every non-canonical value. Missing block is allowed - it just leaves the map empty so CLI
// consumers fall through to the binary default.
function applyMinimumSeverityConfig(config: Config, raw: Record<string, unknown>): void {
  const block = objectValue(raw.minimumSeverity);
  if (!block) {
    return;
  }
  for (const [commandName, value] of Object.entries(block)) {
    config.minimumSeverity.set(assertMinimumSeverityCommand(commandName), parseFailThresholdConfig(value));
  }
}

/*
 * Validates one `minimumSeverity:` map key. Throws on `dashboard` specifically because the
 * dashboard subcommand has no `--fail-on` flag; accepting the key would silently no-op and
 * operators would expect a gate that never fires. Throws on unknown commands so typos surface at
 * load time instead of as silent CI footguns.
 */
function assertMinimumSeverityCommand(commandName: string): MinimumSeverityCommand {
  if (commandName === "dashboard") {
    throw new ConfigLoadError('Unknown command in minimumSeverity: "dashboard". The dashboard subcommand does not currently expose a --fail-on flag; configuring its threshold is not supported.', "Remove the `dashboard:` line from `minimumSeverity:` in `.gruff-ts.yaml`, or open an issue if dashboard should gate.");
  }
  if (commandName === "analyse" || commandName === "summary" || commandName === "report") {
    return commandName;
  }
  throw new ConfigLoadError(`Unknown command in minimumSeverity: ${JSON.stringify(commandName)}. Valid keys: analyse, summary, report.`, SUGGEST_EDIT_CONFIG);
}

/*
 * Validates one `FailThreshold` value coming from YAML. Throws on every non-canonical value with a
 * clear error listing the four supported strings. `never` is rejected explicitly because earlier
 * cross-port drafts considered it as the off-switch value before the family converged on `none`;
 * guarding against drift back to `never` keeps the cross-port vocabulary aligned.
 */
function parseFailThresholdConfig(rawValue: unknown): FailThreshold {
  if (rawValue === "none" || rawValue === "advisory" || rawValue === "warning" || rawValue === "error") {
    return rawValue;
  }
  throw new ConfigLoadError(`FailThreshold must be one of: advisory, warning, error, none. Got: ${JSON.stringify(rawValue)}.`, SUGGEST_EDIT_CONFIG);
}

// Per-command lookup used by the CLI precedence chain (CLI flag > config > binary default).
// Returns undefined when the user did not configure that command so the caller can fall through
// to the binary default. Exported so the CLI consumers in `cli-program.ts` can consult it.
function minimumSeverityFor(config: Config, command: MinimumSeverityCommand): FailThreshold | undefined {
  return config.minimumSeverity.get(command);
}

// Replaces `ignoredPaths` with the user list. Non-string entries are silently dropped - invalid
// YAML shapes should not abort the analysis run.
function applyPathConfig(config: Config, raw: Record<string, unknown>): void {
  const paths = objectValue(raw.paths);
  config.ignoredPaths = arrayValue(paths?.ignore).filter(isString);
}

// The allowlist section is the main lever users have for tuning gruff to their conventions.
// `acceptedAbbreviations` and the seven naming lists are lowercased on import so case-insensitive
// matching is the stable behaviour regardless of how users write entries.
function applyAllowlistConfig(config: Config, raw: Record<string, unknown>): void {
  const allowlists = objectValue(raw.allowlists);
  const abbreviations = arrayValue(allowlists?.acceptedAbbreviations).filter(isString);
  if (allowlists && "acceptedAbbreviations" in allowlists) {
    config.acceptedAbbreviations = new Set(abbreviations.map((value) => value.toLowerCase()));
  }
  config.secretPreviews = new Set(arrayValue(allowlists?.secretPreviews).filter(isString));
  applyNamingAllowlist(config, allowlists, "bannedGenericNames");
  applyNamingAllowlist(config, allowlists, "acceptedBooleanNames");
  applyNamingAllowlist(config, allowlists, "booleanPrefixes");
  applyNamingAllowlist(config, allowlists, "hungarianPrefixes");
  applyNamingAllowlist(config, allowlists, "placeholderNames");
  applyNamingAllowlist(config, allowlists, "negativeBooleanAllowed");
  applyNamingAllowlist(config, allowlists, "knownAcronyms");
}

// Replaces the entire list when the user provides that key - there is no merge with defaults.
// The "set the whole list" semantic is intentional so users can deliberately empty a list.
function applyNamingAllowlist(config: Config, allowlists: Record<string, unknown> | undefined, key: "bannedGenericNames" | "acceptedBooleanNames" | "booleanPrefixes" | "hungarianPrefixes" | "placeholderNames" | "negativeBooleanAllowed" | "knownAcronyms"): void {
  if (!allowlists || !(key in allowlists)) {
    return;
  }
  config[key] = new Set(arrayValue(allowlists[key]).filter(isString).map((value) => value.toLowerCase()));
}

// Per-rule overrides under the `rules:` key. Each entry can carry enabled / threshold / severity /
// options - only the keys the user actually sets become overrides; unset keys fall through to defaults.
function applyRuleConfig(config: Config, raw: Record<string, unknown>): void {
  const rules = objectValue(raw.rules);
  if (!rules) {
    return;
  }
  for (const [ruleId, value] of Object.entries(rules)) {
    const rule = objectValue(value);
    if (!rule) {
      continue;
    }
    config.rules.set(ruleId, ruleConfigValue(rule));
  }
}

// Builds one rule's override entry after `assertRuleThresholdConfig` has thrown on malformed input.
// Validation happens before extraction so users see a useful error rather than a silently dropped key.
function ruleConfigValue(rule: Record<string, unknown>): RuleOverride {
  assertRuleThresholdConfig(rule);
  const ruleOverride: RuleOverride = { options: numericConfigMap(rule.options) };
  applyRuleEnabledConfig(ruleOverride, rule);
  applyRuleThresholdConfig(ruleOverride, rule);
  applyRuleSeverityConfig(ruleOverride, rule);
  return ruleOverride;
}

/*
 * Validates individual `threshold` and `severity` types. Either, neither, or both may be present:
 * many rules have no `threshold` knob at all (security.eval-call, waste.any-type, etc.), so a
 * "must be configured together" gate would block any severity-only override on those rules even
 * though `gruff-ts list-rules <id>` advertises `rules.<id>.severity` as a public knob. Each field
 * is independently optional and falls through to the descriptor default when absent.
 *
 * Throws ConfigLoadError when `threshold` is present but non-numeric, or when `severity` is
 * present but not one of `advisory|warning|error`. Returns silently when both fields are absent
 * (the common case for `enabled`-only or options-only overrides).
 */
function assertRuleThresholdConfig(rule: Record<string, unknown>): void {
  if ("threshold" in rule && typeof rule.threshold !== "number") {
    throw new ConfigLoadError('Rule config key "threshold" must be numeric.', SUGGEST_EDIT_CONFIG);
  }
  if ("severity" in rule && !isSeverity(rule.severity)) {
    throw new ConfigLoadError('Rule config key "severity" must be "advisory", "warning", or "error".', SUGGEST_EDIT_CONFIG);
  }
}

/** Copies an explicit enabled override while preserving absent config keys. */
function applyRuleEnabledConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  if (typeof rule.enabled === "boolean") {
    ruleOverride.enabled = rule.enabled;
  }
}

/** Copies a numeric threshold after validation has proved the value is safe. */
function applyRuleThresholdConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  if (typeof rule.threshold === "number") {
    ruleOverride.threshold = rule.threshold;
  }
}

/** Copies a severity override after validation has proved the value is supported. */
function applyRuleSeverityConfig(ruleOverride: RuleOverride, rule: Record<string, unknown>): void {
  if (isSeverity(rule.severity)) {
    ruleOverride.severity = rule.severity;
  }
}

// Rule options are typed as numeric (thresholds, line counts, etc.). Non-numeric entries are
// silently dropped rather than thrown because allowing malformed YAML to abort a scan is too aggressive.
function numericConfigMap(optionsValue: unknown): Map<string, number> {
  const options = new Map<string, number>();
  const rawOptions = objectValue(optionsValue);
  if (!rawOptions) {
    return options;
  }
  for (const [name, option] of Object.entries(rawOptions)) {
    if (typeof option === "number") {
      options.set(name, option);
    }
  }
  return options;
}

// Returns the first supported config path at the project root; undefined otherwise so
// callers can fall back to defaults without distinguishing "no config" from a real error.
function defaultConfigPath(projectRoot: string): string | undefined {
  for (const fileName of DEFAULT_CONFIG_FILES) {
    const candidate = join(projectRoot, fileName);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// Rules are enabled by default - the absence of a config entry means "use the descriptor default",
// which is the documented contract for how unset rules behave.
function ruleEnabled(config: Config, ruleId: string): boolean {
  return config.rules.get(ruleId)?.enabled ?? true;
}

// Resolves a threshold for the rule. Callers pass the descriptor default so this helper alone
// determines whether config can override - keeps every rule's threshold lookup uniform.
function threshold(config: Config, ruleId: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.threshold ?? defaultValue;
}

// Same shape as `threshold`. The descriptor default is the single source of truth for what severity
// a rule emits when the user has no config entry.
function ruleSeverity(config: Config, ruleId: string, defaultSeverity: Severity): Severity {
  return config.rules.get(ruleId)?.severity ?? defaultSeverity;
}

// Rule-specific numeric options (e.g., minLength for sensitive-data rules). Same default-fallback
// pattern as `threshold` so rules can be configured without forcing every field to be set.
function optionNumber(config: Config, ruleId: string, name: string, defaultValue: number): number {
  return config.rules.get(ruleId)?.options.get(name) ?? defaultValue;
}

// Whitelist check used both by config validation (throws on bad values) and by `applyRuleSeverityConfig`.
// The set of accepted strings is the public severity vocabulary; adding entries is a schema change.
function isSeverity(configValue: unknown): configValue is Severity {
  return configValue === "advisory" || configValue === "warning" || configValue === "error";
}

export { defaultConfigPath, loadConfig, minimumSeverityFor, optionNumber, resolveProfile, ruleEnabled, ruleSeverity, threshold };
