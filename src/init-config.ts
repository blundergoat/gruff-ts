// Renders the default .gruff-ts.yaml file from the rule descriptor registry.
// `gruff-ts init` uses it to give a new project the analyser's effective defaults.
// Users reach this file through the generated config they review before their first scan.
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { defaultConfigPath } from "./config.ts";
import { extractPreservedConfigFields } from "./config-preservation.ts";
import { ruleDescriptors } from "./rules.ts";
import type { FailThreshold, MinimumSeverityCommand, RuleDescriptor } from "./types.ts";

const DEFAULT_CONFIG_FILE_NAME = ".gruff-ts.yaml";

// Default option values for rules with `optionKeys`. The source of truth is the
// `optionNumber` or `optionBoolean(config, ruleId, key, default)` call site in the rule implementation;
// mirroring them here keeps `gruff-ts init` self-contained. `init-config.test.ts` asserts the values
// here match the implementation defaults so drift fails the test suite, not user projects.
const RULE_OPTION_DEFAULTS: Readonly<Record<string, Readonly<Record<string, number | boolean>>>> = {
  "design.large-module-concentration": { minFiles: 4, minLines: 80 },
  "docs.missing-param-tag": { everyCallable: true },
  "docs.missing-return-tag": { everyCallable: true },
};

// Default starter list copied from `defaultConfig()` in config.ts. Generated separately because
// the YAML form (a block sequence) is more reviewable than the inline `[...]` form a Set would emit.
// Universal-programming abbreviations that earn their place across nearly any codebase; project-specific
// vocabulary (domain acronyms) should be appended in the user's config rather than added here.
const DEFAULT_ACCEPTED_ABBREVIATIONS: readonly string[] = [
  "age", "app", "db", "fs", "id", "io", "key", "log", "max", "min", "now", "raw", "rx", "tx", "ui", "url",
];

// Result of an init write attempt, including the no-clobber branch for existing config files.
interface InitResult {
  path: string;
  status: "written" | "overwritten" | "exists";
}

// Inputs the analyse/summary actions must collect before deciding whether to ask the user about
// running `init`. Kept as an explicit shape so the predicate is testable without TTY mocking. All
// three stream TTY states matter: stdin so the answer can be typed, stderr so the prompt is seen,
// and stdout so a piped consumer (e.g. `... --format=json | jq`) does not block on hidden input.
interface InitPromptContext {
  projectRoot: string;
  shouldSkipConfig: boolean;
  hasExplicitConfig: boolean;
  isInteractionAllowed: boolean;
  isOutputSuppressed: boolean;
  isStdinTty: boolean;
  isStdoutTty: boolean;
  isStderrTty: boolean;
}

/**
 * Bundle of values that survive an `init --force` regeneration. `paths.ignore` is preserved
 * verbatim, the per-command `failOn` gate is replayed entry-by-entry; the schemaVersion field is fixed for now
 * because there is only one supported version.
 */
interface PreservedInitConfig {
  ignoredPaths: readonly string[];
  failOn: ReadonlyMap<MinimumSeverityCommand, FailThreshold>;
  sensitiveExclusions: readonly PreservedSensitiveExclusionEntry[];
}

// One reviewed suppression carried through regeneration, in the ratified key order.
interface PreservedSensitiveExclusionEntry {
  rule: string;
  path: string;
  symbol?: string;
  reason: string;
}

const EMPTY_PRESERVED_CONFIG: PreservedInitConfig = { ignoredPaths: [], failOn: new Map(), sensitiveExclusions: [] };

/**
 * Render the default .gruff-ts.yaml content from the rule descriptor registry. Output order is schemaVersion → failOn → paths → allowlists →
 * sensitiveExclusions → rules so the highest-impact CI behaviour (gating threshold per command) sits near the top of the file. Sections are separated
 * by blank lines for readability.
 *
 * @param ignoredPaths - path exclusions kept by gruff-ts init --force. An empty list emits ignore: [].
 * @param preservedFailOn - existing command gates. Missing entries default to advisory for analyse and none for summary and report.
 * @param preservedSensitiveExclusions - existing reviewed suppressions, re-emitted below the guidance comments; an empty list emits only the comments
 * @returns A YAML document string terminated by a trailing newline.
 */
function renderDefaultConfig(
  ignoredPaths: readonly string[] = [],
  preservedFailOn: ReadonlyMap<MinimumSeverityCommand, FailThreshold> = new Map(),
  preservedSensitiveExclusions: readonly PreservedSensitiveExclusionEntry[] = [],
): string {
  return [
    renderSchemaVersionSection(),
    "",
    renderFailOnSection(preservedFailOn),
    "",
    renderPathsSection(ignoredPaths),
    "",
    renderAllowlistsSection(),
    "",
    renderSensitiveExclusionsSection(preservedSensitiveExclusions),
    "",
    renderRulesSection(),
  ].join("\n") + "\n";
}

/**
 * Render the reviewed sensitive-data exclusions described in FAMILY-CONTRACT.md section 13a.
 * Guidance stays commented so fresh projects suppress nothing here. Active entries come from prior manual review.
 *
 * @param preservedEntries - reviewed exclusions carried forward from the existing config
 * @returns YAML section text with guidance and any preserved entries, or only commented guidance when the list is empty
 */
function renderSensitiveExclusionsSection(preservedEntries: readonly PreservedSensitiveExclusionEntry[]): string {
  const guidance = [
    "# Reviewed suppressions for sensitive-data findings. Written by hand only - gruff never",
    "# converts a detected value, a preview, or a finding message into an exclusion.",
    "#",
    "# Each entry names exactly one rule id and one project-relative path, and must carry a",
    "# non-empty reason. `symbol:` narrows further where a rule stamps one. Nothing else is",
    "# suppressed: the same rule in another file and another rule in the same file keep reporting.",
    "# Every entry reports its own count in the report's `suppressions` array and in the text",
    "# `Suppressed findings:` line, so a suppression is always visible in review.",
    "#",
    "# Test, fixture and example paths automatically suppress sensitive-data findings",
    "# except sensitive-data.pii-test-fixture; real credentials there are skipped too.",
    "# Add entries only for reviewed findings that still report.",
    "# Use the finding's rule id and replace the path/reason placeholders.",
    "# sensitiveExclusions:",
    "#   - rule: sensitive-data.aws-access-key",
    "#     path: <reviewed-project-relative-path>",
    "#     reason: <reviewed-rationale>",
  ];
  // Regeneration must never silently re-enable a finding a reviewer accepted in writing, so any
  // existing entries are serialized as active YAML below the guidance comment.
  if (preservedEntries.length === 0) {
    return guidance.join("\n");
  }
  return [...guidance, "sensitiveExclusions:", ...preservedEntries.flatMap(renderPreservedExclusionEntry)].join("\n");
}

// Returns one preserved exclusion as block-sequence YAML lines in the expected key order.
// An entry without a symbol keeps that selector unset in the generated YAML.
function renderPreservedExclusionEntry(entry: PreservedSensitiveExclusionEntry): string[] {
  const lines = [`  - rule: ${JSON.stringify(entry.rule)}`, `    path: ${JSON.stringify(entry.path)}`];
  if (entry.symbol !== undefined) {
    lines.push(`    symbol: ${JSON.stringify(entry.symbol)}`);
  }
  lines.push(`    reason: ${JSON.stringify(entry.reason)}`);
  return lines;
}

// Returns the required top-level schema version field for the generated config.
function renderSchemaVersionSection(): string {
  return [
    "# Config-schema version. Required as of gruff-ts 0.2.0. See ADR-004 (decision log).",
    "schemaVersion: gruff-ts.config.v0.1",
  ].join("\n");
}

// Returns the failOn YAML section, using preserved command thresholds when present.
// Missing analyse defaults to advisory; missing summary and report default to none. Dashboard has no entry.
function renderFailOnSection(preserved: ReadonlyMap<MinimumSeverityCommand, FailThreshold>): string {
  const header = [
    "# Per-command default for `--fail-on`. CLI flag > this block > binary default.",
    "# `dashboard` is intentionally NOT a valid key - it has no --fail-on flag. See ADR-004.",
    "# `minimumSeverity:` is a different setting: one severity that hides quieter findings from the",
    "# report without changing the score or the exit code.",
    "#",
    "# Values:",
    "#   error    - exit non-zero only when an error-severity finding fires (strictest gate).",
    "#   warning  - exit non-zero on warning or error findings (advisory findings pass).",
    "#   advisory - exit non-zero on any finding at all (advisory, warning, or error).",
    "#   none     - never exit non-zero from findings (use for raw reporting / baseline generation).",
    "failOn:",
  ];
  const entries: Array<[MinimumSeverityCommand, FailThreshold]> = [
    ["analyse", preserved.get("analyse") ?? "advisory"],
    ["summary", preserved.get("summary") ?? "none"],
    ["report", preserved.get("report") ?? "none"],
  ];
  return [...header, ...entries.map(([command, severity]) => `  ${command}: ${severity}`)].join("\n");
}

/**
 * Writes .gruff-ts.yaml when no supported config exists or force is enabled.
 * Uses DEFAULT_CONFIG_FILES precedence so the caller can name the blocking file or carry its settings forward on a forced write.
 *
 * @param projectRoot - directory to search for the incumbent config and write the canonical file
 * @param shouldOverwrite - allows a canonical write even when a supported config already exists
 * @returns the incumbent path with exists when skipped, or the canonical path with written or overwritten after a write
 */
function writeDefaultConfig(projectRoot: string, shouldOverwrite: boolean): InitResult {
  const targetPath = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
  const existingConfigPath = defaultConfigPath(projectRoot);
  if (existingConfigPath !== undefined && !shouldOverwrite) {
    return { path: existingConfigPath, status: "exists" };
  }
  const targetExists = existsSync(targetPath);
  // Carry forward paths.ignore, command gates, and reviewed sensitive exclusions so a forced write preserves the selected scan policy.
  //
  // An existing alias can supply that policy when the project has no canonical file.
  // If the existing settings cannot be read, regeneration uses defaults.
  const preserved = existingConfigPath !== undefined ? readExistingPreservedConfig(existingConfigPath) : EMPTY_PRESERVED_CONFIG;
  writeFileSync(targetPath, renderDefaultConfig(preserved.ignoredPaths, preserved.failOn, preserved.sensitiveExclusions));
  return { path: targetPath, status: targetExists ? "overwritten" : "written" };
}

/*
 * Returns ignore paths, command gates and reviewed sensitive exclusions recovered from the existing config path.
 * Uses the permissive extractor so configs without schemaVersion can retain their readable settings.
 * Read or parse failures silently return empty settings because forced regeneration permits replacing unreadable content.
 */
function readExistingPreservedConfig(existingConfigPath: string): PreservedInitConfig {
  try {
    return extractPreservedConfigFields(existingConfigPath);
  } catch {
    return EMPTY_PRESERVED_CONFIG;
  }
}

// Returns the paths YAML section. With no supplied exclusions, it emits an empty ignore list because discovery already applies built-in ignores.
// During forced regeneration, the caller supplies existing path exclusions so the user's entries survive.
function renderPathsSection(ignoredPaths: readonly string[]): string {
  const header = [
    "paths:",
    "  # Recursive scans already respect .gitignore plus built-in default directories",
    "  # such as .git, node_modules, build, dist, coverage, and vendor.",
    "  # Add project-specific generated or local outputs here when Git does not ignore them.",
    "  # Examples:",
    "  #   - \"out/**\"",
    "  #   - \".next/**\"",
    "  #   - \"src/generated/**\"",
  ];
  if (ignoredPaths.length === 0) {
    return [...header, "  ignore: []"].join("\n");
  }
  return [
    ...header,
    "  ignore:",
    ...ignoredPaths.map((ignoredPath) => `    - ${JSON.stringify(ignoredPath)}`),
  ].join("\n");
}

// Returns the starter YAML naming allowlists, listing the default abbreviations accepted in identifiers.
// The other naming allowlists stay commented so users can discover them without changing defaults.
function renderAllowlistsSection(): string {
  return [
    "allowlists:",
    "  # Abbreviations listed here are accepted in identifiers without a naming finding.",
    "  # Replace this list with the short terms reviewers accept in this project.",
    "  acceptedAbbreviations:",
    ...DEFAULT_ACCEPTED_ABBREVIATIONS.map((abbreviation) => `    - ${abbreviation}`),
    "  # Exact fileBase:ClassName pairs accepted by naming.class-file-mismatch.",
    "  # Default: []",
    "  # acceptedClassFilePairs: [focusModeTranscript:TranscriptFocusController]",
    "  # Placeholder words flagged as generic by naming.identifier-quality. The",
    "  # numbered-suffix branch (foo1, value2) stays active even when this is empty.",
    "  # Default: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]",
    "  # placeholderNames: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]",
  ].join("\n");
}

// Walks the registry in its canonical (sorted) order so the generated YAML is byte-stable.
function renderRulesSection(): string {
  const lines = ["rules:"];
  for (const descriptor of ruleDescriptors()) {
    lines.push(...renderRuleEntry(descriptor));
  }
  return lines.join("\n");
}

// Returns YAML lines for the supplied rule descriptor, including its description, id and default enabled state.
// A numeric threshold adds threshold and severity; option fields come from RULE_OPTION_DEFAULTS when registered.
function renderRuleEntry(descriptor: RuleDescriptor): string[] {
  const lines: string[] = [];
  lines.push(`  # ${descriptor.pillar}/${descriptor.severity}: ${descriptor.description}`);
  lines.push(`  ${descriptor.ruleId}:`);
  lines.push(`    enabled: ${descriptor.isEnabledByDefault !== false}`);
  if (typeof descriptor.threshold === "number") {
    lines.push(`    threshold: ${descriptor.threshold}`);
    lines.push(`    severity: ${descriptor.severity}`);
  }
  const optionDefaults = RULE_OPTION_DEFAULTS[descriptor.ruleId];
  if (optionDefaults) {
    lines.push("    options:");
    for (const [key, value] of Object.entries(optionDefaults)) {
      lines.push(`      ${key}: ${value}`);
    }
  }
  return lines;
}

/**
 * Decide whether analyse or summary may offer init when interaction is allowed and output is not suppressed.
 * Requires no explicit config or opt-out, three TTY streams and no supported config file at the project root.
 *
 * @param context - CLI flags, stream state and project root used to decide whether to prompt
 * @returns Whether the prompt should be shown.
 */
function shouldPromptForInit(context: InitPromptContext): boolean {
  if (!context.isInteractionAllowed) {
    return false;
  }
  if (context.isOutputSuppressed) {
    return false;
  }
  if (context.shouldSkipConfig || context.hasExplicitConfig) {
    return false;
  }
  if (!context.isStdinTty || !context.isStdoutTty || !context.isStderrTty) {
    return false;
  }
  return defaultConfigPath(context.projectRoot) === undefined;
}

/**
 * Ask the user a yes/no question on stderr, reading stdin; empty or other answers mean no.
 * The readline interface closes when the question settles.
 *
 * @param question - prompt text written to stderr verbatim
 * @returns true for a trimmed, case-insensitive y or yes; false for other answers
 */
async function promptYesNo(question: string): Promise<boolean> {
  const readlineInterface = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await readlineInterface.question(question);
    return /^(y|yes)$/i.test(answer.trim());
  } finally {
    readlineInterface.close();
  }
}

export type { InitPromptContext, InitResult };
export { DEFAULT_CONFIG_FILE_NAME, RULE_OPTION_DEFAULTS, promptYesNo, renderDefaultConfig, shouldPromptForInit, writeDefaultConfig };
