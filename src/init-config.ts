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
// `optionNumber(config, ruleId, key, default)` call site in the rule implementation; mirroring
// them here keeps `gruff-ts init` self-contained. `init-config.test.ts` asserts the values
// here match the implementation defaults so drift fails the test suite, not user projects.
const RULE_OPTION_DEFAULTS: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  "design.large-module-concentration": { minFiles: 4, minLines: 80 },
  "naming.generic-parameter": { minCyclomatic: 8, minLineCount: 30, minParameters: 3 },
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
 * Render the default .gruff-ts.yaml content from the rule descriptor registry. Output order is
 * schemaVersion → failOn → paths → allowlists → rules so the highest-impact CI behaviour
 * (gating threshold per command) sits near the top of the file. Sections are separated by blank
 * lines for readability.
 *
 * @param ignoredPaths Optional `paths.ignore` entries to inject verbatim (block-sequence form).
 *   The `gruff-ts init --force` flow forwards the existing file's entries so user-curated
 *   exclusions survive regeneration; an empty list emits `ignore: []` for fresh projects.
 * @param preservedFailOn Optional carry-over of the existing config's `failOn:` block.
 *   Empty Map falls back to canonical defaults (advisory / advisory / none).
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

/*
 * Reviewed sensitive-data suppressions, emitted entirely as comments so a fresh project suppresses
 * nothing until someone writes an entry by hand. The section is deliberately separate from
 * `rules:` and `paths.ignore` because it is the only surface that can hide a sensitive finding, and
 * a commented example is how a user discovers it (FAMILY-CONTRACT.md, search:
 * `### 13a. Sensitive exclusions`). Nothing generates an entry: gruff never converts a detected
 * value, a preview, or a message into a suppression.
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
    "# sensitiveExclusions:",
    "#   - rule: sensitive-data.aws-access-key",
    "#     path: tests/fixtures/aws-sample.env",
    "#     reason: Synthetic key used by the loader fixture; not a live credential.",
  ];
  // Regeneration must never silently re-enable a finding a reviewer accepted in writing, so any
  // existing entries are re-emitted verbatim below the guidance comment.
  if (preservedEntries.length === 0) {
    return guidance.join("\n");
  }
  return [...guidance, "sensitiveExclusions:", ...preservedEntries.flatMap(renderPreservedExclusionEntry)].join("\n");
}

// One preserved entry as block-sequence YAML lines, keeping the ratified key order.
function renderPreservedExclusionEntry(entry: PreservedSensitiveExclusionEntry): string[] {
  const lines = [`  - rule: ${JSON.stringify(entry.rule)}`, `    path: ${JSON.stringify(entry.path)}`];
  if (entry.symbol !== undefined) {
    lines.push(`    symbol: ${JSON.stringify(entry.symbol)}`);
  }
  lines.push(`    reason: ${JSON.stringify(entry.reason)}`);
  return lines;
}

// Required top-level schema-version field. Documented in ADR-004 because the introduction itself
// is a pre-1.0 break - every existing config gains this line, no transitional shim.
function renderSchemaVersionSection(): string {
  return [
    "# Config-schema version. Required as of gruff-ts 0.2.0. See ADR-004 (decision log).",
    "schemaVersion: gruff-ts.config.v0.1",
  ].join("\n");
}

// Per-command --fail-on defaults. The canonical out-of-the-box values match the operator's "show
// everything, fail on anything" philosophy. `dashboard` is intentionally NOT a valid key because
// the dashboard subcommand has no --fail-on flag and accepting it would be a silent CI footgun.
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
    ["summary", preserved.get("summary") ?? "advisory"],
    ["report", preserved.get("report") ?? "none"],
  ];
  return [...header, ...entries.map(([command, severity]) => `  ${command}: ${severity}`)].join("\n");
}

/**
 * Write the default config to `<projectRoot>/.gruff-ts.yaml`. Performs a filesystem write side
 * effect when no supported config exists, or when `shouldOverwrite` is true and `.gruff-ts.yaml`
 * is the incumbent. Refuses to clobber (no side effect) when ANY supported config file is present
 * (the four-name precedence list in `DEFAULT_CONFIG_FILES`), not just `.gruff-ts.yaml` -
 * otherwise `init` would silently create a higher-precedence file alongside an existing
 * `.gruff.yaml` / `.gruff.yml` / `.gruff.json` and quietly change the effective config. When
 * overwriting an existing `.gruff-ts.yaml`, the file's `paths.ignore` entries are preserved so
 * `init --force` does not erase project-specific recursive-scan exclusions.
 *
 * @param projectRoot Directory to write the config file into.
 * @param shouldOverwrite Overwrite an existing config file when true.
 * @returns The resolved path and whether a file was written, overwritten, or skipped. When the
 *   refusal is triggered by a non-canonical name, `path` points at that file so the caller's
 *   error message names the actual blocker.
 */
function writeDefaultConfig(projectRoot: string, shouldOverwrite: boolean): InitResult {
  const targetPath = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
  const existingConfigPath = defaultConfigPath(projectRoot);
  if (existingConfigPath !== undefined && !shouldOverwrite) {
    return { path: existingConfigPath, status: "exists" };
  }
  const targetExists = existsSync(targetPath);
  // Preserve paths.ignore + the per-command failOn gate from whichever supported config exists, not just
  // `.gruff-ts.yaml` - otherwise `init --force` against a project with only
  // `.gruff.yaml`/`.yml`/`.json` would silently drop user-curated exclusions and command-specific
  // gating thresholds when generating the new canonical file.
  const preserved = existingConfigPath !== undefined ? readExistingPreservedConfig(existingConfigPath) : EMPTY_PRESERVED_CONFIG;
  writeFileSync(targetPath, renderDefaultConfig(preserved.ignoredPaths, preserved.failOn, preserved.sensitiveExclusions));
  return { path: targetPath, status: targetExists ? "overwritten" : "written" };
}

/*
 * Recover the existing file's `paths.ignore` and per-command gate blocks before `init --force`
 * overwrites it. Uses the permissive extractor (not the strict validator) so a pre-0.2.0 config
 * without `schemaVersion` still hands its curated entries to the regenerated file - the strict
 * gate would throw on the missing field and silently drop the user's `paths.ignore`. The
 * try/catch swallows IO/parse errors and returns empty values so a malformed existing config
 * does not block regeneration; the user is opting into clobbering, but the documented contract
 * is that curated entries survive when readable.
 */
function readExistingPreservedConfig(existingConfigPath: string): PreservedInitConfig {
  try {
    return extractPreservedConfigFields(existingConfigPath);
  } catch {
    return EMPTY_PRESERVED_CONFIG;
  }
}

// `paths.ignore` defaults to empty for fresh projects - discovery.ts already filters node_modules,
// .git, etc. regardless of config. When `init --force` regenerates an existing config, the caller
// forwards the existing entries so user-curated exclusions survive.
function renderPathsSection(ignoredPaths: readonly string[]): string {
  const header = [
    "paths:",
    "  # Recursive scans already respect .gitignore plus built-in default directories",
    "  # such as .git, node_modules, dist, coverage, generated, tmp, and vendor.",
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

// Shows users which short identifier terms avoid naming findings in a newly initialized project.
// The other naming allowlists stay commented so users can discover them without changing defaults.
function renderAllowlistsSection(): string {
  return [
    "allowlists:",
    "  # Abbreviations listed here are accepted in identifiers without a naming finding.",
    "  # Replace this list with the short terms reviewers accept in this project.",
    "  acceptedAbbreviations:",
    // Each family term is visible so a user can review or replace the complete list in generated YAML.
    ...DEFAULT_ACCEPTED_ABBREVIATIONS.map((abbreviation) => `    - ${abbreviation}`),
    "  # Names that trigger naming.generic-function. Each key replaces the built-in",
    "  # default when present; an empty list disables that rule's blacklist branch.",
    "  # Default: [process, handle, doit, run, execute, manage]",
    "  # bannedGenericNames: [process, handle, doit, run, execute, manage]",
    "  # Exact public/CLI/DTO boolean names accepted by naming.boolean-prefix.",
    "  # Default: [all, apply, check, dev, enabled, force, fresh, harness, json, ok, verbose, yes]",
    "  # acceptedBooleanNames: [all, apply, check, dev, enabled, force, fresh, harness, json, ok, verbose, yes]",
    "  # Exact fileBase:ClassName pairs accepted by naming.class-file-mismatch.",
    "  # Default: []",
    "  # acceptedClassFilePairs: [focusModeTranscript:TranscriptFocusController]",
    "  # Exact wire_name:internalName alias pairs accepted within one naming owner.",
    "  # Default: []",
    "  # acceptedCasingPairs: [note_id:noteId]",
    "  # Accepted prefixes for boolean identifiers. Names without one of these",
    "  # prefixes trigger naming.boolean-prefix.",
    "  # Default: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires, allow, check, enable, exclude, include, omit, skip, with, without]",
    "  # booleanPrefixes: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires, allow, check, enable, exclude, include, omit, skip, with, without]",
    "  # Hungarian type-style prefixes flagged by naming.hungarian-notation.",
    "  # Default: [str, obj, arr, bool, int, num]",
    "  # hungarianPrefixes: [str, obj, arr, bool, int, num]",
    "  # Placeholder words flagged as generic by naming.identifier-quality. The",
    "  # numbered-suffix branch (foo1, value2) stays active even when this is empty.",
    "  # Default: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]",
    "  # placeholderNames: [foo, bar, baz, tmp, temp, thing, stuff, data, value, item]",
    "  # Negative-framed boolean names that should NOT trigger naming.negative-boolean.",
    "  # Defaults are HTTP-header conventions; add project terms as needed.",
    "  # Default: [nostore, nofollow, noreferrer, noscript, noindex]",
    "  # negativeBooleanAllowed: [nostore, nofollow, noreferrer, noscript, noindex]",
    "  # Known acronyms whose mixed casings trigger naming.acronym-case. Stored",
    "  # case-insensitively; match is against canonical lowercase.",
    "  # Default: [url, http, https, id, xml, json, html, css, api, sql, db, io, ui, uuid, ip, tcp, udp, ast, cli, npm]",
    "  # knownAcronyms: [url, http, https, id, xml, json, html, css, api, sql, db, io, ui, uuid, ip, tcp, udp, ast, cli, npm]",
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

// One rule entry: a `# pillar/severity: description` comment line, the rule id, `enabled`, then
// threshold/severity/options only when the descriptor declares them. Omitting absent keys keeps
// the generated file aligned with the descriptor's actual contract.
function renderRuleEntry(descriptor: RuleDescriptor): string[] {
  const lines: string[] = [];
  lines.push(`  # ${descriptor.pillar}/${descriptor.severity}: ${descriptor.description}`);
  lines.push(`  ${descriptor.ruleId}:`);
  lines.push("    enabled: true");
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
 * Decide whether the analyse/summary actions should prompt the user to run `init`.
 *
 * Returns true only when every gate passes: interaction is allowed, output isn't suppressed, the
 * user hasn't already opted in (--config) or out (--no-config) of config loading, all three
 * standard streams are TTYs (stdin to type, stderr to display, stdout to confirm the run is not
 * piping machine output to a downstream consumer), and no supported config file is already
 * present at the project root.
 *
 * @param context CLI-collected state needed to make the decision.
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
 * Ask the user a yes/no question on stderr and return their answer.
 *
 * Defaults to "no" when the user just presses enter so the prompt is safe to dismiss. Reads from
 * stdin; closes the readline interface in a finally so a Ctrl-C exits cleanly.
 *
 * @param question Prompt text written to stderr verbatim.
 * @returns True when the user typed y or yes (case-insensitive); false otherwise.
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
