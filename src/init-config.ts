// Renders the default .gruff-ts.yaml file from the rule descriptor registry so `gruff-ts init`
// can drop a config into a fresh project that mirrors the analyser's effective defaults.
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";
import { defaultConfigPath, loadConfig } from "./config.ts";
import { ruleDescriptors } from "./rules.ts";
import type { RuleDescriptor } from "./types.ts";

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
const DEFAULT_ACCEPTED_ABBREVIATIONS: readonly string[] = ["id", "db", "fs", "io", "ui", "tx", "rx"];

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
 * Render the default .gruff-ts.yaml content from the rule descriptor registry.
 *
 * @param ignoredPaths Optional `paths.ignore` entries to inject verbatim (block-sequence form). The
 *   `gruff-ts init --force` flow forwards the existing file's entries so user-curated exclusions
 *   survive regeneration; an empty list emits `ignore: []` for fresh projects.
 * @returns A YAML document string terminated by a trailing newline.
 */
function renderDefaultConfig(ignoredPaths: readonly string[] = []): string {
  return [renderPathsSection(ignoredPaths), "", renderAllowlistsSection(), "", renderRulesSection()].join("\n") + "\n";
}

/**
 * Write the default config to `<projectRoot>/.gruff-ts.yaml`. Refuses to clobber when ANY supported
 * config file is present (the four-name precedence list in `DEFAULT_CONFIG_FILES`), not just
 * `.gruff-ts.yaml` - otherwise `init` would silently create a higher-precedence file alongside an
 * existing `.gruff.yaml` / `.gruff.yml` / `.gruff.json` and quietly change the effective config.
 * When overwriting an existing `.gruff-ts.yaml`, the file's `paths.ignore` entries are preserved
 * so `init --force` does not erase project-specific recursive-scan exclusions.
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
  const preservedIgnoredPaths = targetExists ? readExistingIgnoredPaths(projectRoot) : [];
  writeFileSync(targetPath, renderDefaultConfig(preservedIgnoredPaths));
  return { path: targetPath, status: targetExists ? "overwritten" : "written" };
}

/*
 * Recover the existing file's `paths.ignore` block before `init --force` overwrites it. The
 * try/catch swallows YAML-parse errors and the fallback returns an empty list so a malformed
 * existing config does not block regeneration - the user is opting into clobbering, but the
 * documented contract is that curated ignore entries survive when readable.
 */
function readExistingIgnoredPaths(projectRoot: string): readonly string[] {
  try {
    const config = loadConfig(projectRoot, {
      paths: [],
      shouldSkipConfig: false,
      format: "text",
      failOn: "none",
      shouldIncludeIgnored: false,
      shouldSkipBaseline: true,
    });
    return config.ignoredPaths;
  } catch {
    return [];
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

// `acceptedAbbreviations` is emitted as a block sequence for reviewability; the seven naming
// allowlists below it stay commented out so users see the override knobs without changing defaults.
function renderAllowlistsSection(): string {
  return [
    "allowlists:",
    "  acceptedAbbreviations:",
    ...DEFAULT_ACCEPTED_ABBREVIATIONS.map((abbreviation) => `    - ${abbreviation}`),
    "  secretPreviews: []",
    "  # Names that trigger naming.generic-function. Each key replaces the built-in",
    "  # default when present; an empty list disables that rule's blacklist branch.",
    "  # Default: [process, handle, doit, run, execute, manage]",
    "  # bannedGenericNames: [process, handle, doit, run, execute, manage]",
    "  # Accepted prefixes for boolean identifiers. Names without one of these",
    "  # prefixes trigger naming.boolean-prefix.",
    "  # Default: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires]",
    "  # booleanPrefixes: [is, has, can, should, does, did, was, will, may, in, scan, supports, requires]",
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
