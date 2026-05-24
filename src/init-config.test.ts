// Behavioural coverage for `gruff-ts init`: registry parity, enabled-state handling, option-default drift
// guard, parser round-trip, and the CLI overwrite-guard contract.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "./config.ts";
import { DEFAULT_CONFIG_FILE_NAME, RULE_OPTION_DEFAULTS, renderDefaultConfig, shouldPromptForInit } from "./init-config.ts";
import type { InitPromptContext } from "./init-config.ts";
import { ruleDescriptors } from "./rules.ts";
import { REPO_ROOT } from "./test-fixtures.ts";
import type { AnalysisOptions, Config } from "./types.ts";

test("renderDefaultConfig includes every descriptor rule id", () => {
  const yaml = renderDefaultConfig();
  assertDefaultConfigIncludesEveryDescriptor(yaml);
});

test("renderDefaultConfig emits every descriptor rule as enabled:true", () => {
  const yaml = renderDefaultConfig();
  assertDefaultConfigOptInStates(yaml);
});

test("renderDefaultConfig emits threshold and severity only for rules with descriptor thresholds", () => {
  const yaml = renderDefaultConfig();
  assertDefaultConfigThresholdFields(yaml);
});

test("RULE_OPTION_DEFAULTS mirrors live optionNumber call-site defaults", () => {
  // The init renderer hardcodes option defaults because RuleDescriptor only carries optionKeys,
  // not values. Drift between this table and the rule implementations would make `gruff-ts init`
  // produce subtly-wrong starter config; assert parity by parsing the call sites directly.
  const implementationSources = ["src/analyser.ts", "src/project-rules.ts"].map((path) => readFileSync(join(REPO_ROOT, path), "utf8")).join("\n");
  const implementationDefaults = parseOptionNumberDefaults(implementationSources);
  assert.deepEqual(normalizeOptionDefaults(RULE_OPTION_DEFAULTS), implementationDefaults);
});

test("renderDefaultConfig round-trips through loadConfig with every rule registered", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-init-"));
  try {
    writeFileSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME), renderDefaultConfig());
    const config = loadConfig(projectRoot, baseOptions());
    assertLoadedConfigContainsEveryRule(config.rules);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("gruff-ts init writes the default config, refuses to overwrite, and respects --force", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-init-cli-"));
  try {
    const firstRun = execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "init"], { cwd: projectRoot, encoding: "utf8" });
    const configPath = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
    assert.match(firstRun, new RegExp(`^Wrote .*${DEFAULT_CONFIG_FILE_NAME}\\n\\nNext: generate an adoption baseline with:\\n  gruff-ts analyse \\. --generate-baseline gruff-baseline\\.json --fail-on=none\\nThen gate new findings with:\\n  gruff-ts analyse \\. --baseline gruff-baseline\\.json --fail-on=warning\\n$`));
    const firstContent = readFileSync(configPath, "utf8");
    assert.equal(firstContent, renderDefaultConfig());
    assert.match(firstContent, /# Recursive scans already respect \.gitignore/);
    assert.match(firstContent, /#   - "src\/generated\/\*\*"/);

    writeFileSync(configPath, "# user edits\n");
    const refused = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "init"], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(refused.status, 1, "second init must exit non-zero without --force");
    assert.equal(refused.stdout, "");
    assert.match(refused.stderr, /Refusing to overwrite existing config/);
    assert.equal(readFileSync(configPath, "utf8"), "# user edits\n", "second init must not touch the file");

    const overwritten = execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "init", "--force"], { cwd: projectRoot, encoding: "utf8" });
    assert.match(overwritten, new RegExp(`^Overwrote .*${DEFAULT_CONFIG_FILE_NAME}\\n\\nNext: generate an adoption baseline with:`));
    assert.equal(readFileSync(configPath, "utf8"), renderDefaultConfig());
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("gruff-ts init refuses to write .gruff-ts.yaml when a non-canonical supported config already exists", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-init-precedence-"));
  try {
    const incumbentPath = join(projectRoot, ".gruff.yaml");
    writeFileSync(incumbentPath, "rules: {}\n");

    const refused = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "init"], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(refused.status, 1, "init must refuse so .gruff-ts.yaml does not silently take precedence");
    assert.equal(refused.stdout, "");
    assert.match(refused.stderr, /Refusing to overwrite existing config: .*\.gruff\.yaml/);
    assert.equal(existsSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME)), false, "must not create the higher-precedence file");
    assert.equal(readFileSync(incumbentPath, "utf8"), "rules: {}\n", "incumbent config must remain untouched");
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("renderDefaultConfig preserves passed paths.ignore entries as a block sequence", () => {
  const yaml = renderDefaultConfig([".agents/**", ".claude/**", "fixtures/**"]);
  assert.match(yaml, /^paths:\n(?:  #.*\n)+  ignore:\n    - "\.agents\/\*\*"\n    - "\.claude\/\*\*"\n    - "fixtures\/\*\*"\n/);
});

test("gruff-ts init --force preserves the existing paths.ignore entries", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-init-preserve-"));
  try {
    const configPath = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
    writeFileSync(configPath, renderDefaultConfig([".agents/**", ".goat-flow/**", "fixtures/**"]));

    const overwritten = execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "init", "--force"], { cwd: projectRoot, encoding: "utf8" });
    assert.match(overwritten, /^Overwrote /);

    const newContent = readFileSync(configPath, "utf8");
    assert.equal(newContent, renderDefaultConfig([".agents/**", ".goat-flow/**", "fixtures/**"]));
    assert.match(newContent, /  ignore:\n    - "\.agents\/\*\*"\n    - "\.goat-flow\/\*\*"\n    - "fixtures\/\*\*"/);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("shouldPromptForInit returns true only when every gate passes", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-prompt-"));
  try {
    assert.equal(shouldPromptForInit(promptContext(projectRoot)), true, "baseline missing-config case must prompt");

    writeFileSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME), "rules: {}\n");
    assert.equal(shouldPromptForInit(promptContext(projectRoot)), false, "existing config must suppress prompt");
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("shouldPromptForInit suppresses on every individual opt-out gate", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-prompt-gates-"));
  try {
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), isInteractionAllowed: false }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), isOutputSuppressed: true }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), shouldSkipConfig: true }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), hasExplicitConfig: true }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), isStdinTty: false }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), isStdoutTty: false }), false);
    assert.equal(shouldPromptForInit({ ...promptContext(projectRoot), isStderrTty: false }), false);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("gruff-ts analyse --no-interaction skips the init prompt in a config-less project", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-prompt-cli-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), "export const value = 1;\n");
    const result = spawnSync(
      "bash",
      [join(REPO_ROOT, "bin/gruff-ts"), "--no-interaction", "analyse", "--fail-on=none", "--no-baseline", "."],
      { cwd: projectRoot, encoding: "utf8" },
    );
    assert.equal(result.status, 0, `analyse should succeed without prompting, stderr=${result.stderr}`);
    assert.equal(result.stderr.includes("Run 'gruff-ts init'"), false, "must not print the init prompt with --no-interaction");
    assert.equal(existsSync(join(projectRoot, DEFAULT_CONFIG_FILE_NAME)), false, "must not write a config when prompt is suppressed");
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

// Returns the projectRoot-anchored AnalysisOptions needed to drive loadConfig in tests.
function baseOptions(): AnalysisOptions {
  return { paths: ["."], shouldSkipConfig: false, format: "text", failOn: "none", shouldIncludeIgnored: false, shouldSkipBaseline: true };
}

// Baseline context used by the prompt-predicate tests; individual cases override one field at a time.
function promptContext(projectRoot: string): InitPromptContext {
  return {
    projectRoot,
    shouldSkipConfig: false,
    hasExplicitConfig: false,
    isInteractionAllowed: true,
    isOutputSuppressed: false,
    isStdinTty: true,
    isStdoutTty: true,
    isStderrTty: true,
  };
}

// Keeps descriptor-registry parity assertions outside test bodies so the test remains declarative.
function assertDefaultConfigIncludesEveryDescriptor(yaml: string): void {
  for (const descriptor of ruleDescriptors()) {
    assert.equal(yaml.includes(`  ${descriptor.ruleId}:`), true, `missing rule entry for ${descriptor.ruleId}`);
  }
}

// Verifies default enabled states against the literal rendered YAML, before loadConfig overlays defaults.
function assertDefaultConfigOptInStates(yaml: string): void {
  for (const descriptor of ruleDescriptors()) {
    const block = renderedRuleBlock(yaml, descriptor.ruleId);
    assert.equal(renderedRuleField(block, "enabled"), "true", `enabled mismatch for ${descriptor.ruleId}`);
  }
}

// Checks threshold fields on the rendered document so absent keys stay absent in starter config.
function assertDefaultConfigThresholdFields(yaml: string): void {
  for (const descriptor of ruleDescriptors()) {
    const block = renderedRuleBlock(yaml, descriptor.ruleId);
    if (typeof descriptor.threshold === "number") {
      assert.equal(renderedRuleField(block, "threshold"), String(descriptor.threshold), `threshold mismatch for ${descriptor.ruleId}`);
      assert.equal(renderedRuleField(block, "severity"), descriptor.severity, `severity mismatch for ${descriptor.ruleId}`);
    } else {
      assert.equal(renderedRuleField(block, "threshold"), undefined, `unexpected threshold for ${descriptor.ruleId}`);
      assert.equal(renderedRuleField(block, "severity"), undefined, `unexpected severity for ${descriptor.ruleId}`);
    }
  }
}

// Confirms parser round-trip coverage without putting registry loops directly in the test body.
function assertLoadedConfigContainsEveryRule(ruleOverrides: Config["rules"]): void {
  for (const descriptor of ruleDescriptors()) {
    const ruleOverride = ruleOverrides.get(descriptor.ruleId);
    assert.notEqual(ruleOverride, undefined, `loadConfig dropped ${descriptor.ruleId}`);
    assert.equal(ruleOverride?.enabled, true, `enabled state mismatch for ${descriptor.ruleId}`);
  }
}

// Pulls one rule block by marker rather than parsing the whole YAML document.
function renderedRuleBlock(yaml: string, ruleId: string): string {
  const marker = `  ${ruleId}:\n`;
  const start = yaml.indexOf(marker);
  assert.notEqual(start, -1, `no rendered block for ${ruleId}`);
  const bodyStart = start + marker.length;
  const nextRuleOffset = yaml.slice(bodyStart).search(/\n  [a-z-]+\.[a-z0-9-]+:\n/);
  const end = nextRuleOffset === -1 ? yaml.length : bodyStart + nextRuleOffset;
  return yaml.slice(start, end);
}

// Reads a scalar field from a rendered rule block without normalising the document through loadConfig.
function renderedRuleField(block: string, key: string): string | undefined {
  const match = block.match(new RegExp(`^    ${key}:\\s*(\\S.*)$`, "m"));
  return match?.[1];
}

// Extracts `optionNumber(<varName>.config | config, "ruleId", "key", <number>)` defaults from
// rule implementation sources. Mirrors the parsing approach used by rule-catalogue.test.ts.
function parseOptionNumberDefaults(source: string): Map<string, Map<string, number>> {
  const usages = new Map<string, Map<string, number>>();
  for (const match of source.matchAll(/optionNumber\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*"([^"]+)",\s*(-?\d+(?:\.\d+)?)\)/g)) {
    const ruleId = match[1] ?? "";
    const key = match[2] ?? "";
    const defaultValue = Number(match[3] ?? "0");
    const ruleDefaults = usages.get(ruleId) ?? new Map<string, number>();
    ruleDefaults.set(key, defaultValue);
    usages.set(ruleId, ruleDefaults);
  }
  return sortNestedMap(usages);
}

// Converts the readonly hardcoded table into the same Map<ruleId, Map<key, number>> shape so the
// drift assertion compares like-for-like with deepEqual.
function normalizeOptionDefaults(defaults: Readonly<Record<string, Readonly<Record<string, number>>>>): Map<string, Map<string, number>> {
  const result = new Map<string, Map<string, number>>();
  for (const [ruleId, options] of Object.entries(defaults)) {
    result.set(ruleId, new Map(Object.entries(options)));
  }
  return sortNestedMap(result);
}

// Deterministic key ordering so deepEqual does not fail on insertion-order differences.
function sortNestedMap(input: Map<string, Map<string, number>>): Map<string, Map<string, number>> {
  return new Map(
    [...input.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([ruleId, options]) => [ruleId, new Map([...options.entries()].sort(([left], [right]) => left.localeCompare(right)))]),
  );
}
