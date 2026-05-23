// Behavioural coverage for `gruff-ts init`: registry parity, opt-in handling, option-default drift
// guard, parser round-trip, and the CLI overwrite-guard contract.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "./config.ts";
import { DEFAULT_CONFIG_FILE_NAME, OPT_IN_RULE_IDS, RULE_OPTION_DEFAULTS, renderDefaultConfig, shouldPromptForInit } from "./init-config.ts";
import type { InitPromptContext } from "./init-config.ts";
import { ruleDescriptors } from "./rules.ts";
import { REPO_ROOT } from "./test-fixtures.ts";
import type { AnalysisOptions } from "./types.ts";

test("renderDefaultConfig includes every descriptor rule id", () => {
  const yaml = renderDefaultConfig();
  for (const descriptor of ruleDescriptors()) {
    assert.equal(yaml.includes(`  ${descriptor.ruleId}:`), true, `missing rule entry for ${descriptor.ruleId}`);
  }
});

test("renderDefaultConfig emits opt-in rules as enabled:false and others as enabled:true", () => {
  const yaml = renderDefaultConfig();
  const ruleBlocks = parseRuleBlocks(yaml);
  for (const descriptor of ruleDescriptors()) {
    const block = ruleBlocks.get(descriptor.ruleId);
    assert.notEqual(block, undefined, `no parsed block for ${descriptor.ruleId}`);
    const expected = OPT_IN_RULE_IDS.has(descriptor.ruleId) ? "false" : "true";
    assert.equal(block?.get("enabled"), expected, `enabled mismatch for ${descriptor.ruleId}`);
  }
});

test("renderDefaultConfig emits threshold and severity only for rules with descriptor thresholds", () => {
  const yaml = renderDefaultConfig();
  const ruleBlocks = parseRuleBlocks(yaml);
  for (const descriptor of ruleDescriptors()) {
    const block = ruleBlocks.get(descriptor.ruleId);
    if (typeof descriptor.threshold === "number") {
      assert.equal(block?.get("threshold"), String(descriptor.threshold), `threshold mismatch for ${descriptor.ruleId}`);
      assert.equal(block?.get("severity"), descriptor.severity, `severity mismatch for ${descriptor.ruleId}`);
    } else {
      assert.equal(block?.has("threshold"), false, `unexpected threshold for ${descriptor.ruleId}`);
      assert.equal(block?.has("severity"), false, `unexpected severity for ${descriptor.ruleId}`);
    }
  }
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
    for (const descriptor of ruleDescriptors()) {
      const ruleOverride = config.rules.get(descriptor.ruleId);
      assert.notEqual(ruleOverride, undefined, `loadConfig dropped ${descriptor.ruleId}`);
      assert.equal(ruleOverride?.enabled, !OPT_IN_RULE_IDS.has(descriptor.ruleId), `enabled state mismatch for ${descriptor.ruleId}`);
    }
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("gruff-ts init writes the default config, refuses to overwrite, and respects --force", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-init-cli-"));
  try {
    const firstRun = execFileSync(join(REPO_ROOT, "bin/gruff-ts"), ["init"], { cwd: projectRoot, encoding: "utf8" });
    const configPath = join(projectRoot, DEFAULT_CONFIG_FILE_NAME);
    assert.match(firstRun, new RegExp(`^Wrote .*${DEFAULT_CONFIG_FILE_NAME}\n$`));
    const firstContent = readFileSync(configPath, "utf8");
    assert.equal(firstContent, renderDefaultConfig());

    writeFileSync(configPath, "# user edits\n");
    const refused = spawnSync(join(REPO_ROOT, "bin/gruff-ts"), ["init"], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(refused.status, 1, "second init must exit non-zero without --force");
    assert.equal(refused.stdout, "");
    assert.match(refused.stderr, /Refusing to overwrite existing config/);
    assert.equal(readFileSync(configPath, "utf8"), "# user edits\n", "second init must not touch the file");

    const overwritten = execFileSync(join(REPO_ROOT, "bin/gruff-ts"), ["init", "--force"], { cwd: projectRoot, encoding: "utf8" });
    assert.match(overwritten, new RegExp(`^Overwrote .*${DEFAULT_CONFIG_FILE_NAME}\n$`));
    assert.equal(readFileSync(configPath, "utf8"), renderDefaultConfig());
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
      join(REPO_ROOT, "bin/gruff-ts"),
      ["--no-interaction", "analyse", "--fail-on=none", "--no-baseline", "."],
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
    isStderrTty: true,
  };
}

// Minimal YAML walker that picks each "  ruleId:" block and the "    key: value" pairs under it.
// Avoids loadConfig because some assertions need to inspect the literal rendered shape (e.g.
// whether `threshold` is absent), not the post-overlay Config object.
function parseRuleBlocks(yaml: string): Map<string, Map<string, string>> {
  const blocks = new Map<string, Map<string, string>>();
  let currentRuleId: string | undefined;
  let isInRules = false;
  for (const line of yaml.split("\n")) {
    if (line.trim() === "rules:") {
      isInRules = true;
      continue;
    }
    if (!isInRules || line.startsWith("#")) {
      continue;
    }
    const ruleMatch = line.match(/^ {2}([a-z-]+\.[a-z0-9-]+):\s*$/);
    if (ruleMatch) {
      currentRuleId = ruleMatch[1];
      blocks.set(currentRuleId ?? "", new Map());
      continue;
    }
    const fieldMatch = line.match(/^ {4}([a-zA-Z]+):\s*(\S.*)?$/);
    if (fieldMatch && currentRuleId && fieldMatch[2] !== undefined) {
      blocks.get(currentRuleId)?.set(fieldMatch[1] ?? "", fieldMatch[2]);
    }
  }
  return blocks;
}

// Extracts `optionNumber(<varName>.config | config, "ruleId", "key", <number>)` defaults from
// rule implementation sources. Mirrors the parsing approach used by rule-catalogue.test.ts.
function parseOptionNumberDefaults(source: string): Map<string, Map<string, number>> {
  const usages = new Map<string, Map<string, number>>();
  for (const match of source.matchAll(/optionNumber\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*"([^"]+)",\s*(-?\d+(?:\.\d+)?)\)/g)) {
    const ruleId = match[1] ?? "";
    const key = match[2] ?? "";
    const value = Number(match[3] ?? "0");
    const ruleDefaults = usages.get(ruleId) ?? new Map<string, number>();
    ruleDefaults.set(key, value);
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
