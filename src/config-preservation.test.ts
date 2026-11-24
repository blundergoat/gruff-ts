// Checks which project settings survive regeneration when a user runs `init --force`.
//
// Valid ignored paths, command gates, and sensitive exclusions carry forward from older files.
// An invalid entry is left behind so the regenerated config can load and the user's other choices survive.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { loadConfig, minimumSeverityFor } from "./config.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { extractPreservedConfigFields } from "./config-preservation.ts";
import { migrateConfigText } from "./migrate-config.ts";

// Creates a temporary project directory and passes its path to the scenario callback so writes stay isolated between tests.
// Returns nothing. It attempts to remove the whole directory even if the callback throws.
function withTempProjectRoot(action: (path: string) => void): void {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-config-preservation-"));
  try {
    action(projectRoot);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
}

test("extractPreservedConfigFields reads paths.ignore from a pre-schemaVersion YAML config", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "paths:\n  ignore:\n    - \"legacy/**\"\n    - \"vendored/**\"\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.deepEqual(preserved.ignoredPaths, ["legacy/**", "vendored/**"]);
    assert.equal(preserved.failOn.size, 0);
  });
});

test("extractPreservedConfigFields preserves valid gate entries under either spelling and drops the rest", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "minimumSeverity:\n  analyse: warning\n  summary: garbage\n  dashboard: error\n  report: none\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.equal(preserved.failOn.get("analyse"), "warning");
    assert.equal(preserved.failOn.get("report"), "none");
    assert.equal(preserved.failOn.has("summary"), false);
    assert.equal(preserved.failOn.has("dashboard" as never), false);

    // A 0.6.0 file spells the same block failOn, and a file carrying both is read from the current key.
    writeFileSync(configPath, "failOn:\n  analyse: error\nminimumSeverity: warning\n");
    assert.equal(extractPreservedConfigFields(configPath).failOn.get("analyse"), "error");
  });
});

test("extractPreservedConfigFields returns empty fields for an empty config file", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(configPath, "rules: {}\n");

    const preserved = extractPreservedConfigFields(configPath);

    assert.deepEqual(preserved.ignoredPaths, []);
    assert.equal(preserved.failOn.size, 0);
  });
});

// Proves the carry-over bundle keeps every well-formed reviewed suppression, including the optional
// symbol, and drops an entry missing a required field so the strict parser reports it at load time.
// Writes a `.gruff-ts.yaml` into a temporary project root and removes that root afterwards.
test("extractPreservedConfigFields carries reviewed sensitive exclusions through regeneration", () => {
  withTempProjectRoot((projectRoot) => {
    const configPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(
      configPath,
      [
        "sensitiveExclusions:",
        "  - rule: sensitive-data.aws-access-key",
        "    path: src/fixtures/sample.ts",
        "    reason: Synthetic key used by the loader fixture.",
        "  - rule: sensitive-data.jwt-token",
        "    path: src/fixtures/token.ts",
        "    symbol: Fixtures.sessionToken",
        "    reason: Synthetic token used by the session fixture.",
        "  - rule: sensitive-data.private-key",
        "    path: src/fixtures/key.ts",
        "  - rule: sensitive-data.aws-access-key",
        "    path: src/fixtures/scoped.ts",
        "    symbol: 123",
        "    reason: An invalid symbol must never become a file-wide exclusion.",
        "",
      ].join("\n"),
    );

    const preserved = extractPreservedConfigFields(configPath);

    assert.equal(preserved.sensitiveExclusions.length, 2);
    assert.deepEqual(preserved.sensitiveExclusions[0], {
      rule: "sensitive-data.aws-access-key",
      path: "src/fixtures/sample.ts",
      reason: "Synthetic key used by the loader fixture.",
    });
    assert.equal(preserved.sensitiveExclusions[1]?.symbol, "Fixtures.sessionToken");
  });
});

/**
 * Loads one written config file through the full 0.6.0 config loader for migration round-trip verification.
 *
 * @param projectRoot - temporary project root holding the written config file
 * @param configPath - path to the migrated YAML or JSON config file
 * @returns Resolved 0.6.0 configuration loaded from `configPath`.
 */
function loadMigratedConfig(projectRoot: string, configPath: string) {
  return loadConfig(projectRoot, {
    paths: [projectRoot],
    config: configPath,
    shouldSkipConfig: false,
    format: "text",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedScope: "symbol",
    shouldSkipBaseline: true,
  });
}

// Fixture purpose: proves YAML migration strips retired 0.5 rules, allowlists, secretPreviews, and retired sensitive exclusions.
// Writes a temporary .gruff-ts.yaml to verify loadConfig acceptance and removes the directory afterward.
test("migrateConfigText prunes retired 0.5 rules, allowlist keys, and sensitive exclusions from YAML and passes loadConfig", () => {
  const legacyYaml = [
    "# Keep team header comment.",
    "schemaVersion: gruff-ts.config.v0.1",
    "minimumSeverity:",
    "  analyse: warning",
    "  summary: none",
    "allowlists:",
    "  acceptedAbbreviations:",
    "    - id",
    "    - cli",
    "  secretPreviews:",
    "    mode: masked",
    "  acceptedBooleanNames:",
    "    - active",
    "  acceptedCasingPairs:",
    "    - foo:bar",
    "  bannedGenericNames:",
    "    - helper",
    "  booleanPrefixes:",
    "    - is",
    "  hungarianPrefixes:",
    "    - str",
    "  knownAcronyms:",
    "    - CLI",
    "  negativeBooleanAllowed:",
    "    - disabled",
    "sensitiveExclusions:",
    "  - rule: sensitive-data.high-entropy-string",
    "    path: src/old-fixture.ts",
    "    reason: Retired 0.5 entropy suppression.",
    "  - rule: sensitive-data.aws-access-key",
    "    path: src/test-fixtures.ts",
    "    reason: Active reviewed fixture suppression.",
    "rules:",
    "  docs.stale-comment:",
    "    enabled: false",
    "  naming.generic-function:",
    "    enabled: true",
    "    severity: advisory",
    "  waste.unused-parameter:",
    "    enabled: false",
    "  docs.missing-return-tag:",
    "    enabled: true",
    "    options:",
    "      everyCallable: true",
    "",
  ].join("\n");

  const migration = migrateConfigText(legacyYaml, "yaml");
  assert.equal(migration.text.includes("# Keep team header comment."), true);
  assert.equal(migration.text.includes("docs.stale-comment"), false);
  assert.equal(migration.text.includes("naming.generic-function"), false);
  assert.equal(migration.text.includes("waste.unused-parameter"), false);
  assert.equal(migration.text.includes("knownAcronyms"), false);
  assert.equal(migration.text.includes("secretPreviews"), false);
  assert.equal(migration.text.includes("sensitive-data.high-entropy-string"), false);
  assert.equal(migration.text.includes("sensitive-data.aws-access-key"), true);
  assert.equal(migration.changes.some((change) => change.description.includes("docs.stale-comment")), true);
  assert.equal(migration.changes.some((change) => change.description.includes("knownAcronyms")), true);
  assert.equal(migration.changes.some((change) => change.description.includes("sensitive-data.high-entropy-string")), true);

  withTempProjectRoot((projectRoot) => {
    const outputPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(outputPath, migration.text);
    const loaded = loadMigratedConfig(projectRoot, outputPath);
    assert.equal(minimumSeverityFor(loaded, "analyse"), "warning");
    assert.equal(loaded.acceptedAbbreviations.has("cli"), true);
    assert.equal(loaded.sensitiveExclusions.length, 1);
    assert.equal(loaded.sensitiveExclusions[0]?.rule, "sensitive-data.aws-access-key");
  });
});

// Fixture purpose: proves emptied YAML allowlists, rules, and sensitiveExclusions sections rewrite to valid {} or [] literals.
// Writes a temporary .gruff-ts.yaml to verify loadConfig acceptance and removes the directory afterward.
test("migrateConfigText rewrites emptied YAML sensitiveExclusions, allowlists, and rules sections to empty literals", () => {
  const legacyYaml = [
    "schemaVersion: gruff-ts.config.v0.1",
    "allowlists: # keep trailing comment",
    "  secretPreviews:",
    "    mode: masked",
    "  knownAcronyms:",
    "    - CLI",
    "sensitiveExclusions:",
    "  - rule: sensitive-data.hardcoded-env-value",
    "    path: src/env.ts",
    "    reason: Retired 0.5 exclusion.",
    "  - rule: sensitive-data.high-entropy-string",
    "    path: src/entropy.ts",
    "    reason: Retired 0.5 entropy exclusion.",
    "rules:",
    "  docs.stale-comment:",
    "    enabled: false",
    "",
  ].join("\n");

  const migration = migrateConfigText(legacyYaml, "yaml");
  assert.match(migration.text, /^allowlists: \{\} # keep trailing comment$/m);
  assert.match(migration.text, /^sensitiveExclusions: \[\]$/m);
  assert.match(migration.text, /^rules: \{\}$/m);
  withTempProjectRoot((projectRoot) => {
    const outputPath = join(projectRoot, ".gruff-ts.yaml");
    writeFileSync(outputPath, migration.text);
    const loaded = loadMigratedConfig(projectRoot, outputPath);
    assert.deepEqual(loaded.sensitiveExclusions, []);
    assert.equal(loaded.rules.size, 0);
  });
});

// Fixture purpose: proves JSON migration strips retired 0.5 rules, allowlists, secretPreviews, and retired sensitive exclusions.
// Writes a temporary .gruff-ts.json to verify loadConfig acceptance and removes the directory afterward.
test("migrateConfigText prunes retired 0.5 rules, allowlist keys, and sensitive exclusions from JSON and passes loadConfig", () => {
  const legacyJson = JSON.stringify(
    {
      minimumSeverity: { analyse: "error" },
      allowlists: {
        acceptedAbbreviations: ["id", "cli"],
        secretPreviews: true,
        knownAcronyms: ["API"],
        booleanPrefixes: ["is"],
      },
      sensitiveExclusions: [
        { rule: "sensitive-data.high-entropy-string", path: "src/old.ts", reason: "Retired entropy rule." },
        { rule: "sensitive-data.aws-access-key", path: "src/fixture.ts", reason: "Reviewed synthetic key." },
      ],
      rules: {
        "docs.useless-docblock": { enabled: false },
        "security.floating-promise": { enabled: true },
        "docs.missing-param-tag": { enabled: true },
      },
    },
    null,
    2,
  );

  const migration = migrateConfigText(legacyJson, "json");
  assert.equal(migration.changes.some((change) => change.description.includes("docs.useless-docblock")), true);
  assert.equal(migration.changes.some((change) => change.description.includes("knownAcronyms")), true);
  assert.equal(migration.changes.some((change) => change.description.includes("sensitive-data.high-entropy-string")), true);

  withTempProjectRoot((projectRoot) => {
    const outputPath = join(projectRoot, ".gruff-ts.json");
    writeFileSync(outputPath, migration.text);
    const loaded = loadMigratedConfig(projectRoot, outputPath);
    assert.equal(minimumSeverityFor(loaded, "analyse"), "error");
    assert.equal(loaded.sensitiveExclusions.length, 1);
    assert.equal(loaded.sensitiveExclusions[0]?.rule, "sensitive-data.aws-access-key");
  });
});

test("migrateConfigText and CLI reject unknown non-retired keys before writing output", () => {
  const typoYaml = [
    "schemaVersion: gruff-ts.config.v0.1",
    "rules:",
    "  docs.not-a-real-rule:",
    "    enabled: false",
    "",
  ].join("\n");
  assert.throws(() => migrateConfigText(typoYaml, "yaml"), ConfigLoadError);

  const typoJson = JSON.stringify({
    schemaVersion: "gruff-ts.config.v0.1",
    allowlists: { bogusCustomKey: ["x"] },
  });
  assert.throws(() => migrateConfigText(typoJson, "json"), ConfigLoadError);

  withTempProjectRoot((projectRoot) => {
    const inputPath = join(projectRoot, "old.yaml");
    const outputPath = join(projectRoot, "migrated.yaml");
    writeFileSync(inputPath, typoYaml);
    const run = spawnSync("./bin/gruff-ts", ["migrate-config", "--config", inputPath, "--output", outputPath], { encoding: "utf8" });
    assert.equal(run.status, 2);
    assert.equal(existsSync(outputPath), false);
    assert.match(run.stderr, /docs\.not-a-real-rule/);
  });
});
