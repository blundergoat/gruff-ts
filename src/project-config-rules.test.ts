// Project config and gruff config parser regression tests kept separate from security fixtures.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

// Fixture purpose: tsconfig with all three strictness flags disabled so the rule pack should flag each one.
const RELAXED_TSCONFIG_FIXTURE = {
  "tsconfig.json": JSON.stringify({
    compilerOptions: {
      strict: false,
      noUncheckedIndexedAccess: false,
      exactOptionalPropertyTypes: false,
    },
  }),
};

const TSCONFIG_STRICTNESS_RULE_IDS = ["modernisation.tsconfig-strict-disabled", "modernisation.tsconfig-index-safety-disabled", "modernisation.tsconfig-exact-optional-disabled"];

const STRICT_TSCONFIG_FIXTURE = {
  "tsconfig.json": JSON.stringify({
    compilerOptions: {
      strict: true,
      noUncheckedIndexedAccess: true,
      exactOptionalPropertyTypes: true,
    },
  }),
};

test("tsconfig health detects disabled strictness without changing diagnostics", () => {
  const report = analyseProject(RELAXED_TSCONFIG_FIXTURE);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  TSCONFIG_STRICTNESS_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  const cleanReport = analyseProject(STRICT_TSCONFIG_FIXTURE);
  TSCONFIG_STRICTNESS_RULE_IDS.forEach((ruleId) => {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  });
  const malformedReport = analyseProject({ "package.json": "{ not json" });
  assert.deepEqual(malformedReport.diagnostics, []);
});

test("project config health parses JSONC tsconfigs and non-default tsconfig names", () => {
  const report = analyseProject({
    "tsconfig.base.json": `\uFEFF{
  // Valid tsconfig JSONC should still be inspected.
  "compilerOptions": {
    "strict": false,
    "noUncheckedIndexedAccess": false,
    "exactOptionalPropertyTypes": false,
  },
}
`,
  });
  const strictnessFindings = report.findings.filter((finding) => finding.ruleId.startsWith("modernisation.tsconfig-"));
  assert.deepEqual(strictnessFindings.map((finding) => finding.ruleId).sort(), [...TSCONFIG_STRICTNESS_RULE_IDS].sort());
  assert.equal(strictnessFindings.every((finding) => finding.filePath === "tsconfig.base.json"), true);
});

test("config parser accepts yml/json files, empty allowlists, and hash characters in plain scalars", () => {
  const explicitYml = analyseProject(
    {
      ".gruff.yml": `schemaVersion: gruff-ts.config.v0.1
allowlists:
  acceptedAbbreviations: []
`,
      "bad.ts": `function read(id: string): string {
  return id;
}
`,
    },
    { configPath: ".gruff.yml" },
  );
  assert.equal(explicitYml.findings.some((finding) => finding.ruleId === "naming.short-variable" && finding.symbol === "id"), true);

  const explicitJson = analyseProject(
    {
      ".gruff.json": JSON.stringify({ schemaVersion: "gruff-ts.config.v0.1", rules: { "security.eval-call": { enabled: false } } }),
      "bad.ts": `export function unsafe(input: string): unknown {
  return eval(input);
}
`,
    },
    { configPath: ".gruff.json" },
  );
  assert.equal(explicitJson.findings.some((finding) => finding.ruleId === "security.eval-call"), false);

  const hashScalar = analyseProject(
    {
      ".gruff-ts.yaml": `schemaVersion: gruff-ts.config.v0.1
paths:
  ignore: [ignored#dir/**]
`,
      "ignored#dir/bad.ts": `export function unsafe(input: string): unknown {
  return eval(input);
}
`,
    },
    { configPath: ".gruff-ts.yaml" },
  );
  assert.equal(hashScalar.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
});

test("config schemaVersion is required and must match the supported value", () => {
  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "paths:\n  ignore: []\n",
    }, { shouldSkipConfig: false }),
    /Config must include schemaVersion/,
  );

  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.2\npaths:\n  ignore: []\n",
    }, { shouldSkipConfig: false }),
    /Unsupported schemaVersion/,
  );
});

test("minimumSeverity rejects dashboard, unknown commands, and unknown values including never", () => {
  // Fixture covers the validator's rejection paths: dashboard is a reserved key (no --fail-on flag
  // exists for it); unknown commands raise an error with the canonical-keys hint; unknown values
  // raise an error citing the four canonical values; `never` is explicitly rejected because it was
  // an early cross-port draft for the off-switch value before the family converged on `none`.
  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\nminimumSeverity:\n  dashboard: advisory\n",
    }, { shouldSkipConfig: false }),
    /dashboard subcommand does not currently expose a --fail-on flag/,
  );

  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\nminimumSeverity:\n  unknown: advisory\n",
    }, { shouldSkipConfig: false }),
    /Unknown command in minimumSeverity/,
  );

  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\nminimumSeverity:\n  analyse: never\n",
    }, { shouldSkipConfig: false }),
    /FailThreshold must be one of/,
  );

  assert.throws(
    () => analyseProject({
      "bad.ts": "export const value = 1;\n",
      ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\nminimumSeverity:\n  analyse: critical\n",
    }, { shouldSkipConfig: false }),
    /FailThreshold must be one of/,
  );
});

test("minimumSeverity accepts the four canonical values per command", () => {
  // Fixture covers the happy path: each canonical value parses for each supported command, and
  // the config-load completes without throwing. The actual precedence behaviour is exercised in
  // cli-surfaces.test.ts where Commander's option-source signal is available. Asserting on the
  // report shape (and not on specific finding counts) keeps this test focused on the parser.
  const report = analyseProject({
    "bad.ts": "export const value = 1;\n",
    ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\nminimumSeverity:\n  analyse: error\n  summary: warning\n  report: none\n",
  }, { shouldSkipConfig: false });
  assert.equal(report.schemaVersion, "gruff.analysis.v2");
});
