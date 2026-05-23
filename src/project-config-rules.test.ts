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
      ".gruff.yml": `allowlists:
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
      ".gruff.json": JSON.stringify({ rules: { "security.eval-call": { enabled: false } } }),
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
      ".gruff-ts.yaml": `paths:
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
