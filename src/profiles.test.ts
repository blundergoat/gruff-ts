// Named-profile fixture matrix: built-in preset behaviour, extends-chain flattening, child-wins
// overrides, CLI-over-config precedence, and the load-time validation paths. The determinism and
// cycle-detection proof tests live in cli.test.ts alongside the other config-loading tests; everything
// else that exercises the profile resolver is here.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cwd } from "node:process";
import test from "node:test";
import type { AnalysisReport } from "./cli.ts";
import { resolveProfile } from "./config.ts";
import { BUILT_IN_PROFILES, isKnownRuleId, profileSummaries } from "./profiles.ts";
import { analyseProject, writeFixtureFiles } from "./test-fixtures.ts";

// A small file carrying one naming smell, one security smell, and one maintainability smell, used to
// prove which pillars a profile enables.
const PROFILE_PILLAR_FIXTURE = { "bad.ts": `const xy = 1;\neval("danger");\nconsole.log(xy);\n` };

test("profile minimal enables only the security and sensitive-data pillars", () => {
  const report = analyseProject(PROFILE_PILLAR_FIXTURE, { profile: "gruff.minimal" });
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), true, "security stays enabled under minimal");
  assert.equal(report.findings.some((finding) => finding.pillar === "naming"), false, "naming is disabled under minimal");
  assert.equal(report.findings.some((finding) => finding.pillar === "maintainability"), false, "maintainability is disabled under minimal");
  assert.ok(report.findings.every((finding) => finding.pillar === "security" || finding.pillar === "sensitive-data"), "minimal yields only security/sensitive-data findings");
});

test("profile recommended reproduces the zero-config rule mix", () => {
  const ruleMix = (report: AnalysisReport): string[] => report.findings.map((finding) => finding.ruleId).sort();
  const recommended = analyseProject(PROFILE_PILLAR_FIXTURE, { profile: "gruff.recommended" });
  const zeroConfig = analyseProject(PROFILE_PILLAR_FIXTURE, { shouldSkipConfig: true });
  assert.deepEqual(ruleMix(recommended), ruleMix(zeroConfig), "recommended must reproduce zero-config findings exactly");
});

test("profile child overrides a parent threshold", () => {
  // A tiny file recommended would never flag for length; an inline profile that extends recommended and
  // tightens size.file-length to a few lines must flag it, proving the child threshold applied.
  const tinyFile = { "long.ts": `${"const value = 1;\n".repeat(6)}export {};\n` };
  const tightenedConfig = { profile: { extends: "gruff.recommended", rules: { "size.file-length": { threshold: 3 } } } };
  assert.equal(analyseProject(tinyFile, { profile: "gruff.recommended" }).findings.some((finding) => finding.ruleId === "size.file-length"), false, "default threshold leaves the tiny file alone");
  assert.equal(analyseProject(tinyFile, { config: tightenedConfig }).findings.some((finding) => finding.ruleId === "size.file-length"), true, "tightened child threshold fires");
});

test("profile child disables a rule the parent enabled", () => {
  const evalFixture = { "bad.ts": `eval("danger");\n` };
  const disablingConfig = { profile: { extends: "gruff.recommended", rules: { "security.eval-call": { enabled: false } } } };
  assert.equal(analyseProject(evalFixture, { profile: "gruff.recommended" }).findings.some((finding) => finding.ruleId === "security.eval-call"), true, "recommended flags eval");
  assert.equal(analyseProject(evalFixture, { config: disablingConfig }).findings.some((finding) => finding.ruleId === "security.eval-call"), false, "child disable suppresses eval");
});

test("profile extends chain depth 3 applies all overrides", () => {
  // Each level overrides a different rule; the flattened result must carry all three named thresholds.
  const level1FileLength = 3;
  const level2FunctionLength = 4;
  const level3Cyclomatic = 2;
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-profile-chain-"));
  try {
    writeFixtureFiles(dir, {
      "level1.yaml": `extends: ./level2.yaml\nrules:\n  size.file-length:\n    threshold: ${level1FileLength}\n`,
      "level2.yaml": `extends: ./level3.yaml\nrules:\n  size.function-length:\n    threshold: ${level2FunctionLength}\n`,
      "level3.yaml": `extends: gruff.recommended\nrules:\n  complexity.cyclomatic:\n    threshold: ${level3Cyclomatic}\n`,
    });
    const definition = resolveProfile("./level1.yaml", dir);
    assert.equal(definition.rules.get("size.file-length")?.threshold, level1FileLength, "level1 override survives");
    assert.equal(definition.rules.get("size.function-length")?.threshold, level2FunctionLength, "level2 override survives");
    assert.equal(definition.rules.get("complexity.cyclomatic")?.threshold, level3Cyclomatic, "level3 override survives");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("profile missing extends file errors clearly", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-profile-missing-"));
  try {
    assert.throws(() => resolveProfile("./nonexistent.yaml", dir), /Profile extends file not found/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("profile with an unknown rule id errors clearly", () => {
  assert.throws(
    () => resolveProfile({ extends: "gruff.recommended", rules: { "made.up-rule": { enabled: false } } }, cwd()),
    /Unknown rule id in profile: "made\.up-rule"/,
  );
});

test("CLI profile strict overrides a config profile minimal", () => {
  const namingFixture = { "bad.ts": `const xy = 1;\nconsole.log(xy);\n` };
  const minimalConfig = { profile: "gruff.minimal" };
  assert.equal(analyseProject(namingFixture, { config: minimalConfig }).findings.some((finding) => finding.pillar === "naming"), false, "config minimal disables naming");
  assert.equal(analyseProject(namingFixture, { config: minimalConfig, profile: "gruff.strict" }).findings.some((finding) => finding.ruleId === "naming.short-variable"), true, "CLI strict re-enables naming over config minimal");
});

test("built-in profiles reference only catalogue rule ids", () => {
  const offenders = [...BUILT_IN_PROFILES.entries()].flatMap(([name, definition]) => [...definition.rules.keys()].filter((ruleId) => !isKnownRuleId(ruleId)).map((ruleId) => `${name}:${ruleId}`));
  assert.deepEqual(offenders, [], "built-in profiles reference unknown rule ids");
});

test("profile summaries report all three built-ins with monotonic enabled counts", () => {
  const summaries = profileSummaries();
  assert.deepEqual(summaries.map((summary) => summary.name), ["gruff.minimal", "gruff.recommended", "gruff.strict"]);
  const byName = new Map(summaries.map((summary) => [summary.name, summary]));
  const minimal = byName.get("gruff.minimal");
  const recommended = byName.get("gruff.recommended");
  const strict = byName.get("gruff.strict");
  assert.ok(minimal && recommended && strict, "all three summaries present");
  assert.ok(minimal.enabledRuleCount < recommended.enabledRuleCount, "minimal enables fewer rules than recommended");
  assert.equal(recommended.enabledRuleCount, recommended.totalRuleCount, "recommended enables the whole catalogue");
  assert.equal(strict.enabledRuleCount, strict.totalRuleCount, "strict enables the whole catalogue");
  assert.ok(strict.tightenedThresholdCount > 0, "strict tightens at least one threshold");
});
