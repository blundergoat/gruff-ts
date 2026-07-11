// Tests for the ConfigLoadError data wrapper used by the CLI's graceful config-error formatter,
// plus the loud rule-config validation contract (unknown ids, alias booleans, malformed options).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ConfigLoadError } from "./config-load-error.ts";
import { analyseProject, REPO_ROOT } from "./test-fixtures.ts";

test("ConfigLoadError stores message and suggestion verbatim", () => {
  // Fixture covers the construction contract: message reaches `error.message`; suggestion is
  // accessible as a readonly field that the CLI's stderr formatter renders alongside the message.
  const error = new ConfigLoadError("missing schemaVersion field", "run init --force");
  assert.equal(error.message, "missing schemaVersion field");
  assert.equal(error.suggestion, "run init --force");
  assert.equal(error.name, "ConfigLoadError");
  assert.equal(error instanceof Error, true);
});

test("rule config rejects unknown ids, alias booleans, and malformed options loudly", () => {
  const files = { "ok.ts": "// File overview: config validation fixture.\nexport const fine = 1;\n" };
  // A misspelled top-level rule id must fail at load time instead of silently no-opping.
  assert.throws(() => analyseProject(files, { config: { rules: { "security.evall-call": { enabled: false } } } }), /Unknown rule id/);
  // YAML 1.2 keeps `no`/`off` (quoted or not) as strings; gruff names the accepted forms instead
  // of silently ignoring the override. Other non-boolean types reach the same rejection.
  assert.throws(() => analyseProject(files, { config: { rules: { "security.eval-call": { enabled: "no" } } } }), /"enabled" must be true or false/);
  assert.throws(() => analyseProject(files, { config: { rules: { "security.eval-call": { enabled: "off" } } } }), /"enabled" must be true or false/);
  assert.throws(() => analyseProject(files, { config: { rules: { "security.eval-call": { enabled: 1 } } } }), /"enabled" must be true or false/);
  // Unknown option keys and non-numeric declared options fail naming the rule's accepted keys.
  assert.throws(() => analyseProject(files, { config: { rules: { "naming.generic-parameter": { options: { minCyclomatik: 3 } } } } }), /accepts options: minCyclomatic, minLineCount, minParameters/);
  assert.throws(() => analyseProject(files, { config: { rules: { "naming.generic-parameter": { options: { minCyclomatic: "three" } } } } }), /must be numeric/);
  assert.throws(() => analyseProject(files, { config: { rules: { "security.eval-call": { options: { anything: 1 } } } } }), /accepts no options/);
  // Valid overrides still round-trip: boolean enabled plus a declared numeric option.
  const valid = analyseProject(files, { config: { rules: { "naming.generic-parameter": { enabled: true, options: { minCyclomatic: 3 } } } } });
  assert.equal(valid.schemaVersion, "gruff.analysis.v2");
});

test("an invalid config rule value exits 2 with a concise error and no stack trace", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-config-error-"));
  try {
    writeFileSync(join(projectRoot, "ok.ts"), "// File overview: config error fixture.\nexport const fine = 1;\n");
    writeFileSync(join(projectRoot, ".gruff-ts.yaml"), "schemaVersion: gruff-ts.config.v0.1\nrules:\n  security.eval-call:\n    enabled: no\n");
    const result = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "analyse", ".", "--fail-on", "none"], { cwd: projectRoot, encoding: "utf8" });
    assert.equal(result.status, 2);
    assert.equal(result.stderr.includes('"enabled" must be true or false'), true);
    assert.equal(/\n\s+at /.test(result.stderr), false);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
