// Config-error tests cover the concise failures users receive before analysis can start.
//
// Fixtures exercise the error wrapper and strict rule settings through both the loader and CLI.
// Retired secret-preview values must always stop safely without echoing user-provided content.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "./config.ts";
import { ConfigLoadError } from "./config-load-error.ts";
import { analyseProject, REPO_ROOT } from "./test-fixtures.ts";
import type { AnalysisOptions } from "./types.ts";

const LEGACY_SECRET_PREVIEWS_ERROR = 'Config key "allowlists.secretPreviews" only accepts an empty list; remove all configured entries because secret previews no longer suppress findings.';
const CONFIG_LOAD_OPTIONS = {
  paths: ["."],
  shouldSkipConfig: false,
  format: "json",
  failOn: "none",
  shouldIncludeIgnored: false,
  changedScope: "symbol",
  shouldSkipBaseline: true,
} satisfies AnalysisOptions;
const INVALID_LEGACY_SECRET_PREVIEW_CASES = [
  ["non-empty-list", "[known-fixture-preview]"],
  ["scalar", "known-fixture-preview"],
  ["empty-object", "{}"],
  ["null", "null"],
  ["blank-entry", '[""]'],
  ["mixed-list", "[known-fixture-preview, 42]"],
] as const;

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
  assert.equal(valid.schemaVersion, "gruff.analysis.v3");
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

// Each invalid shape becomes a separately named test so users can identify the exact failed compatibility case.
for (const [caseName, configuredValue] of INVALID_LEGACY_SECRET_PREVIEW_CASES) {
  // Fixture purpose: prove this retired value shape fails with the same safe diagnostic and never echoes the configured content.
  test(`legacy secret previews reject ${caseName} with one safe diagnostic`, () => {
    const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-secret-preview-config-"));
    try {
      writeFileSync(
        join(projectRoot, ".gruff-ts.yaml"),
        `schemaVersion: gruff-ts.config.v0.1\nallowlists:\n  secretPreviews: ${configuredValue}\n`,
      );
      assert.throws(
        () => loadConfig(projectRoot, CONFIG_LOAD_OPTIONS),
        (error: unknown) => {
          assert.equal(error instanceof ConfigLoadError, true, caseName);
          assert.equal((error as ConfigLoadError).message, LEGACY_SECRET_PREVIEWS_ERROR, caseName);
          assert.equal((error as ConfigLoadError).message.includes("known-fixture-preview"), false, caseName);
          return true;
        },
      );
    } finally {
      rmSync(projectRoot, { recursive: true, force: true });
    }
  });
}

test("non-empty legacy secret preview config exits 2 without echoing its value", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-secret-preview-cli-"));
  try {
    writeFileSync(join(projectRoot, "ok.ts"), "// File overview: retired preview CLI fixture.\nexport const fine = 1;\n");
    writeFileSync(
      join(projectRoot, ".gruff-ts.yaml"),
      "schemaVersion: gruff-ts.config.v0.1\nallowlists:\n  secretPreviews: [known-fixture-preview]\n",
    );
    const result = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "analyse", ".", "--fail-on", "none"], {
      cwd: projectRoot,
      encoding: "utf8",
    });

    assert.equal(result.status, 2);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr.includes(LEGACY_SECRET_PREVIEWS_ERROR), true);
    assert.equal(result.stderr.includes("known-fixture-preview"), false);
    assert.equal(/\n\s+at /.test(result.stderr), false);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
