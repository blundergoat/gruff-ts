// Config `paths.ignore` is authoritative in every invocation shape (explicit file operand and
// diff/changed-region run), and `check-ignore` shares the same engine. Regression coverage for
// ADR-007 / M27: before this, an explicitly supplied config-ignored file was analysed and flagged.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { checkIgnore, checkIgnoreExitCode, renderCheckIgnore } from "./check-ignore.ts";
import { analyseProject, yamlConfigFixture } from "./test-fixtures.ts";
import type { AnalysisOptions } from "./types.ts";

// A source that would emit findings (`eval` -> security) if it were ever scanned, so "no findings"
// proves the file was excluded rather than merely clean.
const FLAGGABLE_SOURCE = "export function run(input: string): unknown {\n  return eval(input);\n}\n";
const IGNORE_FIXTURES_CONFIG = { paths: { ignore: ["fixtures/**"] } } as const;
const CHECK_IGNORE_OPTIONS: AnalysisOptions = {
  paths: ["fixtures/sample.ts", "app.ts"],
  shouldSkipConfig: false,
  format: "json",
  failOn: "none",
  shouldIncludeIgnored: false,
  changedScope: "symbol",
  shouldSkipBaseline: true,
};

test("analyse excludes an explicitly supplied config-ignored file and reports it with source + pattern", () => {
  const report = analyseProject(
    { "fixtures/sample.ts": FLAGGABLE_SOURCE },
    { config: IGNORE_FIXTURES_CONFIG, paths: ["fixtures/sample.ts"] },
  );
  assert.equal(report.paths.analysedFiles, 0);
  assert.deepEqual(report.findings, []);
  assert.deepEqual(report.paths.skipped, [{ path: "fixtures/sample.ts", source: "config", pattern: "fixtures/**" }]);
  assert.deepEqual(report.paths.ignoredPaths, ["fixtures/sample.ts"]);
});

test("a changed-region run touching a config-ignored file still excludes it", () => {
  const report = analyseProject(
    { "fixtures/sample.ts": FLAGGABLE_SOURCE },
    { config: IGNORE_FIXTURES_CONFIG, paths: ["fixtures/sample.ts"], changedRanges: "1-3" },
  );
  assert.equal(report.paths.analysedFiles, 0);
  assert.deepEqual(report.findings, []);
  assert.equal(
    report.paths.skipped.some((entry) => entry.path === "fixtures/sample.ts" && entry.source === "config" && entry.pattern === "fixtures/**"),
    true,
  );
});

test("--include-ignored never overrides config paths.ignore", () => {
  const report = analyseProject(
    { "fixtures/sample.ts": FLAGGABLE_SOURCE },
    { config: IGNORE_FIXTURES_CONFIG, paths: ["fixtures/sample.ts"], shouldIncludeIgnored: true },
  );
  assert.equal(report.paths.analysedFiles, 0);
  assert.deepEqual(report.findings, []);
  assert.equal(report.paths.skipped.some((entry) => entry.path === "fixtures/sample.ts" && entry.source === "config"), true);
});

test("check-ignore shares the engine: config-ignored path -> verdict + pattern, clean path -> not ignored", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ci-"));
  const previous = cwd();
  try {
    mkdirSync(join(dir, "fixtures"));
    writeFileSync(join(dir, "fixtures/sample.ts"), FLAGGABLE_SOURCE);
    writeFileSync(join(dir, "app.ts"), "export const x = 1;\n");
    writeFileSync(join(dir, ".gruff-ts.yaml"), yamlConfigFixture(IGNORE_FIXTURES_CONFIG));
    chdir(dir);
    const results = checkIgnore(["fixtures/sample.ts", "app.ts"], CHECK_IGNORE_OPTIONS);
    assert.deepEqual(results, [
      { path: "fixtures/sample.ts", isIgnored: true, source: "config", pattern: "fixtures/**" },
      { path: "app.ts", isIgnored: false },
    ]);
    assert.equal(checkIgnoreExitCode(results), 0);
    const parsed = JSON.parse(renderCheckIgnore(results, "json"));
    assert.deepEqual(parsed, [
      { path: "fixtures/sample.ts", ignored: true, source: "config", pattern: "fixtures/**" },
      { path: "app.ts", ignored: false, source: null, pattern: null },
    ]);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("check-ignore does not apply gitignore rules to explicit file operands", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ci-gitignore-"));
  const previous = cwd();
  try {
    writeFileSync(join(dir, ".gitignore"), "ignored.ts\n");
    writeFileSync(join(dir, "ignored.ts"), FLAGGABLE_SOURCE);
    chdir(dir);
    const results = checkIgnore(["ignored.ts"], { ...CHECK_IGNORE_OPTIONS, paths: ["ignored.ts"], shouldSkipConfig: true });
    assert.deepEqual(results, [{ path: "ignored.ts", isIgnored: false }]);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("check-ignore reports files under default-ignored parent directories", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ci-default-ignore-"));
  const previous = cwd();
  try {
    mkdirSync(join(dir, "dist"));
    writeFileSync(join(dir, "dist/generated.ts"), FLAGGABLE_SOURCE);
    chdir(dir);
    const results = checkIgnore(["dist/generated.ts"], { ...CHECK_IGNORE_OPTIONS, paths: ["dist/generated.ts"], shouldSkipConfig: true });
    assert.deepEqual(results, [{ path: "dist/generated.ts", isIgnored: true, source: "default", pattern: "dist/" }]);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
});
