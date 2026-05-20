// Focused unit tests for the per-test-block rule pass without routing through full project scans.
import assert from "node:assert/strict";
import test from "node:test";
import type { FunctionBlock } from "./blocks.ts";
import { loadConfig } from "./config.ts";
import type { SourceFile } from "./discovery.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import type { AnalysisOptions, Config, Finding } from "./types.ts";

const SOURCE_FILE: SourceFile = {
  absolutePath: "/tmp/test-block-rules.test.ts",
  displayPath: "src/test-block-rules.test.ts",
  isScript: true,
};

const BASE_OPTIONS: AnalysisOptions = {
  paths: [],
  noConfig: true,
  format: "json",
  failOn: "none",
  includeIgnored: false,
  noBaseline: true,
};

const TEST_START_LINE = 3;
const EXPECTED_MAGIC_VALUE = 42;

const ASSERTION_AND_MOCK_CALLBACK = `
  const unusedMock = jest.fn();
  const total = calculateTotal();
  assert.ok(true);
  assert.equal(total, 42);
  expect(() => fail()).toThrow(Error);
`;

const SETUP_BLOAT_CALLBACK = `
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  const four = buildFour();
  const five = buildFive();
  const six = buildSix();
  const seven = buildSeven();
  const eight = buildEight();
  const nine = buildNine();
  const ten = buildTen();
  const eleven = buildEleven();
  const twelve = buildTwelve();
  const thirteen = buildThirteen();
  assert.ok(one);
`;

const STRUCTURAL_CALLBACK = `
  const timer = setTimeout(() => done(), 10);
  if (ready) {
    assert.ok(ready);
  }
  for (const item of items) {
    assert.ok(item);
  }
  test.only("nested", () => assert.ok(nestedReady));
  assert.ok(timer);
`;

test("analyseTestBlock reports assertion and mock quality findings", () => {
  const findings = analyseTestCallback(ASSERTION_AND_MOCK_CALLBACK);
  const magicFinding = findings.find((finding) => finding.ruleId === "test-quality.magic-number-assertion");

  assert.deepEqual(ruleIds(findings), [
    "test-quality.trivial-assertion",
    "test-quality.exception-type-only",
    "test-quality.magic-number-assertion",
    "test-quality.unused-mock",
  ]);
  assert.deepEqual(magicFinding?.metadata, { value: EXPECTED_MAGIC_VALUE });
});

test("analyseTestBlock reports setup bloat metadata from default config", () => {
  const findings = analyseTestCallback(SETUP_BLOAT_CALLBACK);

  assert.deepEqual(ruleIds(findings), ["test-quality.setup-bloat"]);
  assert.deepEqual(findings[0]?.metadata, { setupLines: 13, maxSetupLines: 12 });
});

test("analyseTestBlock reports structural test smells once per block", () => {
  const findings = analyseTestCallback(STRUCTURAL_CALLBACK);

  assert.deepEqual(ruleIds(findings), [
    "test-quality.sleep-in-test",
    "test-quality.loop-in-test",
    "test-quality.conditional-logic",
    "test-quality.only-skip",
  ]);
});

// Runs one callback-shaped fixture through the test-block rule pass. Invariant: default rule config is used.
function analyseTestCallback(callbackBody: string): Finding[] {
  const findings: Finding[] = [];
  analyseTestBlock(SOURCE_FILE, testBlockFixture(callbackBody), defaultTestConfig(), findings);
  return findings;
}

// Builds the minimal FunctionBlock contract that analyseTestBlock consumes.
function testBlockFixture(callbackBody: string): FunctionBlock {
  const body = 'test("fixture", () => {' + callbackBody + "});";
  return {
    name: "fixture",
    params: "",
    startLine: TEST_START_LINE,
    lineCount: body.split(/\r?\n/).length,
    body,
    codeBody: body,
    isPublic: false,
    isTest: true,
    hasLeadingComment: true,
    declarationLine: TEST_START_LINE,
  };
}

// Reuses the production config defaults instead of copying rule defaults into tests.
function defaultTestConfig(): Config {
  return loadConfig(".", BASE_OPTIONS);
}

// Returns rule IDs in emitted order. Invariant: ordering regressions remain visible.
function ruleIds(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId);
}
