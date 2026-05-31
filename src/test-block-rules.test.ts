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
  shouldSkipConfig: true,
  format: "json",
  failOn: "none",
  shouldIncludeIgnored: false,
  changedScope: "symbol",
  shouldSkipBaseline: true,
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

const HTTP_STATUS_ASSERTION_CALLBACK = `
  const res = await fetch(baseUrl);
  assert.equal(res.status, 200);
  expect(response.statusCode).toBe(404);
  assert.equal(retryBudgetMs, 125);
`;

const CARDINAL_ASSERTION_CALLBACK = `
  expect(items).toHaveLength(4);
  expect(groups).toHaveCount(5);
  assert.equal(results.length, 2);
  expect(total).toBe(3);
  assert.equal(retryBudgetMs, 125);
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

const STRUCTURAL_SETUP_ONLY_CALLBACK = `
  const collected = [];
  for (const item of items) {
    collected.push(item);
  }
  if (collected.length === 0) {
    collected.push(fallback);
  }
  assert.equal(collected.length, 1);
`;

const CONST_BOUND_FIXTURE_LOOP_CALLBACK = `
  const cases = [
    { name: "alpha", value: 1 },
    { name: "beta", value: 2 },
  ];
  for (const entry of cases) {
    assert.ok(entry.value);
  }
`;

const CONST_BOUND_FIXTURE_DISCOVERY_CALLBACK = `
  const files = globSync("fixtures/*.json");
  for (const file of files) {
    expect(file).toMatch(/json$/);
  }
`;

const CONST_BOUND_FIXTURE_GUARD_CALLBACK = `
  const cases = [
    { name: "alpha", value: 1, skip: false },
    { name: "beta", value: 2, skip: true },
  ];
  for (const entry of cases) {
    if (entry.skip) {
      continue;
    }
    assert.ok(entry.value);
  }
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

test("analyseTestBlock ignores HTTP status magic numbers but keeps other numeric assertions", () => {
  const findings = analyseTestCallback(HTTP_STATUS_ASSERTION_CALLBACK);

  assert.deepEqual(
    findings.filter((finding) => finding.ruleId === "test-quality.magic-number-assertion").map((finding) => finding.metadata),
    [{ value: 125 }],
  );
});

test("analyseTestBlock ignores cardinal and length/count assertions", () => {
  const findings = analyseTestCallback(CARDINAL_ASSERTION_CALLBACK);

  assert.deepEqual(
    findings.filter((finding) => finding.ruleId === "test-quality.magic-number-assertion").map((finding) => finding.metadata),
    [{ value: 125 }],
  );
});

test("analyseTestBlock ignores numeric assertions in named constant-contract tests", () => {
  const findings = analyseTestCallback(
    `
  assert.equal(DEFAULT_RETRY_BUDGET_MS, 125);
  expect(config.maxAttempts).toBe(7);
`,
    SOURCE_FILE.displayPath,
    "documents default threshold contract",
  );

  assert.deepEqual(findings.filter((finding) => finding.ruleId === "test-quality.magic-number-assertion"), []);
});

test("analyseTestBlock reports setup bloat metadata from default config", () => {
  const findings = analyseTestCallback(SETUP_BLOAT_CALLBACK);

  assert.deepEqual(ruleIds(findings), ["test-quality.setup-bloat"]);
  assert.deepEqual(findings[0]?.metadata, { setupLines: 13, maxSetupLines: 12 });
});

test("analyseTestBlock gives broad-flow tests a larger setup budget", () => {
  const findings = analyseTestCallback(SETUP_BLOAT_CALLBACK, "test/integration/dashboard-server.test.ts");

  assert.deepEqual(ruleIds(findings), []);
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

test("analyseTestBlock ignores setup-only loops and conditionals", () => {
  const findings = analyseTestCallback(STRUCTURAL_SETUP_ONLY_CALLBACK);

  assert.deepEqual(ruleIds(findings), []);
});

test("analyseTestBlock accepts const-bound fixture loops", () => {
  const findings = analyseTestCallback(CONST_BOUND_FIXTURE_LOOP_CALLBACK);

  assert.deepEqual(ruleIds(findings), []);
});

test("analyseTestBlock accepts const-bound fixture discovery loops", () => {
  const findings = analyseTestCallback(CONST_BOUND_FIXTURE_DISCOVERY_CALLBACK);

  assert.deepEqual(ruleIds(findings), []);
});

test("analyseTestBlock accepts const-bound fixture loop guard clauses", () => {
  const findings = analyseTestCallback(CONST_BOUND_FIXTURE_GUARD_CALLBACK);

  assert.deepEqual(ruleIds(findings), []);
});

// Runs one callback-shaped fixture through the test-block rule pass. Invariant: default rule config is used.
function analyseTestCallback(callbackBody: string, displayPath = SOURCE_FILE.displayPath, testName = "fixture"): Finding[] {
  const findings: Finding[] = [];
  analyseTestBlock({ ...SOURCE_FILE, displayPath }, testBlockFixture(callbackBody, testName), defaultTestConfig(), findings);
  return findings;
}

// Builds the minimal FunctionBlock contract that analyseTestBlock consumes.
function testBlockFixture(callbackBody: string, testName: string): FunctionBlock {
  const body = `test("${testName}", () => {` + callbackBody + "});";
  return {
    name: testName,
    params: "",
    startLine: TEST_START_LINE,
    lineCount: body.split(/\r?\n/).length,
    body,
    codeBody: body,
    isPublic: false,
    isExported: false,
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
