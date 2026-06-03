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
const STATIC_REDUNDANT_RULE_ID = "test-quality.static-analysis-redundant-test";

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

const STATIC_ANALYSIS_REDUNDANT_CALLBACK = `
  function renderCatalogue(): string {
    return "catalogue";
  }
  const analyseSecurityFlow = () => undefined;
  assert.equal(typeof renderCatalogue, "function");
  assert.strictEqual(typeof analyseSecurityFlow, "function", "public export");
  assert.ok(new FindingReport() instanceof FindingReport);
  expect(new Result()).toBeInstanceOf(Result);
`;

const IMPORTED_STATIC_ANALYSIS_REDUNDANT_CALLBACK = `
  assert.equal(typeof rules.ruleDescriptors, "function");
  assert.strictEqual(typeof analyseSecurityFlow, "function", "public export");
`;

const IMPORTED_STATIC_CONTEXT_PREFIX = `
import * as rules from "./rules.ts";
import { analyseSecurityFlow } from "./security-flow-rules.ts";
`;

const NON_NULLABLE_RETURN_CALLBACK = `
  interface Result {
    value: string;
  }
  function getResult(): Result {
    return { value: "ok" };
  }
  const buildResult = (): Promise<Result> => Promise.resolve({ value: "ok" });
  assert.notEqual(getResult(), null);
  expect(buildResult()).toBeDefined();
  assert.notEqual(service.getResult(), null);
`;

const RUNTIME_PAYLOAD_TYPE_CALLBACK = `
  const rawRow = JSON.parse(payload);
  assert.ok(rawRow && typeof rawRow === "object");
  assert.equal(typeof row.pillar, "string");
  assert.equal(typeof row.score, "number");
  assert.equal(typeof row.findings, "number");
`;

const RUNTIME_CALLABLE_TYPEOF_CALLBACK = `
  const handler = createMiddleware({ timeout: 100 });
  assert.equal(typeof handler, "function");
  const plugin = loadPlugin("formatter");
  assert.equal(typeof plugin.activate, "function");
`;

const MIXED_STATIC_AND_BEHAVIOR_CALLBACK = `
  function renderReport(): string[] {
    return [];
  }
  assert.equal(typeof renderReport, "function");
  assert.deepEqual(renderer.renderReport(input), ["finding.md"]);
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

test("analyseTestBlock reports structural test smells once per block", () => {
  const findings = analyseTestCallback(STRUCTURAL_CALLBACK);

  assert.deepEqual(ruleIds(findings), [
    "test-quality.sleep-in-test",
    "test-quality.loop-in-test",
    "test-quality.conditional-logic",
    "test-quality.only-skip",
  ]);
});

test("analyseTestBlock reports conditional assertions inside type guards", () => {
  const findings = analyseTestCallback(`
  const result: unknown = getResult();
  if (typeof result === "string") {
    assert.equal(result, "ok");
  }
`);

  assert.equal(findings.some((finding) => finding.ruleId === "test-quality.conditional-logic"), true);
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

test("analyseTestBlock reports static-analysis-redundant shape assertions", () => {
  const findings = analyseTestCallback(STATIC_ANALYSIS_REDUNDANT_CALLBACK, SOURCE_FILE.displayPath, "asserts static shape");
  const staticFindings = findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID);

  assert.equal(staticFindings.length, 4);
  assert.equal(staticFindings.every((finding) => finding.confidence === "high"), true);
  assert.match(staticFindings[0]?.message ?? "", /Static-analysis-redundant candidate: high confidence/);
  assert.equal(staticFindings[0]?.metadata.testFile, SOURCE_FILE.displayPath);
  assert.equal(staticFindings[0]?.metadata.testMethod, "asserts static shape");
  assert.match(String(staticFindings[0]?.metadata.assertion), /typeof renderCatalogue/);
  assert.match(String(staticFindings[0]?.metadata.staticFact), /declared as a function/);
  assert.match(String(staticFindings[0]?.metadata.sourceProof), /src\/test-block-rules\.test\.ts:4/);
  assert.match(String(staticFindings[0]?.metadata.recommendation), /observable behavior/);
});

test("analyseTestBlock reports imported static-analysis-redundant shape assertions only with import evidence", () => {
  const findings = analyseTestCallback(IMPORTED_STATIC_ANALYSIS_REDUNDANT_CALLBACK, SOURCE_FILE.displayPath, "asserts imported static shape", IMPORTED_STATIC_CONTEXT_PREFIX);
  const staticFindings = findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID);

  assert.equal(staticFindings.length, 2);
  assert.deepEqual(staticFindings.map((finding) => finding.metadata.sourceProof), [
    "src/test-block-rules.test.ts:2",
    "src/test-block-rules.test.ts:3",
  ]);
  assert.match(String(staticFindings[0]?.metadata.staticFact), /namespace import/);
  assert.match(String(staticFindings[1]?.metadata.staticFact), /named import/);
});

test("analyseTestBlock reports non-null assertions only for visible non-nullable return declarations", () => {
  const findings = analyseTestCallback(NON_NULLABLE_RETURN_CALLBACK, SOURCE_FILE.displayPath, "asserts non-null declared returns");
  const staticFindings = findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID);

  assert.equal(staticFindings.length, 2);
  assert.deepEqual(staticFindings.map((finding) => finding.metadata.staticFact), [
    "`getResult()` declares a non-nullable `Result` return type.",
    "`buildResult()` declares a non-nullable `Promise<Result>` return type.",
  ]);
});

test("analyseTestBlock keeps runtime payload type assertions quiet", () => {
  const findings = analyseTestCallback(RUNTIME_PAYLOAD_TYPE_CALLBACK);

  assert.deepEqual(findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID), []);
});

test("analyseTestBlock keeps runtime callable typeof assertions quiet", () => {
  const findings = analyseTestCallback(RUNTIME_CALLABLE_TYPEOF_CALLBACK);

  assert.deepEqual(findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID), []);
});

test("analyseTestBlock reports only the redundant assertion in mixed behavior tests", () => {
  const findings = analyseTestCallback(MIXED_STATIC_AND_BEHAVIOR_CALLBACK);

  assert.deepEqual(
    findings.filter((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID).map((finding) => finding.metadata.assertion),
    ['assert.equal(typeof renderReport, "function")'],
  );
});

// Runs one callback-shaped fixture through the test-block rule pass. Invariant: default rule config is used.
function analyseTestCallback(callbackBody: string, displayPath = SOURCE_FILE.displayPath, testName = "fixture", staticSourcePrefix = ""): Finding[] {
  const findings: Finding[] = [];
  const block = testBlockFixture(callbackBody, testName);
  const staticSource = `${staticSourcePrefix}${block.body}`;
  analyseTestBlock({ ...SOURCE_FILE, displayPath }, block, findings, {
    source: staticSource,
    codeSource: staticSource,
    startLine: staticSourcePrefix === "" ? TEST_START_LINE : 1,
  });
  return findings;
}

// Builds the minimal FunctionBlock contract that analyseTestBlock consumes.
function testBlockFixture(callbackBody: string, testName: string): FunctionBlock {
  const body = `test(${JSON.stringify(testName)}, () => {` + callbackBody + "});";
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
