// Focused unit tests for the per-test-block rule pass without routing through full project scans.
import assert from "node:assert/strict";
import test from "node:test";
import type { FunctionBlock } from "./blocks.ts";
import { loadConfig } from "./config.ts";
import type { SourceFile } from "./discovery.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import { analyseFixture } from "./test-fixtures.ts";
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
const EXPECTED_STATIC_REDUNDANT_FINDINGS = 4;
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

const IMPORTABILITY_SENTINEL_CALLBACK = `
  assert.equal(typeof ruleDescriptors, "function");
`;

const IMPORTED_STATIC_CONTEXT_PREFIX = `
import * as rules from "./rules.ts";
import { analyseSecurityFlow } from "./security-flow-rules.ts";
`;

const IMPORTABILITY_SENTINEL_CONTEXT_PREFIX = `
import { ruleDescriptors } from "./rules.ts";
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

  assert.equal(staticFindings.length, EXPECTED_STATIC_REDUNDANT_FINDINGS);
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

test("analyseTestBlock downgrades static-analysis importability sentinels to review guidance", () => {
  const findings = analyseTestCallback(IMPORTABILITY_SENTINEL_CALLBACK, SOURCE_FILE.displayPath, "importability contract exposes rule descriptors", IMPORTABILITY_SENTINEL_CONTEXT_PREFIX);
  const staticFinding = findings.find((finding) => finding.ruleId === STATIC_REDUNDANT_RULE_ID);

  assert.equal(staticFinding?.confidence, "medium");
  assert.match(staticFinding?.message ?? "", /review importability sentinel/i);
  assert.equal(staticFinding?.metadata.reasonCategory, "importability-sentinel");
  assert.equal(staticFinding?.metadata.suggestedAction, "review-or-document");
  assert.match(String(staticFinding?.metadata.recommendation), /document why runtime module-load coverage matters/);
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

// M22 hunt shapes (zod `array.test.ts` and `apply.test.ts`): a snapshot strip must remove only the snapshot call
// chain. A lazy regex started at the earlier `expect(r1.success)` and deleted that real assertion, and vitest's
// `expectTypeOf<T>()` was not seen as an assertion at all. A test whose only assertion is a snapshot still fires.
test("M22 snapshot-only-test strips only whole snapshot call chains and sees expectTypeOf assertions", () => {
  const report = analyseFixture([
    "import { expect, expectTypeOf, test } from \"vitest\";",
    "",
    "test(\"array min/max\", () => {",
    "  const r1 = schema.safeParse([\"asdf\"]);",
    "  expect(r1.success).toEqual(false);",
    "  expect(r1.error!.issues).toMatchInlineSnapshot(`",
    "    [",
    "      { \"code\": \"too_small\", \"message\": \"Too small (expected >=2)\" },",
    "    ]",
    "  `);",
    "});",
    "",
    "test(\"basic apply (object)\", () => {",
    "  const schema = z.object({ a: z.number() }).apply((s) => s.extend({ c: z.boolean() }));",
    "  expect(z.toJSONSchema(schema)).toMatchInlineSnapshot(`",
    "    { \"type\": \"object\" }",
    "  `);",
    "  expectTypeOf<z.infer<typeof schema>>().toEqualTypeOf<{",
    "    a: number;",
    "    c: boolean;",
    "  }>();",
    "});",
    "",
    "test(\"continue parsing despite array size error\", () => {",
    "  const result = schema.safeParse({ people: [123] });",
    "  expect(result).toMatchInlineSnapshot(`",
    "    { \"success\": false }",
    "  `);",
    "});",
    "",
  ].join("\n"), { fileName: "array.test.ts" });
  const snapshotOnly = report.findings.filter((entry) => entry.ruleId === "test-quality.snapshot-only-test").map((entry) => entry.symbol);

  assert.deepEqual(snapshotOnly, ["continue parsing despite array size error"]);
});

// The no-throw strip had the same lazy regex, so a real assertion before an `expect(() => ...).not.toThrow()` was
// deleted with it. Only a test that asserts nothing beyond the absence of an exception still fires.
test("M22 no-throw-only-test strips only whole no-throw call chains", () => {
  const report = analyseFixture([
    "import assert from \"node:assert/strict\";",
    "",
    "test(\"parses and does not throw\", () => {",
    "  expect(parse(\"a\")).toBe(1);",
    "  expect(() => {",
    "    parse(\"(\");",
    "  }).not.toThrow();",
    "});",
    "",
    "test(\"asserts after a callback check\", () => {",
    "  assert.doesNotThrow(() => {",
    "    parse(\")\");",
    "  });",
    "  assert.equal(parse(\"x\"), 1);",
    "});",
    "",
    "test(\"only checks that parse does not throw\", () => {",
    "  assert.doesNotThrow(() => parse(value(\"b\")));",
    "});",
    "",
  ].join("\n"), { fileName: "parse.test.ts" });
  const noThrowOnly = report.findings.filter((entry) => entry.ruleId === "test-quality.no-throw-only-test").map((entry) => entry.symbol);

  assert.deepEqual(noThrowOnly, ["only checks that parse does not throw"]);
});

// M22 brief shape (`test-quality.loop-in-test`, 18 of 18 on the reporting repository): a prettier-wrapped per-case
// message and a message built from a loop-derived local both identify the failing row. A looped assertion with no
// message, and one whose message names no loop binding, still fire: the rule's contract is an identifiable row.
test("M22 loop-in-test reads wrapped and derived-local per-case messages", () => {
  const report = analyseFixture([
    "/** Overview: repro for loop-in-test line-wrapping blindness. */",
    "import assert from \"node:assert/strict\";",
    "import { describe, it } from \"node:test\";",
    "const ITEMS = [\"alpha\", \"beta\", \"gamma\"];",
    "describe(\"s\", () => {",
    "  it(\"single-line message is seen\", () => {",
    "    for (const item of ITEMS) {",
    "      assert.ok(item.length > 0, `${item}: empty`);",
    "    }",
    "  });",
    "  it(\"identical message, prettier-wrapped, is seen\", () => {",
    "    for (const item of ITEMS) {",
    "      assert.ok(",
    "        item.length > 0,",
    "        `${item}: empty`,",
    "      );",
    "    }",
    "  });",
    "  it(\"derived local message is seen\", () => {",
    "    for (const item of ITEMS) {",
    "      const label = `prefix/${item}`;",
    "      assert.ok(item.length > 0, `${label}: empty`);",
    "    }",
    "  });",
    "  it(\"no message still fires\", () => {",
    "    for (const item of ITEMS) {",
    "      assert.ok(item.length > 0);",
    "    }",
    "  });",
    "  it(\"message naming no binding still fires\", () => {",
    "    for (const item of ITEMS) {",
    "      const size = ITEMS.length;",
    "      assert.ok(item.length > 0, `${size}: empty`);",
    "    }",
    "  });",
    "});",
    "",
  ].join("\n"), { fileName: "loops.test.ts" });
  const loopTests = report.findings.filter((entry) => entry.ruleId === "test-quality.loop-in-test").map((entry) => entry.symbol).sort();

  assert.deepEqual(loopTests, ["message naming no binding still fires", "no message still fires"]);
});
