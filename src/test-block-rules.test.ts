// Exercises the test-block rules that developers see after scanning their test files.

// These focused fixtures isolate assertion and structure decisions from project discovery.
// Full analysis-path cases in false-positive-fixes.test.ts also cover source masking.
import assert from "node:assert/strict";
import test from "node:test";
import type { FunctionBlock } from "./blocks.ts";
import type { SourceFile } from "./discovery.ts";
import { analyseTestBlock } from "./test-block-rules.ts";
import { analyseFixture } from "./test-fixtures.ts";
import type { Finding } from "./types.ts";

const SOURCE_FILE: SourceFile = {
  absolutePath: "/tmp/test-block-rules.test.ts",
  displayPath: "src/test-block-rules.test.ts",
  isScript: true,
};

const TEST_START_LINE = 3;
const EXPECTED_STATIC_REDUNDANT_FINDINGS = 4;
const STATIC_REDUNDANT_RULE_ID = "test-quality.static-analysis-redundant-test";

// This fixture matrix protects the checks enabled when a registration result is discarded.
const DISCARDED_REGISTRATION_CASES = [
    { body: "assert.equal(result, result);", ruleId: "test-quality.trivial-assertion" },
];
// Check both observed registration forms so discarding their result cannot hide a test from scan rules.
for (const registration of ["it", "test"]) {
  // Try every quality-control body so the void prefix preserves its warning and source identity.
  for (const { body, ruleId } of DISCARDED_REGISTRATION_CASES) {
    // Compare complete quality findings so anchors and identities stay stable with the void prefix.
    test(`discarding ${registration} preserves ${ruleId}`, () => {
      const source = `// File overview: test registration result fixture.
${registration}("request behavior", () => {
  ${body}
});
`;
      const ordinary = analyseFixture(source).findings.filter((finding) => finding.ruleId.startsWith("test-quality."));
      const discarded = analyseFixture(source.replace(`${registration}(`, `void ${registration}(`)).findings.filter((finding) => finding.ruleId.startsWith("test-quality."));
      assert.equal(ordinary.some((finding) => finding.ruleId === ruleId), true, ruleId);
      assert.deepEqual(discarded, ordinary, `${registration}: ${ruleId}`);
    });
  }
}

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

  assert.deepEqual(ruleIds(findings), [
    "test-quality.trivial-assertion",
    "test-quality.unused-mock",
  ]);
});

test("analyseTestBlock reports structural test smells once per block", () => {
  const findings = analyseTestCallback(STRUCTURAL_CALLBACK);

  assert.deepEqual(ruleIds(findings), [
    "test-quality.loop-in-test",
  ]);
});

test("test-quality findings carry actionable advice in report JSON", () => {
  const bodies = [
    STRUCTURAL_CALLBACK,
    ASSERTION_AND_MOCK_CALLBACK,
    ...DISCARDED_REGISTRATION_CASES.map((entry) => entry.body),
    "process.env.MODE = 'test'; assert.ok(result);",
  ];
  const findings = bodies.flatMap((body) => analyseTestCallback(body));
  const rules = ["global-state-mutation", "loop-in-test", "trivial-assertion"];
  for (const rule of rules) {
    const finding = findings.find((entry) => entry.ruleId === `test-quality.${rule}`);
    assert.ok(finding, rule);
    assert.ok(finding.remediation, `${rule} must carry advice in JSON`);
    assert.doesNotMatch(finding.remediation, /raise.*limit|ignore.*path|split.*separate tests|name expected values/i, rule);
  }
});

test("an unlabeled loop with a should.be assertion still reports loop-in-test", () => {
  // An assertion inside a loop can still hide which item failed, even though the test is not assertion-free.
  const findings = analyseTestCallback(`
  for (const item of items) {
    item.should.be.equal(1);
  }
`);

  assert.equal(findings.some((finding) => finding.ruleId === "test-quality.loop-in-test"), true);
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

// Scan one callback fixture under the default-rule contract; an empty result means no quality warning.
// An empty prefix adds no source declarations ahead of the test.
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

// Build the minimal callable contract used to check developer-visible test warnings.
// An empty callback body represents a test with no executable work; its parameter list is intentionally empty.
function testBlockFixture(callbackBody: string, testName: string): FunctionBlock {
  const body = `test(${JSON.stringify(testName)}, () => {` + callbackBody + "});";
  return {
    name: testName,
    params: "",
    startLine: TEST_START_LINE,
    lineCount: body.split(/\r?\n/).length,
    codeLineCount: body.split(/\r?\n/).length,
    body,
    codeBody: body,
    isPublic: false,
    isExported: false,
    isTest: true,
    hasLeadingComment: true,
    declarationLine: TEST_START_LINE,
  };
}

// Return warning IDs in their stable emitted order; an empty list means the scanned fixture produced no warnings.
function ruleIds(findings: Finding[]): string[] {
  return findings.map((finding) => finding.ruleId);
}

// M22 brief shape (`test-quality.loop-in-test`, 18 of 18 on the reporting repository): a prettier-wrapped per-case message and a message built from a
//
// loop-derived local both identify the failing row.
// A looped assertion with no message, and one whose message names no loop binding, still fire: the rule's contract is an identifiable row.
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

// Each case distinguishes a supported label or guard from the nearest unsafe mutation.
const M15_STRUCTURE_CASES: ReadonlyArray<{ name: string; body: string; rule: string; reports: boolean }> = [
  { name: "bare case message", body: "for (const item of items) { assert.ok(valid(item), item); }", rule: "loop-in-test", reports: false },
  { name: "concatenated case message", body: "for (const item of items) { assert.ok(valid(item), 'case: ' + item); }", rule: "loop-in-test", reports: false },
  { name: "call-built case message", body: "for (const item of items) { assert.ok(valid(item), describeCase(item)); }", rule: "loop-in-test", reports: false },
  { name: "case expected operand", body: "for (const item of items) { assert.equal(actual(), item); }", rule: "loop-in-test", reports: false },
  { name: "expect case expected operand", body: "for (const item of items) { expect(actual()).toBe(item); }", rule: "loop-in-test", reports: false },
  { name: "C-style case message", body: "for (let index = 0; index < items.length; index++) { assert.ok(valid(items[index]), `case ${index}`); }", rule: "loop-in-test", reports: false },
  { name: "for-in case message", body: "for (const key in items) { assert.ok(valid(items[key]), key); }", rule: "loop-in-test", reports: false },
  { name: "actual alone lacks case context", body: "for (const item of items) { assert.ok(valid(item)); }", rule: "loop-in-test", reports: true },
  { name: "constant message lacks case context", body: "for (const item of items) { assert.ok(valid(item), 'item'); }", rule: "loop-in-test", reports: true },
  { name: "label cannot hide branch policy", body: "for (const item of items) { if (item.ok) { assert.ok(valid(item), item); } }", rule: "loop-in-test", reports: true },
];

// Full analysis covers masking and shared-node ownership as well as each detector predicate.
for (const { name, body, rule, reports } of M15_STRUCTURE_CASES) {
  test(`M15 structure: ${name}`, () => {
    const report = analyseFixture(`import assert from "node:assert/strict";\nimport { it } from "node:test";\nit("${name}", async (t) => { ${body} });`, { fileName: "m15-structure.test.ts" });
    const actual = report.findings.some((finding) => finding.ruleId === `test-quality.${rule}`);
    assert.equal(actual, reports, name);
  });
}
