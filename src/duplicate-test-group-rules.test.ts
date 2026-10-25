// Drives the public analysis path to protect group membership, literal boundaries and opt-in behavior.
// Fixtures deliberately repeat test syntax so each assertion describes a consolidation decision.
import assert from "node:assert/strict";
import test from "node:test";
import { parsedScriptParseCount } from "./parsed-script.ts";
import { analyseFixture } from "./test-fixtures.ts";

const RULE_ID = "test-quality.duplicate-test-body";
const MATCHING_BODIES = [1, 2, 3].map((value) => `const result = convert(${value}); assert.equal(result, ${value + 1});`);

/**
 * Builds independently named registrations with caller-controlled bodies and call forms.
 * @param bodies - syntax to compare inside block callbacks
 * @param callee - supported runner root or modifier chain
 * @param options - optional argument preceding each callback
 * @returns source text containing all registrations in source order
 */
function registrations(bodies: string[], callee = "test", options = ""): string {
  return bodies.map((body, index) => `${callee}("case ${index}", ${options}() => { ${body} });`).join("\n");
}

/**
 * Runs the real parser, dispatch and finding construction with the pilot enabled.
 * Contract: fixture callers receive only this rule's deterministic native findings.
 * @param source - test-file contents
 * @param fileName - grammar-selecting fixture path, including TSX when JSX text is exercised
 * @returns only this pilot's native findings
 */
function groups(source: string, fileName = "suite.test.ts") {
  return analyseFixture(source, {
    fileName,
    config: { rules: { [RULE_ID]: { enabled: true } } },
  }).findings.filter((finding) => finding.ruleId === RULE_ID);
}

test("duplicate test groups are default-off and reuse the shared parse when enabled", () => {
  const source = registrations(MATCHING_BODIES);
  const before = parsedScriptParseCount();
  assert.equal(analyseFixture(source, { fileName: "suite.test.ts" }).findings.some((finding) => finding.ruleId === RULE_ID), false);
  assert.equal(parsedScriptParseCount() - before, 1);
  const enabledBefore = parsedScriptParseCount();
  assert.equal(groups(source).length, 1);
  assert.equal(parsedScriptParseCount() - enabledBefore, 1);
});

test("one finding lists the complete ordered group and uses the first native anchor", () => {
  const source = registrations([...MATCHING_BODIES, "const result = convert(4); assert.equal(result, 5);"]);
  const findings = groups(source);
  assert.equal(findings.length, 1);
  const finding = findings[0]!;
  assert.equal(finding.line, 1);
  assert.equal(finding.column, 1);
  assert.equal(finding.symbol, "case 0");
  assert.equal(finding.metadata.groupSize, 4);
  assert.deepEqual(finding.metadata.members, [0, 1, 2, 3].map((index) => ({
    name: `case ${index}`, qualifiedName: `case ${index}`, line: index + 1, column: 1, endLine: index + 1,
  })));
  assert.match(finding.message, /test runner's table form with a descriptive label per row/);
  assert.deepEqual(groups(source), findings);
});

test("same-line registrations retain every member instead of using the legacy callable projection", () => {
  const source = registrations(MATCHING_BODIES).replaceAll("\n", " ");
  const finding = groups(source)[0]!;
  const members = finding.metadata.members as { line: number; column: number }[];
  assert.equal(members.length, 3);
  assert.deepEqual(members.map((member) => member.line), [1, 1, 1]);
  assert.ok(members[0]!.column < members[1]!.column && members[1]!.column < members[2]!.column);
});

test("literal values, comments and formatting normalize without renaming local variables", () => {
  const source = [
    'test("number", () => { const result = convert(1, "red", true, null); assert.equal(result, 2); });',
    'it("other", () => { /* explanation */ const result=convert(3, \'blue\', false, null); assert.equal(result, 4) });',
    'test("third", () => { const result = convert(5, "green", true, null);; assert.equal(result, 6); });',
  ].join("\n");
  assert.equal(groups(source).length, 1);
  assert.equal(groups(source.replace('const result = convert(5', 'const answer = convert(5')).length, 0);
});

test("retained whitespace strings, keys and index descendants keep separate meanings", async (context) => {
  // Each body varies only the candidate literal, exposing accidental normalization of protected text.
  const cases = [
    { name: "space", values: ['"red fox"', '"blue fox"', '"green fox"'], body: (value: string) => `convert(${value})` },
    { name: "decoded space", values: ['"red\\u0020fox"', '"blue\\x20fox"', '"green fox"'], body: (value: string) => `convert(${value})` },
    { name: "tab", values: ['"red\\tfox"', '"blue\\tfox"', '"green\\tfox"'], body: (value: string) => `convert(${value})` },
    { name: "template text", values: ['`red fox ${input}`', '`blue fox ${input}`', '`green fox ${input}`'], body: (value: string) => `convert(${value})` },
    { name: "object key", values: ['"red"', '"blue"', '"green"'], body: (value: string) => `convert({${value}: 1})` },
    { name: "computed key descendant", values: ["1", "2", "3"], body: (value: string) => `convert({[choose(${value})]: 1})` },
    { name: "index descendant", values: ["1", "2", "3"], body: (value: string) => `values[choose(${value})]` },
  ];
  for (const entry of cases) {
    await context.test(entry.name, () => {
      assert.equal(groups(registrations(entry.values.map((value) => `const result = ${entry.body(value)}; assert.ok(result);`))).length, 0, entry.name);
    });
  }
});

test("literal kinds, operators, calls and statement order remain significant", async (context) => {
  const cases = [
    ["convert(1)", 'convert("one")', "convert(true)"],
    ["input + 1", "input - 1", "input * 1"],
    ["convert(1)", "parse(1)", "render(1)"],
  ];
  for (const [index, expressions] of cases.entries()) {
    await context.test(`syntax ${index}`, () => {
      assert.equal(groups(registrations(expressions.map((expression) => `const result = ${expression}; assert.ok(result);`))).length, 0, `syntax ${index}`);
    });
  }
  assert.equal(groups(registrations(["prepare(); check();", "check(); prepare();", "verify(); prepare();"])).length, 0);
});

test("one-statement bodies, expression callbacks and pairs stay silent", () => {
  assert.equal(groups(registrations(MATCHING_BODIES.slice(0, 2))).length, 0);
  assert.equal(groups(registrations(["check(1);", "check(2);", "check(3);"])).length, 0);
  assert.equal(groups([1, 2, 3].map((value) => `test("case ${value}", () => check(${value}));`).join("\n")).length, 0);
  assert.equal(groups(registrations(["if (ready) { prepare(); check(1); }", "if (ready) { prepare(); check(2); }", "if (ready) { prepare(); check(3); }"])).length, 0);
});

test("syntax tokens and for-loop clause positions keep different bodies apart", async (context) => {
  // These bodies expose tokens and empty clause positions omitted by an AST child-only projection.
  const cases = [
    { name: "prefix operators", bodies: ["+input", "-input", "~input"].map((value) => `const result = ${value}; assert.ok(result);`) },
    { name: "postfix operators", bodies: ["input++", "input--", "input++"].map((value) => `const result = ${value}; assert.ok(result);`) },
    { name: "declaration kinds", bodies: ["const", "let", "var"].map((kind) => `${kind} result = convert(1); assert.ok(result);`) },
    { name: "for clause positions", bodies: ["for (advance();;) { break; }", "for (;advance();) { break; }", "for (;;advance()) { break; }"].map((body) => `${body} assert.ok(result);`) },
  ];
  for (const entry of cases) {
    await context.test(entry.name, () => assert.equal(groups(registrations(entry.bodies)).length, 0, entry.name));
  }
});

test("option arguments retain their unary operators", () => {
  const source = ["+timeout", "-timeout", "~timeout"].map((timeout, index) =>
    `test("case ${index}", { timeout: ${timeout} }, () => { const result = convert(1); assert.ok(result); });`).join("\n");
  assert.equal(groups(source).length, 0);
});

test("JSX text remains exact while identical JSX groups still qualify", () => {
  const different = ["red fox", "blue fox", "green fox"].map((text) => `const result = <span>${text}</span>; assert.ok(result);`);
  assert.equal(groups(registrations(different), "suite.test.tsx").length, 0);
  const identical = [1, 2, 3].map((value) => `const result = <span value={${value}}>same text</span>; assert.ok(result);`);
  assert.equal(groups(registrations(identical), "suite.test.tsx").length, 1);
});

test("optional statement semicolons and trailing commas do not split a matching group", () => {
  const bodies = [
    "const result = convert(1,); assert.equal(result, 2,);",
    "const result = convert(3)\nassert.equal(result, 4)",
    "const result = convert(5);; assert.equal(result, 6);",
  ];
  assert.equal(groups(registrations(bodies)).length, 1);
  const loopBodies = [1, 2, 3].map((value) => `for (advance(${value}); ready(); finish()) { check(${value}); } assert.ok(result);`);
  assert.equal(groups(registrations(loopBodies)).length, 1);
});

test("separate same-named suites, functions, classes and namespaces never pool members", async (context) => {
  const first = registrations(MATCHING_BODIES.slice(0, 2));
  const last = registrations(MATCHING_BODIES.slice(2));
  const scopes = [
    `describe("same", () => { ${first} }); describe("same", () => { ${last} });`,
    `function first() { ${first} } function second() { ${last} }`,
    `class First { run() { ${first} } } class Second { run() { ${last} } }`,
    `namespace First { ${first} } namespace Second { ${last} }`,
  ];
  for (const [index, source] of scopes.entries()) {
    await context.test(`container ${index}`, () => assert.equal(groups(source).length, 0, `container ${index}`));
  }
  const source = `describe.skip("outer", () => { describe("inner", () => { ${registrations(MATCHING_BODIES)} }); });`;
  assert.equal(groups(source).length, 1);
  assert.equal((groups(source)[0]!.metadata.members as { qualifiedName: string }[])[0]!.qualifiedName, "outer > inner > case 0");
});

test("member modifiers and exact option values must agree in their original order", () => {
  assert.equal(groups(registrations(MATCHING_BODIES, "test.skipIf(flag).concurrent")).length, 1);
  const changedModifier = registrations(MATCHING_BODIES).replace('test("case 1"', 'test.skip("case 1"');
  assert.equal(groups(changedModifier).length, 0);
  const changedOrder = registrations(MATCHING_BODIES, "test.only.concurrent").replace('test.only.concurrent("case 1"', 'test.concurrent.only("case 1"');
  assert.equal(groups(changedOrder).length, 0);
  const options = registrations(MATCHING_BODIES, "test", "{ timeout: 10 }, ");
  assert.equal(groups(options).length, 1);
  assert.equal(groups(options.replace("timeout: 10", "timeout: 20")).length, 0);
  const timeout = registrations(MATCHING_BODIES).replaceAll("});", "}, 10);");
  assert.equal(groups(timeout).length, 1);
  assert.equal(groups(timeout.replace("}, 10)", "}, 20)")).length, 0);
});

test("table registrations and registrations under table loops remain silent", async (context) => {
  const repeated = registrations(MATCHING_BODIES);
  const sources = [
    registrations(MATCHING_BODIES, "test.each(rows)"),
    registrations(MATCHING_BODIES, "it.for(rows)"),
    `describe.each(rows)("suite", () => { ${repeated} });`,
    `for (const row of rows) { ${repeated} }`,
    `for (let index = 0; index < rows.length; index++) { ${repeated} }`,
    `rows.forEach((row) => { ${repeated} });`,
    `rows.map((row) => { ${repeated} });`,
  ];
  for (const [index, source] of sources.entries()) {
    await context.test(`table ${index}`, () => assert.equal(groups(source).length, 0, `table ${index}`));
  }
});

test("folding the group into labelled runner rows removes it without another test-quality finding", () => {
  const source = 'test.each([["one", 1, 2], ["two", 2, 3], ["three", 3, 4]])("%s", (label, input, expected) => { const result = convert(input); assert.equal(result, expected, label); });';
  const report = analyseFixture(source, { fileName: "suite.test.ts", config: { rules: { [RULE_ID]: { enabled: true } } } });
  assert.deepEqual(report.findings.filter((finding) => finding.pillar === "test-quality"), []);
});

test("malformed syntax and ordinary production functions provide no group evidence", () => {
  assert.equal(groups(registrations(MATCHING_BODIES) + "\nconst broken = ;").length, 0);
  const source = MATCHING_BODIES.map((body, index) => `function calculate${index}() { ${body} }`).join("\n");
  assert.equal(groups(source).length, 0);
});
