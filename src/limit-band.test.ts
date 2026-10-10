// Precision-floor M14: size and complexity findings report in two bands (FAMILY-CONTRACT.md section 12, search `Size and
// complexity findings in two bands`), and four more function forms are measured by the size and complexity rules only.
import assert from "node:assert/strict";
import test from "node:test";

import { GROUP_PARAMETERS, limitBand, LOWER_BAND_FILE, LOWER_BAND_FUNCTION, LOWER_BAND_PARAMETER, SIMPLIFY_PATH, SPLIT_FILE, SPLIT_FUNCTION } from "./limit-band.ts";
import { analyseFixture } from "./test-fixtures.ts";
import type { Finding, Severity } from "./types.ts";

// Each rule's limit is set low so a fixture just over it and one at twice it stay small.
const LIMITS = {
  "size.function-length": 10,
  "size.parameter-count": 4,
  "complexity.cyclomatic": 4,
  "complexity.cognitive": 4,
  "size.file-length": 10,
} as const;

type BandedRule = keyof typeof LIMITS;

// A documented function whose body holds the given number of straight-line statements.
function functionOfStatements(statements: number): string {
  const body = Array.from({ length: statements }, (_, index) => `  const value${index} = ${index};`);
  return ["/** Probe. */", "export function probe(): void {", ...body, "}", ""].join("\n");
}

// A documented function declaring the given number of parameters.
function functionWithParameters(count: number): string {
  const parameters = Array.from({ length: count }, (_, index) => `p${index}: number`).join(", ");
  return `/** Probe. */\nexport function probe(${parameters}): number {\n  return p0;\n}\n`;
}

// A documented function of flat `if` statements, each one decision.
function functionWithBranches(count: number): string {
  const branches = Array.from({ length: count }, (_, index) => `  if (flag === ${index}) {\n    total += ${index};\n  }`);
  return ["/** Probe. */", "export function probe(flag: number): number {", "  let total = 0;", ...branches, "  return total;", "}", ""].join("\n");
}

// A file of the given number of exported constants, one code line each.
function fileOfLines(count: number): string {
  return Array.from({ length: count }, (_, index) => `export const value${index} = ${index};`).join("\n") + "\n";
}

// The one finding a rule reports for a fixture, scanned with every banded rule at its low limit.
// Contract: the test fails unless the rule reports exactly one finding, so a deterministic single result is returned.
function onlyFinding(ruleId: BandedRule, source: string, severity?: Severity): Finding {
  const rules = Object.fromEntries(Object.entries(LIMITS).map(([id, threshold]) => [id, id === ruleId && severity ? { enabled: true, threshold, severity } : { enabled: true, threshold }]));
  const findings = analyseFixture(source, { config: { rules } }).findings.filter((finding) => finding.ruleId === ruleId);
  assert.equal(findings.length, 1, `${ruleId}: ${JSON.stringify(findings)}`);
  return findings[0] as Finding;
}

const CASES: Array<{ ruleId: BandedRule; lower: string; upper: string; lowerAdvice: string; upperAdvice: string; defaultSeverity: Severity }> = [
  { ruleId: "size.function-length", lower: functionOfStatements(10), upper: functionOfStatements(18), lowerAdvice: LOWER_BAND_FUNCTION, upperAdvice: SPLIT_FUNCTION, defaultSeverity: "warning" },
  { ruleId: "size.parameter-count", lower: functionWithParameters(5), upper: functionWithParameters(8), lowerAdvice: LOWER_BAND_PARAMETER, upperAdvice: GROUP_PARAMETERS, defaultSeverity: "warning" },
  { ruleId: "complexity.cyclomatic", lower: functionWithBranches(4), upper: functionWithBranches(8), lowerAdvice: LOWER_BAND_FUNCTION, upperAdvice: SIMPLIFY_PATH, defaultSeverity: "warning" },
  { ruleId: "complexity.cognitive", lower: functionWithBranches(3), upper: functionWithBranches(8), lowerAdvice: LOWER_BAND_FUNCTION, upperAdvice: SIMPLIFY_PATH, defaultSeverity: "warning" },
  { ruleId: "size.file-length", lower: fileOfLines(12), upper: fileOfLines(20), lowerAdvice: LOWER_BAND_FILE, upperAdvice: SPLIT_FILE, defaultSeverity: "error" },
];

test("each size and complexity rule reports in two bands with the advice its emitter fills", () => {
  for (const { ruleId, lower, upper, lowerAdvice, upperAdvice, defaultSeverity } of CASES) {
    const near = onlyFinding(ruleId, lower);
    assert.deepEqual([near.metadata.limitBand, near.severity, near.remediation], ["lower", "advisory", lowerAdvice], `${ruleId} just over its limit`);
    const far = onlyFinding(ruleId, upper);
    assert.deepEqual([far.metadata.limitBand, far.severity, far.remediation], ["upper", defaultSeverity, upperAdvice], `${ruleId} at twice its limit`);
  }
});

test("a configured severity does not lift a lower-band finding", () => {
  const near = onlyFinding("size.function-length", functionOfStatements(10), "error");
  const far = onlyFinding("size.function-length", functionOfStatements(18), "error");
  assert.deepEqual([near.severity, far.severity], ["advisory", "error"]);
});

test("the band boundary compares in floating point", () => {
  // The cognitive default puts the boundary at 22.5, and the parameter-count default puts it at 10.5.
  const cognitiveLimit = 15;
  const parameterLimit = 7;
  const bands = [limitBand(22, cognitiveLimit), limitBand(23, cognitiveLimit), limitBand(10, parameterLimit), limitBand(11, parameterLimit)];
  assert.deepEqual(bands, ["lower", "upper", "lower", "upper"]);
});

// One statement per line, so each form's body is long enough to cross a function-length limit of 10.
function statements(count: number, indent: string): string {
  return Array.from({ length: count }, (_, index) => `${indent}total += ${index};`).join("\n");
}

// Fixture purpose: one legacy script holding each measure-only form once, a var function expression, a member-assigned
// function, an object-literal key function and an immediately invoked function, each over a function-length limit of 10.
// Stable contract: each form reports under its own name, compared sorted so the assertion does not depend on report order.
test("four more function forms are measured by the size and complexity rules only", () => {
  const source = [
    "var Calendar = {};",
    "var render = function () {",
    "  var total = 0;",
    statements(12, "  "),
    "  return total;",
    "};",
    "Calendar.draw = function () {",
    "  var total = 0;",
    statements(12, "  "),
    "  return total;",
    "};",
    "var Widget = {",
    "  paint: function () {",
    "    var total = 0;",
    statements(12, "    "),
    "    return total;",
    "  },",
    "};",
    "(function () {",
    "  var total = 0;",
    statements(12, "  "),
    "  return total;",
    "})();",
    "",
  ].join("\n");
  const findings = analyseFixture(source, { fileName: "legacy.js", config: { rules: { "size.function-length": { threshold: 10 } } } }).findings;
  const measured = findings.filter((finding) => finding.ruleId === "size.function-length").map((finding) => finding.symbol).sort();
  assert.deepEqual(measured, ["<iife>", "Calendar.draw", "Widget.paint", "render"]);
  const seenByOtherBlockRules = findings.filter((finding) => !finding.ruleId.startsWith("size.") && !finding.ruleId.startsWith("complexity.") && measured.includes(finding.symbol ?? ""));
  assert.deepEqual(seenByOtherBlockRules, [], "documentation and naming rules do not see these forms");
});

test("a measure-only callable's decisions count in its own measure, not again in the function around it", () => {
  const branches = Array.from({ length: 6 }, (_, index) => `    if (flag === ${index}) {\n      total += ${index};\n    }`).join("\n");
  const source = ["(function () {", "  var pick = function (flag) {", "    var total = 0;", branches, "    return total;", "  };", "  pick(1);", "})();", ""].join("\n");
  const findings = analyseFixture(source, { fileName: "legacy.js", config: { rules: { "complexity.cyclomatic": { enabled: true, threshold: 4 } } } }).findings;
  const cyclomatic = findings.filter((finding) => finding.ruleId === "complexity.cyclomatic").map((finding) => [finding.symbol, finding.metadata.complexity]);
  assert.deepEqual(cyclomatic, [["pick", 7]]);
});
