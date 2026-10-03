// Focused parser-diagnostic and masking tests for source-text helpers that are otherwise exercised through scans.
import assert from "node:assert/strict";
import test from "node:test";
import { maskNonCode, parseDiagnostics } from "./source-text.ts";
import { analyseFixture } from "./test-fixtures.ts";

// The interpolation shapes the external gruff-ts false-positive report lists for the masking stack. A single depth
// counter passed some of them by luck; each must mask every template body and hand the next line back as code.
test("masking gives every template interpolation its own frame, however the templates nest", () => {
  const shapes = ["`${a}`", "`${`${a}`}`", "`x${a}y${`z${b}`}w`", "`${ { a: 1 }.a }`", "`${`${`${a}`}`}`", "`${a}` + `${b}`"];
  for (const shape of shapes) {
    const source = "const value = " + shape + ";\nconst after = 1;\n";
    const masked = maskNonCode(source);
    const [valueLine, afterLine] = masked.split("\n");

    assert.equal(masked.length, source.length, `${shape}: masking kept every offset`);
    assert.equal(afterLine, "const after = 1;", `${shape}: the next line is code again`);
    assert.doesNotMatch(valueLine ?? "", /[wxyz]/, `${shape}: every template body is masked`);
  }
});

// Braces that are not code must not move an interpolation's depth: object literals count, while braces inside a
// string or a block comment within the interpolation are masked and never close it early.
test("masking keeps interpolation braces balanced across object literals, strings and comments", () => {
  const source = "const text = `a ${format({ when: \"}\", /* } */ depth: { level: 1 } })} b`;\nexport function next(): number {\n  return 1;\n}\n";
  const masked = maskNonCode(source);
  const lines = masked.split("\n");

  assert.equal(masked.length, source.length);
  assert.equal(lines[1], "export function next(): number {");
  assert.equal(lines[2], "  return 1;");
  assert.match(lines[0] ?? "", /depth: \{ level: 1 \} \}\)\}\s+`;$/);
  assert.doesNotMatch(lines[0] ?? "", /\/\*|\ba b\b/);
});

test("parse diagnostics accept valid TSX text delimiters", () => {
  const diagnostics = parseDiagnostics(scriptFile("src/Badge.tsx"), `export function Badge(): JSX.Element {
  return <span>)</span>;
}
`);

  assert.deepEqual(diagnostics, []);
});

test("parse diagnostics report real TSX syntax errors", () => {
  const diagnostics = parseDiagnostics(scriptFile("src/Broken.tsx"), `export function Broken(): JSX.Element {
  return <div><span></div>;
}
`);

  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0]?.diagnosticType, "parse-error");
  assert.equal(diagnostics[0]?.filePath, "src/Broken.tsx");
  assert.equal(diagnostics[0]?.line, 2);
  assert.match(diagnostics[0]?.message ?? "", /JSX element 'span'/);
});

test("parse diagnostics collapse multiple parser errors into one file summary", () => {
  const diagnostics = parseDiagnostics(scriptFile("golden.js"), `export class Demo {
  …
  static value = 1;
  …
}
`);

  assert.equal(diagnostics.length, 1);
  assert.equal(diagnostics[0]?.line, 2);
  assert.match(diagnostics[0]?.message ?? "", /2 diagnostics in this file; first: Invalid character/);
});

test("parse diagnostics accept template literal interpolation", () => {
  const diagnostics = parseDiagnostics(scriptFile("src/template.ts"), `const names = ["a", "b"];
const banner = \`**Skills:** \${names.map((name) => \`\\\`\${name}\\\`\`).join(", ")}\`;
void banner;
`);

  assert.deepEqual(diagnostics, []);
});

test("parse diagnostics accept regex literals with bracket characters", () => {
  const diagnostics = parseDiagnostics(scriptFile("src/regex.ts"), `const pattern = /[})\\]]/;
export function matches(value: string): boolean {
  return pattern.test(value);
}
`);

  assert.deepEqual(diagnostics, []);
});

test("parse diagnostics accept ordinary balanced TypeScript and JavaScript", () => {
  assert.deepEqual(parseDiagnostics(scriptFile("src/example.ts"), `export function sum(values: number[]): number {
  return values.reduce((total, value) => total + value, 0);
}
`), []);
  assert.deepEqual(parseDiagnostics(scriptFile("src/example.js"), `export function sum(values) {
  return values.reduce((total, value) => total + value, 0);
}
`), []);
});

// Minimal source shape consumed by parseDiagnostics.
function scriptFile(displayPath: string): { displayPath: string; isScript: boolean } {
  return { displayPath, isScript: true };
}

// M22 external report fixtures. The sources are the appendix files of the gruff-ts false-positive report, and each
// reproduction is checked beside its control, because a control that changes is as informative as a repro that does.
const REPORT_NESTED_LABEL = [
  "/**",
  " * Build a label whose interpolation contains a second template literal.",
  " *",
  " * @param count - number of items",
  " * @returns the finished label",
  " */",
  "export function buildLabel(count: number): string {",
  "  return `${count} item${count > 1 ? \"s\" : \"\"}${",
  "    count > 10 ? ` (${count} is a lot)` : \"\"",
  "  }`;",
  "}",
];
const REPORT_FLAT_LABEL = [
  "/**",
  " * Build a label without nesting a template literal inside an interpolation.",
  " *",
  " * @param count - number of items",
  " * @returns the finished label",
  " */",
  "export function buildLabel(count: number): string {",
  "  const plural = count > 1 ? \"s\" : \"\";",
  "  const suffix = count > 10 ? \" (that is a lot)\" : \"\";",
  "  return `${count} item${plural}${suffix}`;",
  "}",
];
const REPORT_GRADE_FOR = [
  "/**",
  " * Grade a ratio. This function has a real body and reads its parameter four times.",
  " *",
  " * @param pct - ratio from 0 to 1",
  " * @returns a grade letter",
  " */",
  "export function gradeFor(pct: number): string {",
  "  if (pct >= 0.9) return \"A\";",
  "  if (pct >= 0.8) return \"B\";",
  "  if (pct >= 0.7) return \"C\";",
  "  return \"F\";",
  "}",
];
const REPORT_SWALLOW_SILENTLY = [
  "/**",
  " * Swallow an error with no rationale at all. This SHOULD trip waste.swallowed-catch.",
  " *",
  " * @param run - the operation to attempt",
  " * @returns nothing",
  " */",
  "export function swallowSilently(run: () => void): void {",
  "  try {",
  "    run();",
  "  } catch {}",
  "}",
];

// Joins report fixture blocks into one module with the blank line the appendix files put between declarations.
function reportModule(header: string, ...blocks: string[][]): string {
  return [header, "", ...blocks.flatMap((block) => [...block, ""])].join("\n");
}

test("M22 report repro A: a nested template literal leaves the next function analysed, like its flattened control", () => {
  const nestedSource = reportModule("/** Repro A: a template literal nested inside an interpolation of another template literal. */", REPORT_NESTED_LABEL, REPORT_GRADE_FOR);
  const controlSource = reportModule("/** Repro A control: identical to repro-a-nested-template.ts, with the nested template flattened. */", REPORT_FLAT_LABEL, REPORT_GRADE_FOR);
  // The waste-pillar rule ids one module reports, in report order.
  const wasteRuleIds = (source: string): string[] => analyseFixture(source).findings.filter((entry) => entry.ruleId.startsWith("waste.")).map((entry) => entry.ruleId);

  assert.deepEqual(wasteRuleIds(nestedSource), []);
  assert.deepEqual(wasteRuleIds(controlSource), []);
  assert.equal(maskNonCode(nestedSource).split("\n").includes("export function gradeFor(pct: number): string {"), true);
});

test("M22 report repro E: the swallowed catch below a nested template is still reported, like its control", () => {
  const nestedSource = reportModule("/** Repro E: the same desync also SUPPRESSES real findings after the nested template. */", REPORT_NESTED_LABEL, REPORT_SWALLOW_SILENTLY);
  const controlSource = reportModule("/** Repro E control: repro-e-false-negative.ts with the nested template flattened. */", REPORT_FLAT_LABEL, REPORT_SWALLOW_SILENTLY);
  // The waste-pillar rule ids one module reports, sorted into a stable order so the pair compares by content.
  const wasteRuleIds = (source: string): string[] => analyseFixture(source).findings.filter((entry) => entry.ruleId.startsWith("waste.")).map((entry) => entry.ruleId).sort();

  assert.deepEqual(wasteRuleIds(nestedSource), ["waste.swallowed-catch"]);
  assert.deepEqual(wasteRuleIds(controlSource), ["waste.swallowed-catch"]);
});
