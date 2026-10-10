// Controls for FAMILY-CONTRACT section 12's code-lines clause (search `Code lines in every line count`): every length a
// rule compares with a threshold counts code lines, so JSDoc, comments, blank lines and decorators never tip a rule,
// while code alone still does.
import assert from "node:assert/strict";
import test from "node:test";

import { analyseFixture, analyseProject } from "./test-fixtures.ts";
import type { Finding } from "./types.ts";

const FUNCTION_LENGTH_LIMIT = 200;
const GENERIC_PARAMETER_MIN_LINES = 30;
const FILE_LENGTH_LIMIT = 1000;
const SHORT_LOOP_BODY_LINES = 10;

// Builds `count` straight-line statements, each one code line.
function steps(count: number, indent = "  "): string {
  return Array.from({ length: count }, (_, index) => `${indent}const step${index} = value + ${index};`).join("\n");
}

// Builds a JSDoc block with `noteLines` extra note lines, all of them documentation.
function jsdoc(noteLines: number, indent = ""): string {
  const notes = Array.from({ length: noteLines }, (_, index) => `${indent} * Note ${index} explains one step.`).join("\n");
  return `${indent}/**\n${indent} * Measures a value.\n${notes}\n${indent} * @param value - the input\n${indent} * @returns the input\n${indent} */`;
}

// Builds `count` comment-only lines.
function comments(count: number, indent = "  "): string {
  return Array.from({ length: count }, (_, index) => `${indent}// Step ${index} is explained here.`).join("\n");
}

// A function whose code lines are its declaration, `bodySteps` statements, the return and the closing brace.
function measureFunction(bodySteps: number, documentation = "", inlineComments = ""): string {
  return `${documentation}\nexport function measure(value: number): number {\n${inlineComments}\n${steps(bodySteps)}\n  return value;\n}\n`;
}

// Keeps the findings one rule reported, in a stable report order.
function findingsFor(findings: readonly Finding[], ruleId: string): Finding[] {
  return findings.filter((finding) => finding.ruleId === ruleId);
}

test("function length counts code lines: a documented function under the limit is quiet, code over it still reports", () => {
  const underLimitSteps = FUNCTION_LENGTH_LIMIT - 10;
  const documented = analyseFixture(measureFunction(underLimitSteps, jsdoc(30), comments(20)));
  assert.deepEqual(findingsFor(documented.findings, "size.function-length"), []);
  const overLimitSteps = FUNCTION_LENGTH_LIMIT - 1;
  const long = findingsFor(analyseFixture(measureFunction(overLimitSteps)).findings, "size.function-length");
  assert.equal(long.length, 1);
  assert.equal(long[0]?.metadata?.["lines"], overLimitSteps + 3);
});

test("function length leaves decorator lines out of a method's count", () => {
  const methodSteps = FUNCTION_LENGTH_LIMIT - 4;
  const source = `function traced(_target: object, _key: string): void {}\n\nexport class Ledger {\n  @traced\n  @traced\n  @traced\n  measure(value: number): number {\n${steps(methodSteps, "    ")}\n    return value;\n  }\n}\n`;
  assert.deepEqual(findingsFor(analyseFixture(source).findings, "size.function-length"), []);
});

test("the generic-parameter length gate counts code lines, so a JSDoc never makes a placeholder name report", () => {
  const shortSteps = GENERIC_PARAMETER_MIN_LINES - 6;
  const documented = analyseFixture(measureFunction(shortSteps, jsdoc(10)));
  assert.deepEqual(findingsFor(documented.findings, "naming.generic-parameter"), []);
  const longSteps = GENERIC_PARAMETER_MIN_LINES;
  assert.equal(findingsFor(analyseFixture(measureFunction(longSteps)).findings, "naming.generic-parameter").length, 1);
});

test("the context-documentation length gate counts code lines, so documenting a long-looking function stays quiet", () => {
  const underLimitSteps = FUNCTION_LENGTH_LIMIT - 10;
  const documented = analyseFixture(measureFunction(underLimitSteps, jsdoc(30), comments(15)));
  assert.deepEqual(findingsFor(documented.findings, "docs.missing-why-for-complex-code"), []);
});

test("file length leaves decorator lines out, and code over the limit still reports", () => {
  const decorated = Array.from({ length: 10 }, (_, index) => `  @tag\n  @tag\n  value${index} = ${index};`).join("\n");
  const header = `function tag(_target: object, _key: string): void {}\n\nexport class Ledger {\n${decorated}\n}\n`;
  const headerCodeLines = 13;
  // Adds `count` one-line exports, each a code line.
  const filler = (count: number) => Array.from({ length: count }, (_, index) => `export const filler${index} = ${index};`).join("\n");
  const atLimit = analyseFixture(`${header}${filler(FILE_LENGTH_LIMIT - headerCodeLines)}\n`);
  assert.deepEqual(findingsFor(atLimit.findings, "size.file-length"), []);
  const overLimit = analyseFixture(`${header}${filler(FILE_LENGTH_LIMIT - headerCodeLines + 1)}\n`);
  assert.equal(findingsFor(overLimit.findings, "size.file-length").length, 1);
});

test("module concentration measures code lines, so a documented module's share does not grow", () => {
  // Builds a production module of `lines` code lines, optionally led by documentation.
  const module = (name: string, lines: number, documentation = "") =>
    `${documentation}${Array.from({ length: lines }, (_, index) => `export const ${name}${index} = ${index};`).join("\n")}\n`;
  const notes = Array.from({ length: 12 }, (_, index) => `// Note ${index} about the core module.`).join("\n") + "\n";
  const quiet = analyseProject({ "src/core.ts": module("core", 100, notes), "src/alpha.ts": module("alpha", 28), "src/beta.ts": module("beta", 28), "src/gamma.ts": module("gamma", 28) });
  assert.deepEqual(findingsFor(quiet.findings, "design.large-module-concentration"), []);
  const dominant = analyseProject({ "src/core.ts": module("core", 112), "src/alpha.ts": module("alpha", 28), "src/beta.ts": module("beta", 28), "src/gamma.ts": module("gamma", 28) });
  assert.equal(findingsFor(dominant.findings, "design.large-module-concentration").length, 1);
});

test("a for-of body's span counts code lines, so comments never cost a short loop variable its leniency", () => {
  // Builds a function whose for-of body holds `statements` code lines plus the given comments.
  const loop = (statements: number, inlineComments: string) =>
    `export function weigh(files: readonly string[]): number {\n  let total = 0;\n  for (const f of files) {\n${inlineComments}\n${Array.from({ length: statements }, (_, index) => `    total += f.length + ${index};`).join("\n")}\n  }\n  return total;\n}\n`;
  const shortBody = SHORT_LOOP_BODY_LINES - 2;
  const commented = analyseFixture(loop(shortBody, comments(6, "    ")));
  assert.deepEqual(findingsFor(commented.findings, "naming.short-variable").filter((finding) => finding.message.includes("`f`")), []);
  const longBody = SHORT_LOOP_BODY_LINES;
  const long = analyseFixture(loop(longBody, ""));
  assert.equal(findingsFor(long.findings, "naming.short-variable").filter((finding) => finding.message.includes("`f`")).length, 1);
});
