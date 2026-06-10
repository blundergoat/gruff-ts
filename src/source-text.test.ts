// Focused parser-diagnostic tests for source-text helpers that are otherwise exercised through scans.
import assert from "node:assert/strict";
import test from "node:test";
import { parseDiagnostics } from "./source-text.ts";

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
