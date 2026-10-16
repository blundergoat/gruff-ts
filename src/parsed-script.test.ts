// Shared-parse boundary tests: AST callable discovery (the shapes regex discovery missed), the
// legacy one-block-per-line and anonymous-callback policies, TSX parsing, and the one-parse-per-
// script invariant that keeps the boundary from silently regressing into multiple parser calls.
import assert from "node:assert/strict";
import test from "node:test";
import { functionBlocks } from "./blocks.ts";
import type { SourceFile } from "./discovery.ts";
import { parsedScriptParseCount, parseScript } from "./parsed-script.ts";
import { analyseSecurityFlow } from "./security-flow-rules.ts";
import { maskNonCode } from "./source-text.ts";
import { analyseFixture, analyseProject } from "./test-fixtures.ts";

// Parses one fixture through the shared boundary and returns its discovered blocks.
function discoveredBlocks(fileName: string, source: string) {
  const parsed = parseScript({ displayPath: fileName, isScript: true }, source);
  return functionBlocks(source, maskNonCode(source), parsed);
}

test("AST discovery finds generic, multi-line, and parenless callables the regex missed", () => {
  const source = `// File overview: discovery fixture.
export function generic<T extends string>(first: Map<string, number>, second: [string, number], third: { nested: string } = { nested: "x" }): T[] {
  return [];
}
const parenless = value => value + 1;
export async function multiLine(
  first: string,
  second: number,
): Promise<void> {
  await Promise.resolve(first + second);
}
`;
  const blocks = discoveredBlocks("fixture.ts", source);
  const byName = new Map(blocks.map((block) => [block.name, block]));

  // Generic signature: discovered, and the parameter count comes from AST nodes, so the commas
  // inside the generic type, tuple type, and object default do not inflate it (three, not eight).
  assert.equal(byName.get("generic")?.parameterCount, 3);
  assert.equal(byName.get("generic")?.isExported, true);
  // Parenless single-argument arrow: discovered with exactly one parameter.
  assert.equal(byName.get("parenless")?.parameterCount, 1);
  // Multi-line signature with async export: discovered at its declaration line (the sixth fixture
  // line, where `export async function multiLine(` sits).
  const MULTI_LINE_DECLARATION_LINE = 6;
  assert.equal(byName.get("multiLine")?.parameterCount, 2);
  assert.equal(byName.get("multiLine")?.declarationLine, MULTI_LINE_DECLARATION_LINE);
});

test("AST discovery keeps the legacy anonymous-callback and one-block-per-line policies", () => {
  const source = `// File overview: policy fixture.
function outer(items: string[]): number {
  items.forEach(item => {
    void item;
  });
  function inner(): void {}
  return items.length;
}
const first = () => 1; const second = () => 2;
`;
  const names = discoveredBlocks("fixture.ts", source).map((block) => block.name);
  // Named declarations at any nesting depth stay discovered; anonymous argument callbacks stay
  // out (their naming policy is deferred), and one line still yields at most one block.
  assert.deepEqual(names, ["outer", "inner", "first"]);
});

test("TSX components parse cleanly and their callables are discovered", () => {
  const source = `// File overview: tsx fixture.
export const Widget = (props: { label: string }) => {
  return <div title="Don't stop">{props.label}</div>;
};
`;
  const parsed = parseScript({ displayPath: "widget.tsx", isScript: true }, source);
  assert.equal(parsed?.diagnostics.length, 0);
  const blocks = functionBlocks(source, maskNonCode(source), parsed);
  assert.equal(blocks.some((block) => block.name === "Widget"), true);
});

test("parameter-count uses AST parameters, not commas inside nested type syntax", () => {
  // Six real parameters whose generic, tuple, and default commas would comma-split to twelve;
  // the AST count keeps the rule quiet at the default threshold of seven.
  const quiet = analyseFixture(`// File overview: parameter-count fixture.
export function wideTypes(a: Map<string, number>, b: [string, number], c: Set<Map<string, string>>, d: { nested: string } = { nested: "x" }, e: Array<[number, number]>, f: string): void {
  void [a, b, c, d, e, f];
}
`);
  assert.equal(quiet.findings.some((finding) => finding.ruleId === "size.parameter-count"), false);

  // Eight plain parameters stay a true positive with the actual count in message and metadata.
  const loud = analyseFixture(`// File overview: parameter-count fixture.
export function manyParams(a: string, b: string, c: string, d: string, e: string, f: string, g: string, h: string): void {
  void [a, b, c, d, e, f, g, h];
}
`);
  // The fixture declares exactly eight plain parameters (a through h).
  const DECLARED_PLAIN_PARAMETERS = 8;
  const finding = loud.findings.find((found) => found.ruleId === "size.parameter-count");
  assert.equal(finding?.metadata.parameters, DECLARED_PLAIN_PARAMETERS);
});

test("parameter text keeps names that follow end-of-line comments", () => {
  const report = analyseFixture(`function inspect(
  first: string, // Retained parameter.
  second: string,
): string {
  return first;
}
`);
  const unusedParameters = report.findings
    .filter((finding) => finding.ruleId === "waste.unused-parameter")
    .map((finding) => finding.metadata.parameter);

  assert.deepEqual(unusedParameters, ["second"]);
});

test("AST export classification handles split declarations and same-name class methods", () => {
  const splitExportBlocks = discoveredBlocks("split-export.ts", `export async function
publicApi(): Promise<void> {
  await Promise.resolve();
}
`);
  const publicApi = splitExportBlocks.find((block) => block.name === "publicApi");
  assert.equal(publicApi?.declarationLine, 2);
  assert.equal(publicApi?.startLine, 2);
  assert.equal(publicApi?.isPublic, true);
  assert.equal(publicApi?.isExported, true);

  const sameNameBlocks = discoveredBlocks("same-name.ts", `function helper(): number {
  return 1;
}
class Worker {
  helper(): number {
    return 2;
  }
}
export { helper };
`).filter((block) => block.name === "helper");
  assert.deepEqual(
    sameNameBlocks.map((block) => ({ declarationLine: block.declarationLine, isExported: block.isExported })),
    [
      { declarationLine: 1, isExported: true },
      { declarationLine: 5, isExported: false },
    ],
  );
});

test("one analysed script parses exactly once per run", () => {
  const before = parsedScriptParseCount();
  analyseProject({
    "first.ts": "// File overview: parse-count fixture.\nexport const one = 1;\n",
    "second.ts": "// File overview: parse-count fixture.\nexport function two(): number {\n  return 2;\n}\n",
  });
  // Diagnostics, security-flow analysis, block discovery, and docblock rules all consumed the
  // same two parses; any additional parser call in the pipeline would raise this delta.
  assert.equal(parsedScriptParseCount() - before, 2);

  const beforeSymbolScope = parsedScriptParseCount();
  analyseProject({
    "scoped.ts": "// File overview: symbol-scope parse-count fixture.\nexport function scoped(): number {\n  return 1;\n}\n",
    // The line-count budget rejects this file before parsing; symbol widening must not reparse it.
    "oversized.ts": "\n".repeat(20_001),
  }, { changedRanges: "3-3" });
  assert.equal(parsedScriptParseCount() - beforeSymbolScope, 1);
});

// Fixture purpose: the one-parse-per-run assertion above is only as wide as the parse counter. The
// security-flow scanner owns the pipeline's second parser entry point, and it used to call
// createSourceFile directly, so an analysis-path caller that stopped threading the run's parse
// would have re-parsed every script while the count still read one per file.
// Stable contract: every parser entry point in the pipeline increments the shared counter.
test("the security-flow fallback parse is counted by the shared boundary", () => {
  const fileStub = { displayPath: "flow.ts", absolutePath: "/flow.ts", isScript: true } as SourceFile;
  const source = "function read(req) {\n  const target = req.query.path;\n  fs.readFile(target);\n}\n";

  const before = parsedScriptParseCount();
  analyseSecurityFlow(fileStub, source, []);
  assert.equal(parsedScriptParseCount() - before, 1, "the fallback parse must be visible to the counter");

  // Supplying the run's shared parse must add no parse of its own.
  const shared = parseScript(fileStub, source);
  const beforeShared = parsedScriptParseCount();
  analyseSecurityFlow(fileStub, source, [], shared?.sourceFile);
  assert.equal(parsedScriptParseCount() - beforeShared, 0, "a threaded shared parse must not reparse");
});

// Fixture covers the report's repro B: its `CLIError` parameter property and explicit-field control, plus every
// parameter-property modifier beside one ordinary parameter nothing reads.
test("M22 report repro B: constructor parameter properties are members, while an unused ordinary parameter still fires", () => {
  const report = analyseFixture([
    "/** Structured error carrying an exit code for CLI process termination. */",
    "export class CLIError extends Error {",
    "  constructor(",
    "    message: string,",
    "    public readonly exitCode: number,",
    "  ) {",
    "    super(message);",
    "  }",
    "}",
    "",
    "/** Control: the same class written with an explicit field instead of a parameter property. */",
    "export class CLIErrorExplicit extends Error {",
    "  readonly exitCode: number;",
    "",
    "  constructor(message: string, exitCode: number) {",
    "    super(message);",
    "    this.exitCode = exitCode;",
    "  }",
    "}",
    "",
    "/** Every parameter-property modifier, including a bare readonly, beside one ordinary parameter nothing reads. */",
    "export class Settings {",
    "  constructor(private host: string, protected port: number, readonly label: string, ignoredCode: number) {}",
    "}",
    "",
  ].join("\n"));
  const unusedParameters = report.findings.filter((entry) => entry.ruleId === "waste.unused-parameter").map((entry) => entry.metadata?.parameter);

  assert.deepEqual(unusedParameters, ["ignoredCode"]);
});

// A template interpolation's braces are not a function block. Taking them for one collapsed an
// expression-bodied arrow's body to the interpolation's blanked contents, so every parameter used beside the
// template read as unused. M46 measured four such findings across the TypeScript corpus.
test("M46: an expression-bodied arrow whose body holds a template interpolation reads its parameters", () => {
  const report = analyseFixture([
    "/** The corpus shape: the parameter is used on the line that also carries a template interpolation. */",
    "export const routeConflict = (messages: string[]): string =>",
    "  [",
    "    \"Conflicting routes:\",",
    "    ...messages.map((message) => `  - ${message}`),",
    "  ].join(\"\\n\");",
    "",
    "/** Control: the same body with no interpolation, which always read correctly. */",
    "export const routeConflictPlain = (entries: string[]): string =>",
    "  [",
    "    \"Conflicting routes:\",",
    "    ...entries.map((entry) => \"  - \" + entry),",
    "  ].join(\"\\n\");",
    "",
    "/** Control: an expression body holding an interpolation that reads nothing from the signature. */",
    "export const fixedLabel = (unreadInput: string[]): string =>",
    "  [`  - fixed`].join(\"\\n\");",
    "",
  ].join("\n"));
  const unusedParameters = report.findings.filter((entry) => entry.ruleId === "waste.unused-parameter").map((entry) => entry.metadata?.parameter);

  assert.deepEqual(unusedParameters, ["unreadInput"]);
});

// Fixture covers the report's repro C: a later default reading an earlier parameter, its body-default control, and
// a parameter named only inside another parameter's function type.
test("M22 report repro C: a parameter read by a later parameter's default is used, while an unread one still fires", () => {
  const report = analyseFixture([
    "/** Run a handler, defaulting the working directory to the project root. */",
    "export function describeRun(",
    "  projectRoot: string,",
    "  command: string,",
    "  cwd: string = projectRoot,",
    "): { command: string; cwd: string } {",
    "  return { command, cwd };",
    "}",
    "",
    "/** Control: the same defaulting written in the body instead of the signature. */",
    "export function describeRunControl(",
    "  projectRoot: string,",
    "  command: string,",
    "  cwd?: string,",
    "): { command: string; cwd: string } {",
    "  return { command, cwd: cwd ?? projectRoot };",
    "}",
    "",
    "/** A default that reads nothing, and a function-typed parameter whose own type names a parameter. */",
    "export function formatValue(value: string, fallback: string, format: (fallback: string) => string = (text) => text): string {",
    "  return format(value);",
    "}",
    "",
  ].join("\n"));
  const unusedParameters = report.findings.filter((entry) => entry.ruleId === "waste.unused-parameter").map((entry) => entry.metadata?.parameter);

  assert.deepEqual(unusedParameters, ["fallback"]);
});
