// Lock-in tests for the 11 false-positive fixes triaged after the M38 goat-flow report.
// Each test pairs a fixture that USED to trigger a false positive with a fixture that should
// still legitimately fire - so future refactors cannot silently un-fix any of them.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, HIGH_ENTROPY_FIXTURE_VALUE } from "./test-fixtures.ts";
import { countMatches } from "./text-scans.ts";

test("FP-#10 security.inner-html ignores empty-string DOM clearing", () => {
  // Fixture clears via "" and '', then assigns user input on line 4 - only the line-4 assignment
  // should fire because it's the actual injection sink.
  const expectedFiringLine = 4;
  const expectedFindingCount = 1;
  const report = analyseFixture(`function clear(container: HTMLElement, userInput: string): void {
  container.innerHTML = "";
  container.innerHTML = '';
  container.innerHTML = userInput;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "security.inner-html");
  assert.equal(findings.length, expectedFindingCount);
  assert.equal(findings[0]?.line, expectedFiringLine);
});

test("FP-#3 security.process-exec skips RegExp.exec call sites", () => {
  // Fixture: rule.pattern.exec is a RegExp call and must not fire; the two user-controlled
  // child_process calls on lines 5 and 6 must fire as the only real findings.
  const expectedFindingCount = 2;
  const expectedFiringLines = [5, 6];
  const report = analyseFixture(`import { exec, spawn } from "node:child_process";
function check(rule: { pattern: RegExp }, line: string, cmd: string): void {
  const match = rule.pattern.exec(line);
  void match;
  exec(cmd);
  spawn(cmd, ["-la"]);
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "security.process-exec");
  assert.equal(findings.length, expectedFindingCount);
  const lineNumbers = findings.map((entry) => entry.line).sort();
  assert.deepEqual(lineNumbers, expectedFiringLines);
});

test("FP-#8 test-quality.no-assertions recognises custom helpers", () => {
  // Purpose: prove the no-assertions detector accepts assertFoo, fooCheck, `.rejects.` matchers,
  // and still flags the one test in the fixture that genuinely lacks any assertion.
  const report = analyseFixture(`function assertLocalPathError(err: unknown): void { void err; }
function bashCheck(out: string): void { void out; }

test("uses custom assertion helper", () => {
  assertLocalPathError(getSomething());
});

test("uses Check-suffixed helper", () => {
  bashCheck(runScript());
});

test("uses rejects matcher", async () => {
  await expect(doIt()).rejects.toThrow();
});

test("genuinely has no assertion", () => {
  doWork();
});
`);
  const noAssertion = report.findings.filter((entry) => entry.ruleId === "test-quality.no-assertions");
  assert.equal(noAssertion.length, 1);
  assert.match(noAssertion[0]?.message ?? "", /genuinely has no assertion/);
});

test("FP-#11 waste.console-log skips CLI/script paths", () => {
  const cliReport = analyseFixture(`console.log("starting");\n`, { fileName: "src/cli/run.ts" });
  assert.equal(cliReport.findings.some((entry) => entry.ruleId === "waste.console-log"), false);

  const scriptReport = analyseFixture(`console.log("build");\n`, { fileName: "scripts/build.ts" });
  assert.equal(scriptReport.findings.some((entry) => entry.ruleId === "waste.console-log"), false);

  const appReport = analyseFixture(`console.log("debug");\n`, { fileName: "src/dashboard/app.ts" });
  assert.equal(appReport.findings.some((entry) => entry.ruleId === "waste.console-log"), true);
});

test("FP-#2 sensitive-data.high-entropy-string suppresses repo path-shape strings", () => {
  // Purpose: prove path-shape strings clear the entropy gate but a real secret value still fires.
  const realSecret = HIGH_ENTROPY_FIXTURE_VALUE;
  const report = analyseFixture(`const ref = ".goat-flow/tasks/0.1/M38-css-metrics-and-todo-density-calibration.md";
const otherRef = "src/cli/audit/check-content-quality.ts";
const adrRef = "ADR-025-block-all-git-push.md";
const absoluteTaskRef = "/repo/.goat-flow/tasks/1.7.0/M00-side-menu-navigation.md";
const secret = "${realSecret}";
void ref;
void otherRef;
void adrRef;
void absoluteTaskRef;
void secret;
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.high-entropy-string");
  const expectedFindingCount = 1;
  assert.equal(findings.length, expectedFindingCount);
});

test("FP-#5 waste.empty-function skips interface and type-literal signatures", () => {
  const report = analyseFixture(`interface StateFS {
  exists(path: string): boolean;
  readFile(path: string): string | null;
}

function realEmpty(): void {}

function realWork(): number {
  return 1;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.empty-function");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.symbol, "realEmpty");
});

test("FP-#7 waste.unused-parameter skips interface signatures", () => {
  const report = analyseFixture(`interface StateFS {
  readFile(path: string): string;
}

function impl(usedParam: number, unusedParam: string): number {
  return usedParam;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unused-parameter");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata?.parameter, "unusedParam");
});

test("FP-#6 waste.unused-import sees identifiers inside template interpolations", () => {
  const report = analyseFixture(`import { getPackageVersion, formatRow } from "./helpers";

const banner = \`gruff v\${getPackageVersion()}\`;
const row = \`| \${formatRow("x")} |\`;
void banner;
void row;
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unused-import");
  assert.deepEqual(findings.map((entry) => entry.symbol).sort(), []);
});

test("template interpolation code remains visible to executable-source rules", () => {
  const report = analyseFixture(`export function render(input: string): string {
  return \`value: \${eval(input)}\`;
}
`);
  assert.equal(report.findings.some((entry) => entry.ruleId === "security.eval-call"), true);
});

test("unused import detects multiline named imports", () => {
  const report = analyseFixture(`import {
  usedThing,
  unusedThing,
} from "./helpers";

export function render(): string {
  return usedThing();
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unused-import");
  assert.deepEqual(findings.map((entry) => entry.symbol), ["unusedThing"]);
});

test("countMatches does not mutate caller-owned global regex state", () => {
  const pattern = /value/g;
  const preservedLastIndex = 3;
  pattern.lastIndex = preservedLastIndex;
  assert.equal(countMatches("value value", pattern), 2);
  assert.equal(pattern.lastIndex, preservedLastIndex);
});

test("FP-#1 parse-error does not fire on valid nested template literals", () => {
  const report = analyseFixture(`const names = ["a", "b"];
const banner = \`**Skills:** \${names.map((n) => \`\\\`\${n}\\\`\`).join(", ")}\`;
void banner;
`);
  assert.deepEqual(report.diagnostics, []);
});

test("FP-#4 waste.unreachable-code respects braceless if-return guard clauses", () => {
  const report = analyseFixture(`function route(command: string): string {
  if (command === "quality")
    return "quality-result";
  if (command === "skill")
    return "skill-result";
  return "default";
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unreachable-code");
  assert.deepEqual(findings, []);
});

test("FP-#9 docs.stale-comment only validates flags in gruff-mentioning comments", () => {
  // Purpose: prove the unknown-CLI-flag check is gated to comments that name the gruff CLI. Other
  // tools' flags inside other-project comments must not be flagged as unknown gruff options.
  const externalComments = analyseFixture(`// Run \`npm pack --dry-run\` to preview the tarball.
// Use \`node --import tsx\` so the loader sees TypeScript files.
// \`git rev-parse --show-toplevel\` finds the repo root.
// Pass --agent or --harness to inspect the audit profile.
export const value = 1;
`);
  assert.deepEqual(externalComments.findings.filter((entry) => entry.ruleId === "docs.stale-comment" && entry.metadata?.referenceType === "cliFlag"), []);

  // Counterpart: a comment that names gruff-ts and references a fake gruff-ts flag should still fire.
  const selfReport = analyseFixture(`// Run gruff-ts with --imaginary-flag to test the gate.
export const value = 1;
`);
  assert.equal(selfReport.findings.some((entry) => entry.ruleId === "docs.stale-comment" && entry.metadata?.referenceType === "cliFlag"), true);
});
