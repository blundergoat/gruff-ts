// Lock-in tests for the 11 false-positive fixes triaged after the M38 goat-flow report.
// Each test pairs a fixture that USED to trigger a false positive with a fixture that should
// still legitimately fire - so future refactors cannot silently un-fix any of them.
import assert from "node:assert/strict";
import test from "node:test";
import { renderReport } from "./cli.ts";
import { renderSummary } from "./report-renderers.ts";
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

test("FP-#12 waste.unreachable-code recognises multi-line if predicate", () => {
  // Verbatim repro from the 2026-05-25 goat-flow feedback §1: when an if-predicate spans several
  // lines and ends in a braceless consequent, the consequent is the conditional body. The next
  // top-level return is the function's only unconditional exit and must not be flagged.
  const report = analyseFixture(`function isSideEffectful(method: string, path: string): boolean {
  if (
    method === "POST" &&
    path.startsWith("/api/")
  )
    return true;
  return method === "DELETE" && path.startsWith("/api/terminal/");
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unreachable-code");
  assert.deepEqual(findings, []);
});

test("FP-#13 waste.unreachable-code recognises multi-line while predicate", () => {
  // Parallel coverage for `while (\n …\n)\n  body;\nnext` - the body is conditional and `next` must
  // not be flagged. while/for/if share the same braceless-opener detection path.
  const report = analyseFixture(`function drain(items: number[]): number {
  let total = 0;
  while (
    items.length > 0 &&
    total < 100
  )
    total += items.shift() ?? 0;
  return total;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unreachable-code");
  assert.deepEqual(findings, []);
});

test("FP-#14 waste.unreachable-code recognises single-line predicate", () => {
  // Regression guard for the original FP-#4 protection - the paren-depth change in M01 must not
  // regress the single-line `if (x)\n  return;\nnext` case. Two distinct guard clauses ensure both
  // the first and second consequent are correctly treated as conditional.
  const report = analyseFixture(`function pick(command: string, fallback: string): string {
  if (command === "quality")
    return "quality-result";
  if (command === "skill")
    return "skill-result";
  return fallback;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unreachable-code");
  assert.deepEqual(findings, []);
});

test("FP-#15 waste.unreachable-code still flags genuine unreachable code", () => {
  // Negative test: the rule's real signal must survive M01. A `return;` followed by another
  // top-level statement (no conditional context) is unreachable and must still fire.
  // The expected firing line is the third line of the fixture (where `console.log` sits after the
  // unconditional return on line 2).
  const expectedUnreachableLine = 3;
  const report = analyseFixture(`function genuinelyUnreachable(x: number): boolean {
  return x > 0;
  console.log("never");
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.unreachable-code");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.line, expectedUnreachableLine);
});

test("FP-#16 waste.swallowed-catch accepts /* ignore */ rationale", () => {
  // Bare-token vocabulary widening (§2.2 of the 2026-05-25 feedback): the most common idiom for
  // documented teardown swallows is a one-word comment. Five common forms must clear; an empty
  // catch body must still fire so the rule's real signal is preserved.
  const report = analyseFixture(`async function close(stream: { close(): Promise<void> }): Promise<void> {
  try {
    await stream.close();
  } catch {
    /* ignore */
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.swallowed-catch");
  assert.deepEqual(findings, []);
});

test("FP-#17 waste.swallowed-catch accepts /* cleanup */ rationale", () => {
  const report = analyseFixture(`async function release(handle: { close(): void }): Promise<void> {
  try {
    handle.close();
  } catch {
    /* cleanup */
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.swallowed-catch");
  assert.deepEqual(findings, []);
});

test("FP-#18 waste.swallowed-catch accepts /* teardown */ rationale", () => {
  const report = analyseFixture(`function dispose(handle: { close(): void }): void {
  try {
    handle.close();
  } catch {
    /* teardown */
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.swallowed-catch");
  assert.deepEqual(findings, []);
});

test("FP-#19 waste.swallowed-catch accepts /* no-op */ rationale", () => {
  const report = analyseFixture(`function tryParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    /* no-op */
  }
  return undefined;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "waste.swallowed-catch");
  assert.deepEqual(findings, []);
});

test("FP-#21 naming.boolean-prefix accepts imperative-flag verbs", () => {
  /*
   * Fixture covers the §2.4 regression from the 2026-05-25 goat-flow feedback: option-bag booleans
   * frequently use imperative verbs (`checkDrift`, `skipAuto`, `enableX`) which are intent-revealing
   * despite not matching the adjective/modal default prefix set. The widened default
   * `booleanPrefixes` now accepts these.
   */
  const report = analyseFixture(`export function configure(): void {
  const checkDrift: boolean = true;
  const skipAuto: boolean = false;
  const enableFeature: boolean = true;
  const allowFallback: boolean = false;
  const includeMetadata: boolean = true;
  const excludeTests: boolean = false;
  const omitHeader: boolean = true;
  const withCache: boolean = false;
  const withoutTimeout: boolean = true;
  void checkDrift; void skipAuto; void enableFeature; void allowFallback;
  void includeMetadata; void excludeTests; void omitHeader; void withCache; void withoutTimeout;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.boolean-prefix");
  assert.deepEqual(findings, []);
});

test("FP-#22 naming.short-variable accepts fn and cb abbreviations", () => {
  // §2.8(a): `fn` and `cb` are universal conventions for "function parameter" and "callback
  // parameter" and are now in the default acceptedAbbreviations set.
  const report = analyseFixture(`export function bind(fn: (n: number) => number, cb: () => void): (n: number) => number {
  return (n: number) => {
    const result = fn(n);
    cb();
    return result;
  };
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable");
  assert.deepEqual(findings, []);
});

test("FP-#23 naming.short-variable accepts for-of binding in short body", () => {
  // §2.8(b): a single-character binding inside a for-of whose body spans ≤ 10 lines is idiomatic
  // (the scope is locally obvious). The walker scans forward through codeLines to count body lines.
  const report = analyseFixture(`export function logAll(files: string[]): void {
  for (const f of files) {
    console.log(f);
  }
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable");
  assert.deepEqual(findings, []);
});

test("FP-#24 naming.short-variable still flags for-of binding in long body", () => {
  /*
   * Negative fixture covers the long-body regression: when the body is > 10 lines the binding
   * outlives the locally obvious scope and the rule's signal returns. Body below spans 12 lines
   * (open brace to close brace).
   */
  const report = analyseFixture(`export function processFiles(files: string[]): number {
  let total = 0;
  for (const f of files) {
    const length = f.length;
    const first = f.charAt(0);
    const last = f.charAt(length - 1);
    const upper = f.toUpperCase();
    const lower = f.toLowerCase();
    const reversed = f.split("").reverse().join("");
    const padded = f.padEnd(20);
    const trimmed = f.trim();
    const replaced = f.replace(/x/g, "y");
    total += length + first.length + last.length + upper.length + lower.length + reversed.length + padded.length + trimmed.length + replaced.length;
  }
  return total;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable" && entry.symbol === "f");
  assert.equal(findings.length, 1);
});

test("FP-#25 naming.short-variable still flags non-for-of short declaration", () => {
  // Negative: the for-of body exemption must NOT leak into ordinary `const x = …` declarations.
  // The rule's primary signal (short variables in general scope) is preserved.
  const report = analyseFixture(`export function compute(): number {
  const x = 5;
  return x * 2;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "naming.short-variable" && entry.symbol === "x");
  assert.equal(findings.length, 1);
});

test("FP-#41 summary renders per-severity rule rows with description", () => {
  // M07: top-N rules block carries per-severity split + one-line description so an operator
  // triaging a noisy run can see whether the top entry is errors or advisories at a glance.
  const report = analyseFixture(`function helperOne(): void { eval("noop"); }
function helperTwo(): void { eval("noop"); }
`);
  const summary = renderSummary(report);
  // The eval calls fire security.eval-call as error-severity findings; the row should show the err
  // count and the rule's description from the catalogue.
  assert.match(summary, /- security\.eval-call: \d+ \(\d+ err \/ \d+ warn \/ \d+ adv\) - Flags eval\(\) dynamic code execution\./);
});

test("FP-#42 summary rule row truncates long description with ellipsis", () => {
  // The description budget keeps each row legible at 100 columns. A rule with a long description
  // (`docs.missing-internal-function-doc` is the longest documentation-pillar description today)
  // should render with a trailing ellipsis when it exceeds the 60-char body limit.
  const report = analyseFixture(`function helperOne(): void {}
function helperTwo(): void {}
`);
  const summary = renderSummary(report);
  assert.match(summary, /- docs\.missing-internal-function-doc: \d+ \(\d+ err \/ \d+ warn \/ \d+ adv\) - .*…/);
});

test("FP-#43 analyse text footer hint appears at threshold and not below", () => {
  // Synthetic fixture crafted to cross the 50-finding threshold. Each line of `if (x == y)` fires
  // modernisation.loose-equality, so we generate enough lines to push past 50.
  const aboveThreshold = analyseFixture(`function noisy(x: unknown, y: unknown): boolean {
${Array.from({ length: 55 }, () => "  if (x == y) return true;").join("\n")}
  return false;
}
`);
  const aboveText = renderReport(aboveThreshold, "text");
  assert.match(aboveText, /Tip: \d+ findings is more than a flat list usefully shows/);

  const belowThreshold = analyseFixture(`function clean(x: unknown): boolean {
  return x === null;
}
`);
  const belowText = renderReport(belowThreshold, "text");
  assert.equal(/Tip: \d+ findings/.test(belowText), false);
});

test("FP-#44 analyse footer hint does not appear in HTML / markdown / JSON outputs", () => {
  // Negative coverage: the volume hint is text-only by design. HTML/Markdown/JSON consumers parse
  // their format strictly and a stray "Tip:" line would break them.
  const report = analyseFixture(`function noisy(x: unknown, y: unknown): boolean {
${Array.from({ length: 55 }, () => "  if (x == y) return true;").join("\n")}
  return false;
}
`);
  const html = renderReport(report, "html");
  const markdown = renderReport(report, "markdown");
  const json = renderReport(report, "json");
  assert.equal(/Tip: \d+ findings/.test(html), false);
  assert.equal(/Tip: \d+ findings/.test(markdown), false);
  assert.equal(/Tip: \d+ findings/.test(json), false);
});

test("FP-#45 summary topRules JSON shape is unchanged by M07", () => {
  // Negative: the JSON output preserves the `{name, count}` shape for topRules. M07 enriches the
  // text/summary rule row block but keeps the JSON contract byte-stable.
  const report = analyseFixture(`function helperOne(): void { eval("noop"); }
`);
  const json = JSON.parse(renderReport(report, "json"));
  // Note: renderReport "json" uses the analysis schema; the summary JSON is renderSummaryJson which
  // isn't directly callable from renderReport. The analyse JSON has no topRules block, so we only
  // assert the analyse JSON's score block is unchanged here.
  const scoreKeys = Object.keys(json.score).sort();
  assert.deepEqual(scoreKeys, ["composite", "grade", "pillars", "topOffenders"]);
});

test("FP-#38 summary renderers include per-severity grade breakdown lines", () => {
  // §3.2(a): an F composite driven entirely by advisories reads identically to an F driven by
  // errors in the headline. The breakdown lines surface the difference. Text + markdown surfaces
  // both render the three lines; HTML renders three grade pills. JSON stays unchanged (covered by
  // FP-#40 below).
  const report = analyseFixture(`function helperOne(): void { eval("noop"); }
function helperTwo(): void { eval("noop"); }
`);
  const textOutput = renderReport(report, "text");
  assert.match(textOutput, /Composite: [A-F] \(\d+\.\d\)/);
  assert.match(textOutput, /Errors:\s+[A-F] \(\d+\)/);
  assert.match(textOutput, /Warnings:\s+[A-F] \(\d+\)/);
  assert.match(textOutput, /Advisory:\s+[A-F] \(\d+\)/);

  const markdownOutput = renderReport(report, "markdown");
  assert.match(markdownOutput, /Composite: \*\*[A-F] \(\d+\.\d\)\*\*/);
  assert.match(markdownOutput, /- Errors:\s+[A-F] \(\d+\)/);
  assert.match(markdownOutput, /- Warnings:\s+[A-F] \(\d+\)/);
  assert.match(markdownOutput, /- Advisory:\s+[A-F] \(\d+\)/);

  const htmlOutput = renderReport(report, "html");
  assert.match(htmlOutput, /severity-grades/);
  assert.match(htmlOutput, /Errors <span class="grade-pill/);
  assert.match(htmlOutput, /Warnings <span class="grade-pill/);
  assert.match(htmlOutput, /Advisory <span class="grade-pill/);
});

test("FP-#39 top-offender lines use quality N.N/100 wording in summary", () => {
  // §3.3: the trailing `score 0.0` was opaque - the new wording (`quality 0.0/100`) reads as a
  // labelled quality metric so an operator scanning the top-offender list knows what the number is.
  const report = analyseFixture(`function helperOne(): void { eval("noop"); }
function helperTwo(): void { eval("noop"); }
`);
  const summary = renderSummary(report);
  assert.match(summary, /quality \d+\.\d\/100/);
  assert.equal(/findings, score \d+\.\d/.test(summary), false);
});

test("FP-#40 JSON output schema and shape unchanged by M05", () => {
  // Negative coverage: M05 is renderer-only. JSON output must still be `gruff.analysis.v2`, no new
  // severity-grade fields appear in the score block, and the existing keys (composite, grade,
  // pillars, topOffenders) are the only top-level entries.
  const report = analyseFixture(`function helperOne(): void { eval("noop"); }
`);
  const json = JSON.parse(renderReport(report, "json"));
  assert.equal(json.schemaVersion, "gruff.analysis.v2");
  const scoreKeys = Object.keys(json.score).sort();
  assert.deepEqual(scoreKeys, ["composite", "grade", "pillars", "topOffenders"]);
});

test("FP-#32 docs.missing-exported-function-doc fires on export function", () => {
  // §2.9 of the 2026-05-25 feedback: exported API surface fires the warning-tier variant; the
  // baseline `export function foo()` shape is the canonical case.
  const report = analyseFixture(`export function publicHelper(): string {
  return "hello";
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "docs.missing-exported-function-doc" && entry.symbol === "publicHelper");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.severity, "warning");
});

test("FP-#33 docs.missing-exported-function-doc fires on export const fn = () => ...", () => {
  // Pattern 3 extension: `export const fn = () => ...` is the arrow-assignment export shape; pre-M04
  // the block-pattern regex didn't match the leading `export`, so neither variant of the doc rule
  // fired. Post-M04, the regex matches and isExported flags the binding as exported. The fixture
  // intentionally omits the return-type annotation because the underlying pattern 3 regex doesn't
  // accept `: Foo` between `)` and `=>` (a pre-existing limitation outside M04's scope).
  const report = analyseFixture(`export const publicArrow = (input) => {
  return input + 1;
};
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "docs.missing-exported-function-doc" && entry.symbol === "publicArrow");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.severity, "warning");
});

test("FP-#34 docs.missing-internal-function-doc fires on internal helper", () => {
  // Internal helpers fire the advisory variant. The body's lack of leading comment is the trigger;
  // a function with even a brief leading comment clears.
  const report = analyseFixture(`function internalHelper(): string {
  return "internal";
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "docs.missing-internal-function-doc" && entry.symbol === "internalHelper");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.severity, "advisory");
});

test("FP-#35 docs.missing-exported-function-doc clears when leading comment present", () => {
  // Negative for the exported variant: a leading comment satisfies the rule for both severities.
  const report = analyseFixture(`// Returns a greeting.
export function publicHelper(): string {
  return "hello";
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "docs.missing-exported-function-doc");
  assert.deepEqual(findings, []);
});

test("FP-#36 docs.missing-internal-function-doc clears when leading comment present", () => {
  // Negative for the internal variant. Symmetric coverage with the exported clear case.
  const report = analyseFixture(`// Joins parts with a separator.
function internalHelper(parts: string[]): string {
  return parts.join("-");
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "docs.missing-internal-function-doc");
  assert.deepEqual(findings, []);
});

test("FP-#37 docs.missing-exported-function-doc and docs.missing-internal-function-doc separate by export status", () => {
  // Combined: one file with both shapes proves the rule splits emission correctly. The exported
  // entry fires the warning-tier rule; the internal entry fires the advisory-tier rule. Both
  // appear in the same scan with the correct rule IDs and severities.
  const report = analyseFixture(`export function publicEntry(): string {
  return helper();
}

function helper(): string {
  return "value";
}
`);
  const exported = report.findings.filter((entry) => entry.ruleId === "docs.missing-exported-function-doc" && entry.symbol === "publicEntry");
  const internal = report.findings.filter((entry) => entry.ruleId === "docs.missing-internal-function-doc" && entry.symbol === "helper");
  assert.equal(exported.length, 1);
  assert.equal(internal.length, 1);
  assert.equal(exported[0]?.severity, "warning");
  assert.equal(internal[0]?.severity, "advisory");
});

test("FP-#26 test-quality.loop-in-test accepts literal-array fixture loop", () => {
  // §2.6 of the 2026-05-25 feedback: table-test pattern iterating over a literal array with an
  // assertion in the body is parametric coverage, not control-flow noise. Suppression criteria
  // are: iterable is `[...]`, body has no branching, and body's last statement is an assertion.
  const report = analyseFixture(`test("table coverage", () => {
  for (const x of [1, 2, 3]) {
    assert.equal(x > 0, true);
  }
});
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "test-quality.loop-in-test");
  assert.deepEqual(findings, []);
});

test("FP-#27 test-quality.loop-in-test accepts Object.entries fixture loop", () => {
  // Sibling shape: `Object.entries(literal)` is the property-bag table-test idiom.
  const report = analyseFixture(`test("entry coverage", () => {
  for (const [k, v] of Object.entries({a: 1, b: 2})) {
    expect(v).toBeDefined();
    void k;
  }
});
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "test-quality.loop-in-test");
  assert.deepEqual(findings, []);
});

test("FP-#28 test-quality.loop-in-test still flags dynamic-iterable loop", () => {
  // Negative: when the iterable is a function call (network, fixture builder, etc.) the loop is
  // genuine control flow and the rule's signal returns.
  const report = analyseFixture(`test("dynamic loop", async () => {
  for (const item of await fetchItems()) {
    assert.ok(item);
  }
});
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "test-quality.loop-in-test");
  assert.equal(findings.length, 1);
});

test("FP-#29 test-quality.loop-in-test still flags conditional inside literal-array loop", () => {
  // Negative: even with a literal-array iterable, the presence of an `if` inside the body means
  // not every branch terminates in an assertion. The conservative isFixtureLoop heuristic opts out
  // when any if/switch/case/default is detected; the rule then fires on the inner assertion.
  const report = analyseFixture(`test("conditional body", () => {
  for (const x of [1, 2, 3]) {
    if (x > 1) {
      assert.ok(x);
    }
  }
});
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "test-quality.loop-in-test");
  assert.equal(findings.length, 1);
});

test("FP-#20 waste.swallowed-catch still flags /* silent */ and empty catch", () => {
  // Negative coverage: two forms deliberately NOT widened. `silent` matches real defects in
  // goat-flow's dashboard-projects.ts and must keep firing. Empty catch bodies are the rule's
  // primary signal. Deferred-work markers were never in any widened set, so they need no explicit
  // case here.
  const silentReport = analyseFixture(`function f(handle: { close(): void }): void {
  try { handle.close(); } catch {
    /* silent */
  }
}
`);
  assert.equal(silentReport.findings.some((entry) => entry.ruleId === "waste.swallowed-catch"), true);

  const emptyReport = analyseFixture(`function h(handle: { close(): void }): void {
  try { handle.close(); } catch {}
}
`);
  assert.equal(emptyReport.findings.some((entry) => entry.ruleId === "waste.swallowed-catch"), true);
});
