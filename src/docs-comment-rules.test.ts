// Check the documentation and comment advice developers receive when scanning TypeScript.
//
// Focused fixtures cover missing descriptions, stale comments, fixture purpose and suppression rationale.
// Run these tests when changing comment interpretation so ordinary source text keeps its intended scan result.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject, largeFixtureSourceLines, TS_IGNORE_DIRECTIVE } from "./test-fixtures.ts";

test("void-prefixed test callbacks do not require internal-function documentation", () => {
  const report = analyseFixture(`// File overview: discarded test registration result.
const path = "/Products/search";
void it("GET product search returns all products", async () => {
  const response = await requestProducts(path);
  assert.equal(response.statusCode, 200);
});
`);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc"), false);
});

test("test-like text does not exempt an ordinary function from documentation", () => {
  const report = analyseFixture(`// File overview: masked registration text.
const title = "void it('not a callback', () => {})";
function it(value: number): number {
  return value + 1;
}
// void it("also not a callback", () => {});
`);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc" && finding.symbol === "it"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId.startsWith("test-quality.")), false);
});

test("docblock rules cover async exports and survive prose containing the word export", () => {
  const report = analyseFixture(`// File overview: docblock anchoring fixture.
/**
 * Handles the export pipeline for shipped reports; the word export here is prose, not code.
 * @param wrongName documents a parameter that does not exist
 */
export async function shipReports(actualName: string): Promise<number> {
  return actualName.length;
}
`);
  const docblockFindings = report.findings.filter((finding) => finding.symbol === "shipReports");
  const ruleIds = new Set(docblockFindings.map((finding) => finding.ruleId));
  // Before AST anchoring, the async keyword broke detection and the prose "export" inside the docblock suppressed the block entirely - all three
  // sub-rules were silently skipped.
  assert.equal(ruleIds.has("docs.stale-param-tag"), true);
  assert.equal(ruleIds.has("docs.missing-param-tag"), true);
  assert.equal(ruleIds.has("docs.missing-return-tag"), true);
});

test("a draft-mutating apply function does not absorb a later filesystem writer", () => {
  const report = analyseFixture(`// File overview: callable boundary fixture.
// Applies pending edits onto the supplied draft object in place.
function applyPendingEdits(draft: { total: number }): void {
  draft.total += 1;
}

// Renders the final report body for the caller.
function persistReport(path: string, body: string): void {
  writeFileSync(path, body);
}
`, { config: { rules: { "docs.missing-side-effect-doc": { enabled: true } } } });
  const sideEffectSymbols = report.findings
    .filter((finding) => finding.ruleId === "docs.missing-side-effect-doc")
    .map((finding) => finding.symbol);
  // Exact block boundaries: only the real filesystem writer needs a side-effect note; the in-memory draft mutation above it must not inherit the
  // later function's write signal.
  assert.deepEqual(sideEffectSymbols, ["persistReport"]);
});

test("documentation rubric requires file overview and comments on functions and interfaces", () => {
  const report = analyseFixture(`interface DiagnosticSourceFile {
  displayPath: string;
}

function parseDiagnostics(file: DiagnosticSourceFile, source: string): string {
  return source + file.displayPath;
}
`);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-file-overview"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc" && finding.symbol === "DiagnosticSourceFile"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc" && finding.symbol === "parseDiagnostics"), true);

  // Fixture covers documented code that should clear file, interface, and function doc findings.
  const documentedReport = analyseFixture(`/**
 * Scans source text in fixtures for documentation coverage.
 */

// Minimal source contract consumed by parser diagnostics.
interface DiagnosticSourceFile {
  displayPath: string;
}

/**
 * Checks fixture source and returns a derived parser value.
 *
 * @param file - Source metadata used to report paths.
 * @param source - Raw fixture text to inspect.
 */
function parseDiagnostics(file: DiagnosticSourceFile, source: string): string {
  return source + file.displayPath;
}
`);
  // Each supplied description must keep its corresponding missing-doc advice out of the scan.
  ["docs.missing-file-overview", "docs.missing-interface-doc", "docs.missing-exported-function-doc", "docs.missing-internal-function-doc"].forEach((ruleId) => {
    assert.equal(documentedReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  });
});

test("comment quality rules extract only real comments", () => {
  // Fixture covers real comments versus marker text inside strings, templates, and regexes.
  const report = analyseFixture(`/**
 * Exercises line, block, and JSDoc comments for comment-quality rules.
 */
// TODO add ownership
const stringTodo = "TODO is not a comment";
const templateTodo = \`FIXME inside a template is not a comment\`;
const regexTodo = /HACK\\/\\/XXX/;

/*
 * FIXME add a tracking issue
 */
function documentedFunction(): void {}

/**
 * HACK document the interface purpose
 */
interface DocumentedShape {
  value: string;
}
`);
  const todoFindings = report.findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking");
  assert.deepEqual(todoFindings.map((finding) => finding.line), [4, 9, 14]);
  assert.equal(todoFindings.every((finding) => ["TODO", "FIXME", "HACK"].includes(String(finding.metadata.marker))), true);
});

test("comment quality stale-comment flags stale references", () => {
  // Fixture purpose: pairs stale path/rule/flag references with valid changed-region flag names.
  const report = analyseFixture(`/**
 * Exercises stale comment references.
 */
// See \`src/missing-file.ts\` before changing this helper.
// Unknown scanner rule docs.removed-rule should be deleted.
// Run gruff-ts with --removed-flag when debugging.
// Run gruff-ts analyse --changed-ranges 2-3 --changed-scope hunk --since main for changed code.
// legacy migration note mentions \`src/old-file.ts\` intentionally.
function currentFeature(): void {}

// OldFeature function
function newFeature(): void {}
`);
  const staleFindings = report.findings.filter((finding) => finding.ruleId === "docs.stale-comment");
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "path" && finding.message.includes("src/missing-file.ts")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "ruleId" && finding.message.includes("docs.removed-rule")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--removed-flag")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--changed-ranges")), false);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--changed-scope")), false);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--since")), false);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "function" && finding.symbol === "newFeature"), true);
  assert.equal(staleFindings.some((finding) => finding.message.includes("src/old-file.ts")), false);
});

test("comment quality stale-comment ignores prose that only looks like a symbol", () => {
  // Fixture separates ordinary prose comments from a backticked stale-symbol reference.
  const report = analyseFixture(`/**
 * Read-only filesystem interface for scanner tests.
 */
interface ReadonlyFS {
  exists(path: string): boolean;
}

/**
 * Symlink helper that skips hosts without permissions.
 */
function symlinkOrSkip(): boolean {
  return true;
}

/**
 * \`OldFeature\` helper that documents the replacement.
 */
function newFeature(): void {}
`);
  const staleFindings = report.findings.filter((finding) => finding.ruleId === "docs.stale-comment");
  assert.equal(staleFindings.some((finding) => finding.symbol === "ReadonlyFS"), false);
  assert.equal(staleFindings.some((finding) => finding.symbol === "symlinkOrSkip"), false);
  assert.equal(staleFindings.some((finding) => finding.symbol === "newFeature"), true);
});

test("comment quality requires tracking for TODO markers", () => {
  const report = analyseFixture(`/**
 * Exercises tracked and untracked task-marker comments.
 */
// TODO owner: platform-runtime
// FIXME tracked in #123
// HACK https://example.test/issues/42 keeps the fixture intentional
// XXX 2026-05-18 revisit the temporary setup
// TODO add the missing owner
function trackedTodos(): void {}
`);
  const todoFindings = report.findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking");
  const expectedUntrackedTodoLine = 8;
  assert.equal(todoFindings.length, 1);
  assert.equal(todoFindings[0]?.line, expectedUntrackedTodoLine);
});

test("comment quality requires rationale for non-TypeScript suppressions", () => {
  const report = analyseFixture(`/**
 * Exercises suppression rationale checks.
 */
// eslint-disable-next-line no-console
console.log("debug");
// biome-ignore lint/suspicious/noExplicitAny: because the generated fixture uses any.
const ok: any = {};
// ` + TS_IGNORE_DIRECTIVE + `
const narrowed = ok.value;
`);
  const suppressionFindings = report.findings.filter((finding) => finding.ruleId === "docs.suppression-without-rationale");
  assert.equal(suppressionFindings.length, 1);
  assert.match(suppressionFindings[0]?.message ?? "", /eslint-disable-next-line/);
  assert.equal(report.findings.some((finding) => finding.ruleId === "modernisation.ts-comment-without-rationale"), true);
});

// Fixture purpose: axios case 398 explains its directive on the comment line directly above, and a rationale may run over several comment lines.
//
// Code above, a blank line, another directive or a comment trailing code breaks that attachment, so those directives keep the finding.
// Stable contract: only the unbroken block of standalone comments directly above a standalone directive supplies its rationale.
test("suppression rationale can come from the attached comment block above the directive", () => {
  // Fixture covers case 398's attached rationale beside unexplained, detached, stacked and trailing-comment directives.
  const report = analyseFixture(`// The control-code ranges are intentional: header sanitization strips C0/DEL bytes.
// eslint-disable-next-line no-control-regex
const invalidChars = buildPattern("c0");
// eslint-disable-next-line no-control-regex
const byteChars = buildPattern("bytes");
// Stripping is intentional because callers pass raw header bytes.

// eslint-disable-next-line no-control-regex
const detachedChars = buildPattern("detached");
// Parsing is intentional; the legacy grammar needs it.
// eslint-disable-next-line no-param-reassign
// eslint-disable-next-line no-control-regex
const stackedChars = buildPattern("stacked");
const trailing = buildPattern("trailing"); // Intentional: keeps the old grammar.
// eslint-disable-next-line no-control-regex
const trailingChars = buildPattern("after-trailing");
// The trailing semicolon below exists because the printer emits it when the
// block is reprinted.
// prettier-ignore
const printed = buildPattern("printed");
`);
  const suppressionLines = report.findings.filter((finding) => finding.ruleId === "docs.suppression-without-rationale").map((finding) => finding.line);
  assert.deepEqual(suppressionLines, [4, 8, 12, 15]);
});

test("comment quality restates signature through useless-docblock without duplicates", () => {
  // Fixture covers useless-docblock detection without duplicate function/interface findings.
  const report = analyseFixture(`/**
 * Exercises restating comments.
 */
/** Parses diagnostics. */
function parseDiagnostics(): void {}

// DiagnosticSourceFile interface
interface DiagnosticSourceFile {
  displayPath: string;
}

// Parser options contract must stay deterministic for callers.
interface ParserOptions {
  stable: boolean;
}

/** updateName */
export function updateName(name: string): string {
  return name;
}
`);
  const uselessFindings = report.findings.filter((finding) => finding.ruleId === "docs.useless-docblock");
  assert.equal(uselessFindings.some((finding) => finding.symbol === "parseDiagnostics"), true);
  assert.equal(uselessFindings.some((finding) => finding.symbol === "DiagnosticSourceFile"), true);
  assert.equal(uselessFindings.filter((finding) => finding.symbol === "updateName").length, 1);
  assert.equal(uselessFindings.some((finding) => finding.symbol === "ParserOptions"), false);
});

test("documentation context detector matrix covers why side-effect error-behavior invariant magic-threshold", () => {
  const routingBranches = branchFixtureLines(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"]);
  // Fixture covers context-doc rules for why, side effects, errors, invariants, and thresholds.
  const report = analyseFixture(`/**
 * Exercises maintainer-context documentation rules.
 */
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

const maxRetryLimit = 12;
const ordinaryCount = 42;
// Tuned threshold from production retry budgets.
const explainedRetryLimit = 12;
const contextText = "side effect throws schema threshold 99";
const contextTemplate = \`missing why threshold 88\`;
const contextRegex = /side-effect|invariant|77/;

/** Handles routing branches. */
function complexFlow(value: string): string {
${routingBranches}
  return value;
}

/** Complex flow exists because legacy states arrive out of order. */
function complexFlowWithWhy(value: string): string {
${routingBranches}
  return value;
}

/** Saves output. */
function persistOutput(path: string): void {
  writeFileSync(path, "ok");
}

/** Filesystem writes persist the generated report. */
function persistOutputWithContext(path: string): void {
  writeFileSync(path, "ok");
}

/** Parses user value. */
function parseRequired(value: string): string {
  if (!value) {
    throw new Error("missing value");
  }
  return value;
}

/** @throws Error when the required value is absent. */
function parseRequiredWithContext(value: string): string {
  if (!value) {
    throw new Error("missing value");
  }
  return value;
}

/** Payload details. */
interface ReportEnvelope {
  schemaVersion: string;
  fingerprint: string;
}

/** Schema contract must stay stable for report readers. */
interface StableReportEnvelope {
  schemaVersion: string;
  fingerprint: string;
}

/** Restating complex flow. */
function restatingComplexFlow(value: string): string {
${routingBranches}
  return value;
}

function undocumentedSideEffect(path: string): void {
  writeFileSync(path, "ok");
  spawn("node", []);
}
`, { config: { rules: { "docs.missing-side-effect-doc": { enabled: true }, "docs.missing-invariant-doc": { enabled: true } } } });
  const findingsByRule = new Map<string, Set<string>>();
  // Every fixture finding must keep the source file and location a developer needs to act on the advice.
  report.findings.forEach((finding) => {
    const symbols = findingsByRule.get(finding.ruleId) ?? new Set<string>();
    symbols.add(finding.symbol ?? String(finding.metadata.thresholdKind ?? "-"));
    findingsByRule.set(finding.ruleId, symbols);
  });

  // Check each expected warning and quiet result so the documentation matrix preserves its intended boundary.
  documentationContextExpectations().forEach(([ruleId, symbol, expected]) => {
    assert.equal(findingsByRule.get(ruleId)?.has(symbol), expected, `${ruleId} ${symbol}`);
  });
});

test("missing-why no longer fires on a flat switch that only tripped via npath", () => {
  const switchCases = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
    .map((value) => `    case "${value}": return "${value}";`)
    .join("\n");
  const report = analyseFixture(`/** Routes a status code to its label. */
function routeStatus(code: string): string {
  switch (code) {
${switchCases}
    default: return "unknown";
  }
}
`);
  // A 10-case flat switch scored old-npath 2**10 = 1024 (well over the retired 200 default, so it tripped the missing-why complexity gate), but its
  //
  // cyclomatic (12), cognitive (13), and nesting all stay under threshold.
  // With npath gone the gate must not demand a "why" on legible flat dispatch.
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-why-for-complex-code"), false);
});

// Stable fixture contract covers causal phrases, contiguous comments, and an unexplained control.
test("missing-why accepts natural rationale phrases across contiguous line comments", () => {
  const routingBranches = branchFixtureLines(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"]);
  // This fixture covers accepted phrase shapes beside one deliberately unexplained function.
  const report = analyseFixture(`// Required by the legacy wire-order contract.
// Routes known states to stable output.
function requiredByCompatibility(value: string): string {
${routingBranches}
  return value;
}

/** Routes states this way due to the backend ordering contract. */
function dueToBackend(value: string): string {
${routingBranches}
  return value;
}

/** Routes known states to stable output. */
function unexplainedRouting(value: string): string {
${routingBranches}
  return value;
}
`);
  const symbols = report.findings
    .filter((finding) => finding.ruleId === "docs.missing-why-for-complex-code")
    .map((finding) => finding.symbol);
  assert.deepEqual(symbols, ["unexplainedRouting"]);
});

// M22 brief shape (10 findings downstream; 3 of 3 sampled had real rationale): a docblock that states a constraint or a contrast explains the control
// flow.
// The two sampled docblocks are verbatim from the brief.
//
// A comment that only names the arguments, and a constraint word beside a near-paraphrase of the function name, still fire, which is the rule's
// contract for rationale that restates nothing.
test("missing-why accepts constraint and contrast rationale that says more than the name", () => {
  const routingBranches = branchFixtureLines(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"]);
  // Fixture covers the brief's two sampled docblocks verbatim beside two controls that must still fire.
  const report = analyseFixture(`/**
 * Walks every claim of a schema-v2 note and tallies its review flags.
 * Use to build the status model for the axes and the copied header: the
 * renderer and the clipboard must count from the same payload walk.
 * ...
 */
function v2ReviewCountsFrom(value: string): string {
${routingBranches}
  return value;
}

/**
 * Runs post-visit correction once when Stop or replay finalization arrives.
 * Summary generation may await an in-flight request defensively, but a
 * settled unavailable or blocked outcome is never retried by that click.
 */
function ensureCorrectedTranscriptReady(value: string): string {
${routingBranches}
  return value;
}

/** Takes the value and the fallback. */
function namesItsArguments(value: string, fallback: string): string {
${routingBranches}
  return value || fallback;
}

/** Always routes the value. */
function routeValue(value: string): string {
${routingBranches}
  return value;
}
`);
  const symbols = report.findings
    .filter((finding) => finding.ruleId === "docs.missing-why-for-complex-code")
    .map((finding) => finding.symbol)
    .sort();
  assert.deepEqual(symbols, ["namesItsArguments", "routeValue"]);
});

// Build repeated branch text for a documentation-rule fixture without adding complexity to the test driver.
function branchFixtureLines(values: string[]): string {
  return values.map((value) => `  if (value === "${value}") return "${value}";`).join("\n");
}

// List expected documentation advice so the matrix checks each developer-visible outcome.
function documentationContextExpectations(): Array<[string, string, boolean]> {
  return [
    ["docs.missing-why-for-complex-code", "complexFlow", true],
    ["docs.missing-why-for-complex-code", "complexFlowWithWhy", false],
    ["docs.missing-side-effect-doc", "persistOutput", true],
    ["docs.missing-side-effect-doc", "persistOutputWithContext", false],
    ["docs.missing-error-behavior-doc", "parseRequired", true],
    ["docs.missing-error-behavior-doc", "parseRequiredWithContext", false],
    ["docs.missing-invariant-doc", "ReportEnvelope", true],
    ["docs.missing-invariant-doc", "StableReportEnvelope", false],
    ["docs.magic-threshold-without-rationale", "maxRetryLimit", true],
    ["docs.magic-threshold-without-rationale", "explainedRetryLimit", false],
    ["docs.missing-side-effect-doc", "undocumentedSideEffect", false],
    ["docs.missing-internal-function-doc", "undocumentedSideEffect", true],
    ["docs.useless-docblock", "restatingComplexFlow", true],
    ["docs.missing-why-for-complex-code", "restatingComplexFlow", false],
  ];
}

// Build literal fixtures that check source-purpose advice and stable finding identities.
function fixturePurposeMatrixSource(): string {
  return [
    "const report = analyseFixture(`",
    ...largeFixtureSourceLines("matrixValue"),
    "`);",
    "",
    "const shortExample = `const tiny = 1;`;",
    "const PROSE_FIXTURE_SOURCE = `",
    ...Array.from({ length: 13 }, (_, index) => `Plain prose line ${index} for a release note.`),
    "`;",
    "const uiCopy = `",
    ...Array.from({ length: 13 }, (_, index) => `Button label ${index}: Save changes`),
    "`;",
    "const markdownSnippet = `",
    ...Array.from({ length: 13 }, (_, index) => `- Item ${index}: documentation text`),
    "`;",
    "const snapshotText = `",
    ...Array.from({ length: 13 }, (_, index) => `<div data-index=\"${index}\">snapshot</div>`),
    "`;",
    "// fixture covers parser branch detection.",
    "const PARSER_FIXTURE_SOURCE = `",
    ...largeFixtureSourceLines("parserValue"),
    "`;",
    "const ROUTE_FIXTURE_SOURCE = `",
    ...largeFixtureSourceLines("routeValue"),
    "`;",
    "// fixture covers generated source for a rule-count regression.",
    "const generatedFixtureSource = Array.from({ length: 13 }, (_value, index) => \"const generated\" + index + \" = \" + index + \";\").join(\"\\n\");",
    "const generatedWithoutPurposeFixtureSource = Array.from({ length: 13 }, (_value, index) => \"const generatedMissing\" + index + \" = \" + index + \";\").join(\"\\n\");",
  ].join("\n");
}

test("fixture purpose detector matrix", () => {
  const report = analyseFixture(fixturePurposeMatrixSource(), { fileName: "fixture-purpose.test.ts" });
  const findings = report.findings.filter((finding) => finding.ruleId === "docs.fixture-purpose-missing");
  const symbols = new Set(findings.map((finding) => finding.symbol));

  assert.equal(symbols.has("analyseFixture"), true);
  assert.equal(symbols.has("ROUTE_FIXTURE_SOURCE"), true);
  assert.equal(symbols.has("generatedWithoutPurposeFixtureSource"), true);
  assert.equal(symbols.has("PARSER_FIXTURE_SOURCE"), false);
  assert.equal(symbols.has("PROSE_FIXTURE_SOURCE"), false);
  const expectedFixturePurposeFindings = 3;
  assert.equal(findings.length, expectedFixturePurposeFindings);
  assert.equal(findings.every((finding) => Number(finding.metadata.fixtureLines) > 12), true);

  const changedBodyReport = analyseFixture(["const report = analyseFixture(`", ...largeFixtureSourceLines("changedMatrixValue"), "`);"].join("\n"), { fileName: "fixture-purpose.test.ts" });
  const originalInline = findings.find((finding) => finding.symbol === "analyseFixture");
  const changedInline = changedBodyReport.findings.find((finding) => finding.ruleId === "docs.fixture-purpose-missing" && finding.symbol === "analyseFixture");
  assert.equal(changedInline?.fingerprint, originalInline?.fingerprint);
});

// Fixture covers the gate contract: comment-quality gating must keep the fixture-purpose rule alive.
test("fixture purpose rule still runs when every other comment-quality rule is disabled", () => {
  // Regression: the analyser's comment-quality group gate must include `docs.fixture-purpose-missing`, otherwise disabling the other comment rules
  // silently disables this still-enabled rule too.
  const disabledRuleIds = [
    "docs.magic-threshold-without-rationale",
    "docs.missing-error-behavior-doc",
    "docs.missing-invariant-doc",
    "docs.missing-side-effect-doc",
    "docs.missing-why-for-complex-code",
    "docs.stale-comment",
    "docs.suppression-without-rationale",
    "docs.todo-without-tracking",
    "docs.useless-docblock",
  ];
  const report = analyseFixture(fixturePurposeMatrixSource(), {
    fileName: "fixture-purpose.test.ts",
    config: { rules: Object.fromEntries(disabledRuleIds.map((ruleId) => [ruleId, { enabled: false }])) },
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), true);
  assert.equal(report.findings.some((finding) => disabledRuleIds.includes(finding.ruleId)), false);
});

// Build setup-heavy test text that checks when a developer needs to explain the fixture's purpose.
function fixturePurposeSetupBlockSource(): string {
  return [
    "test(\"builds noisy fixture setup\", () => {",
    ...Array.from({ length: 13 }, (_, index) => `  const fixtureValue${index} = ${index};`),
    "  const report = analyseProject({ \"bad.ts\": \"const value = 1;\" });",
    "  assert.ok(report);",
    "});",
    "",
    "// fixture covers setup-bloat calibration.",
    "test(\"builds documented fixture setup\", () => {",
    ...Array.from({ length: 13 }, (_, index) => `  const documentedFixtureValue${index} = ${index};`),
    "  const report = analyseProject({ \"bad.ts\": \"const value = 1;\" });",
    "  assert.ok(report);",
    "});",
  ].join("\n");
}

test("fixture purpose flags large fixture-heavy test setup without flagging documented setup", () => {
  const report = analyseFixture(fixturePurposeSetupBlockSource(), { fileName: "fixture-purpose.test.ts" });
  const fixturePurposeFindings = report.findings.filter((finding) => finding.ruleId === "docs.fixture-purpose-missing");
  assert.equal(fixturePurposeFindings.some((finding) => finding.symbol === "builds noisy fixture setup"), true);
  assert.equal(fixturePurposeFindings.some((finding) => finding.symbol === "builds documented fixture setup"), false);
});

test("comment rules config disable keeps fixture purpose independent", () => {
  const source = [
    "const report = analyseFixture(`",
    ...largeFixtureSourceLines("disableValue"),
    "`);",
    "",
    "function undocumentedHelper(): void {}",
  ].join("\n");
  const defaultReport = analyseFixture(source, { fileName: "fixture-purpose.test.ts" });
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), true);
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc" && finding.symbol === "undocumentedHelper"), true);

  const disabledReport = analyseFixture(source, {
    fileName: "fixture-purpose.test.ts",
    config: { rules: { "docs.fixture-purpose-missing": { enabled: false } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), false);
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc" && finding.symbol === "undocumentedHelper"), true);
});

test("missing public docs are reported once per exported class type or enum", () => {
  // Fixture covers public class, type, and enum declarations without existing docs.
  const report = analyseFixture(`export class PublicLoader {
  loadValue(): string {
    return "ok";
  }
}

export type PublicValue = string;

export enum PublicMode {
  Ready = "ready",
}

export function loadValue(): string {
  return "ok";
}
`);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicLoader").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicValue").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicMode").length, 1);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "loadValue"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-exported-function-doc" && finding.symbol === "loadValue"), true);
});

test("size file-length skips generated lockfiles", () => {
  const lockfile = Array.from({ length: 900 }, (_, index) => `"entry-${index}": "value"`).join("\n");
  const report = analyseProject({ "package-lock.json": lockfile });
  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length" && finding.filePath === "package-lock.json"), false);
});

// No project-specific tracking token ships by default, so a project must add its own through `allowlists.trackingTokens`.
test("project tracking tokens come from allowlists.trackingTokens, and none ship by default", () => {
  const source = `/**
 * Exercises a project task reference on a TODO marker.
 */
// TODO M12 follow-up
function trackedLater(): void {}
`;
  const byDefault = analyseFixture(source).findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking");
  assert.equal(byDefault.length, 1);
  const configured = analyseFixture(source, { config: { allowlists: { trackingTokens: ["\\bM\\d{1,3}\\b"] } } });
  assert.deepEqual(configured.findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking"), []);
});

// Fixture for the tag rules' everyCallable switch: an arrow and a function-expression constant that
// return a value and lack tags, a void arrow constant, and a function declaration to compare severity with.
const CALLABLE_CONSTANT_SOURCE = `// File overview: callable constant fixture.
/** Joins two labels with a separator. */
export const joinArrow = (left: string): string => left + "-";

/** Picks the first label from a pair. */
export const pickFirst = function (first: string): string {
  return first;
};

/** Writes a label to the console. */
export const logLabel = (label: string): void => {
  console.log(label);
};

/** Joins a label with a fixed separator. */
export function joinDeclared(left: string): string {
  return left;
}
`;

// Collects the two tag rules' findings as "severity message" lines in a stable sorted order so each case reads as one list.
function tagFindings(options: Parameters<typeof analyseFixture>[1] = {}): string[] {
  return analyseFixture(CALLABLE_CONSTANT_SOURCE, options)
    .findings.filter((finding) => finding.ruleId === "docs.missing-param-tag" || finding.ruleId === "docs.missing-return-tag")
    .map((finding) => `${finding.severity} ${finding.message}`)
    .sort();
}

test("tag rules leave documented callable constants alone at default settings", () => {
  assert.deepEqual(tagFindings(), ["advisory Docblock for `joinDeclared` is missing @param for `left`.", "advisory Docblock for `joinDeclared` is missing @returns."]);
});

test("everyCallable on docs.missing-param-tag covers arrow and function-expression constants at the declaration severity", () => {
  assert.deepEqual(tagFindings({ config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "advisory Docblock for `joinArrow` is missing @param for `left`.",
    "advisory Docblock for `joinDeclared` is missing @param for `left`.",
    "advisory Docblock for `joinDeclared` is missing @returns.",
    "advisory Docblock for `logLabel` is missing @param for `label`.",
    "advisory Docblock for `pickFirst` is missing @param for `first`.",
  ]);
});

test("everyCallable on docs.missing-return-tag asks only non-void callable constants for @returns", () => {
  assert.deepEqual(tagFindings({ config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "advisory Docblock for `joinArrow` is missing @returns.",
    "advisory Docblock for `joinDeclared` is missing @param for `left`.",
    "advisory Docblock for `joinDeclared` is missing @returns.",
    "advisory Docblock for `pickFirst` is missing @returns.",
  ]);
});

// Fixture for the tag rules' everyCallable switch on methods: an exported class with documented
// public, static and private methods that lack tags (the private one is void), an undocumented
// public method and an undocumented private method, and a documented object-literal method.
const METHOD_SOURCE = `// File overview: method fixture.
/** Holds labels for joining. */
export class LabelHolder {
  /** Joins a label with the prefix. */
  public join(left: string): string {
    return left;
  }

  /** Joins a label without an instance. */
  static joinStatic(left: string): string {
    return left;
  }

  /** Writes a label to the console. */
  private logHidden(label: string): void {
    console.log(label);
  }

  undocumented(left: string): string {
    return this.secret(left);
  }

  private secret(left: string): string {
    return left;
  }
}

/** Helper object literal. */
export const helpers = {
  /** Picks the first label. */
  pickFirst(first: string): string {
    return first;
  },
};
`;

const TAG_RULE_IDS = ["docs.missing-param-tag", "docs.missing-return-tag"];
const MISSING_DOC_RULE_IDS = ["docs.missing-exported-function-doc", "docs.missing-internal-function-doc"];

// Collects the method fixture's findings for the given rules as "severity message" lines in a stable sorted order.
function methodFindings(ruleIds: string[], options: Parameters<typeof analyseFixture>[1] = {}): string[] {
  return analyseFixture(METHOD_SOURCE, options)
    .findings.filter((finding) => ruleIds.includes(finding.ruleId))
    .map((finding) => `${finding.severity} ${finding.message}`)
    .sort();
}

test("tag rules and missing-doc tiers leave methods alone at default settings", () => {
  assert.deepEqual(methodFindings(TAG_RULE_IDS), []);
  assert.deepEqual(methodFindings(MISSING_DOC_RULE_IDS), [
    "advisory Internal function `secret` is missing a leading maintainer comment; describe parameter `left`; describe the return value.",
    "advisory Internal function `undocumented` is missing a leading maintainer comment; describe parameter `left`; describe the return value.",
  ]);
});

test("everyCallable on docs.missing-param-tag covers class and object-literal methods under their own names", () => {
  assert.deepEqual(methodFindings(TAG_RULE_IDS, { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "advisory Docblock for `joinStatic` is missing @param for `left`.",
    "advisory Docblock for `join` is missing @param for `left`.",
    "advisory Docblock for `logHidden` is missing @param for `label`.",
    "advisory Docblock for `pickFirst` is missing @param for `first`.",
  ]);
});

test("everyCallable on docs.missing-return-tag asks only non-void methods for @returns", () => {
  assert.deepEqual(methodFindings(TAG_RULE_IDS, { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "advisory Docblock for `joinStatic` is missing @returns.",
    "advisory Docblock for `join` is missing @returns.",
    "advisory Docblock for `pickFirst` is missing @returns.",
  ]);
});

test("everyCallable on either tag rule reports an undocumented public method of an exported class as exported, never a private one", () => {
  const expected = [
    "warning Exported function `undocumented` is missing a leading maintainer comment; describe parameter `left`; describe the return value.",
    "warning Internal function `secret` is missing a leading maintainer comment; describe parameter `left`; describe the return value.",
  ];
  assert.deepEqual(methodFindings(MISSING_DOC_RULE_IDS, { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), expected);
  assert.deepEqual(methodFindings(MISSING_DOC_RULE_IDS, { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), expected);
});

// Fixtures for the tag rules' everyCallable switch on default exports: an anonymous and a named
// `export default function` and a default-exported arrow, each documented without tags.
const DEFAULT_EXPORT_SOURCES = [
  `// File overview: anonymous default export fixture.
/** Joins a label with a fixed separator. */
export default function (left: string): string {
  return left;
}
`,
  `// File overview: named default export fixture.
/** Joins a label with a fixed separator. */
export default function joinDefault(left: string): string {
  return left;
}
`,
  `// File overview: default arrow export fixture.
/** Joins a label with a fixed separator. */
export default (left: string): string => left;
`,
];

// Fixture for the tag rules' everyCallable switch on later export statements: a function exported by
// a default-name export, and a function and an arrow constant exported by a list (the arrow under an
// alias), all documented without tags.
const LATER_EXPORT_SOURCE = `// File overview: later export fixture.
/** Joins a label, exported later as the default. */
function joinLater(left: string): string {
  return left;
}

/** Joins a label, exported later in a list. */
function joinListed(left: string): string {
  return left;
}

/** Joins a label as an arrow, exported later under another name. */
const joinListedArrow = (left: string): string => left;

export default joinLater;
export { joinListed, joinListedArrow as renamedArrow };
`;

// Collects the tag rules' findings across the given fixtures as "severity symbol message" lines in a stable sorted order.
function exportFormTagFindings(sources: string[], options: Parameters<typeof analyseFixture>[1] = {}): string[] {
  return sources
    .flatMap((source) => analyseFixture(source, options).findings)
    .filter((finding) => TAG_RULE_IDS.includes(finding.ruleId))
    .map((finding) => `${finding.severity} ${finding.symbol} ${finding.message}`)
    .sort();
}

test("tag rules leave default and later-exported callables alone at default settings", () => {
  assert.deepEqual(exportFormTagFindings([...DEFAULT_EXPORT_SOURCES, LATER_EXPORT_SOURCE]), []);
});

test("everyCallable on docs.missing-param-tag covers default exports and names an anonymous one default", () => {
  assert.deepEqual(exportFormTagFindings(DEFAULT_EXPORT_SOURCES, { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "advisory default Docblock for `default` is missing @param for `left`.",
    "advisory default Docblock for `default` is missing @param for `left`.",
    "advisory joinDefault Docblock for `joinDefault` is missing @param for `left`.",
  ]);
});

test("everyCallable on docs.missing-param-tag covers callables a later export statement names, under their local names", () => {
  assert.deepEqual(exportFormTagFindings([LATER_EXPORT_SOURCE], { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "advisory joinLater Docblock for `joinLater` is missing @param for `left`.",
    "advisory joinListed Docblock for `joinListed` is missing @param for `left`.",
    "advisory joinListedArrow Docblock for `joinListedArrow` is missing @param for `left`.",
  ]);
});

test("everyCallable on docs.missing-return-tag covers default and later-exported callables", () => {
  assert.deepEqual(exportFormTagFindings([...DEFAULT_EXPORT_SOURCES, LATER_EXPORT_SOURCE], { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "advisory default Docblock for `default` is missing @returns.",
    "advisory default Docblock for `default` is missing @returns.",
    "advisory joinDefault Docblock for `joinDefault` is missing @returns.",
    "advisory joinLater Docblock for `joinLater` is missing @returns.",
    "advisory joinListed Docblock for `joinListed` is missing @returns.",
    "advisory joinListedArrow Docblock for `joinListedArrow` is missing @returns.",
  ]);
});

// Fixture for the tag rules' everyCallable switch on private and nested callables: a documented
// module-private function, private arrow constant and void private function that lack tags, an
// undocumented private function, and a documented nested function and nested arrow constant inside
// a fully tagged exported function.
const PRIVATE_CALLABLE_SOURCE = `// File overview: private and nested callable fixture.
/** Joins a label privately. */
function joinPrivate(left: string): string {
  return left;
}

/** Joins a label with a private arrow. */
const joinPrivateArrow = (left: string): string => left;

/** Writes a label to the console. */
function logPrivate(label: string): void {
  console.log(label);
}

function undocumentedPrivate(left: string): string {
  return left;
}

/**
 * Uses the private helpers.
 * @param label - the label to join
 * @returns the joined label
 */
export function useAll(label: string): string {
  /** Joins a label inside the outer function. */
  function inner(left: string): string {
    return left;
  }
  /** Joins a label with a nested arrow. */
  const innerArrow = (left: string): string => left;
  logPrivate(label);
  return joinPrivate(label) + joinPrivateArrow(label) + inner(label) + innerArrow(label) + undocumentedPrivate(label);
}
`;

// Collects the private-callable fixture's findings for the given rules as "severity symbol message" lines in a stable sorted order.
function privateCallableFindings(ruleIds: string[], options: Parameters<typeof analyseFixture>[1] = {}): string[] {
  return analyseFixture(PRIVATE_CALLABLE_SOURCE, options)
    .findings.filter((finding) => ruleIds.includes(finding.ruleId))
    .map((finding) => `${finding.severity} ${finding.symbol} ${finding.message}`)
    .sort();
}

test("tag rules and the internal missing-doc tier leave private and nested callables alone at default settings", () => {
  assert.deepEqual(privateCallableFindings(TAG_RULE_IDS), []);
  assert.deepEqual(privateCallableFindings(MISSING_DOC_RULE_IDS), ["advisory undocumentedPrivate Internal function `undocumentedPrivate` is missing a leading maintainer comment; describe parameter `left`; describe the return value."]);
});

test("everyCallable on docs.missing-param-tag covers private and nested functions and callable constants", () => {
  assert.deepEqual(privateCallableFindings(TAG_RULE_IDS, { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "advisory inner Docblock for `inner` is missing @param for `left`.",
    "advisory innerArrow Docblock for `innerArrow` is missing @param for `left`.",
    "advisory joinPrivate Docblock for `joinPrivate` is missing @param for `left`.",
    "advisory joinPrivateArrow Docblock for `joinPrivateArrow` is missing @param for `left`.",
    "advisory logPrivate Docblock for `logPrivate` is missing @param for `label`.",
  ]);
});

test("everyCallable on docs.missing-return-tag asks only non-void private and nested callables for @returns", () => {
  assert.deepEqual(privateCallableFindings(TAG_RULE_IDS, { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "advisory inner Docblock for `inner` is missing @returns.",
    "advisory innerArrow Docblock for `innerArrow` is missing @returns.",
    "advisory joinPrivate Docblock for `joinPrivate` is missing @returns.",
    "advisory joinPrivateArrow Docblock for `joinPrivateArrow` is missing @returns.",
  ]);
});

test("everyCallable on either tag rule reports an undocumented private function at the exported severity without calling it exported", () => {
  const expected = ["warning undocumentedPrivate Internal function `undocumentedPrivate` is missing a leading maintainer comment; describe parameter `left`; describe the return value."];
  assert.deepEqual(privateCallableFindings(MISSING_DOC_RULE_IDS, { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), expected);
  assert.deepEqual(privateCallableFindings(MISSING_DOC_RULE_IDS, { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), expected);
});

// Fixture for docs.missing-return-tag's everyCallable inference from the body: an annotated function,
// unannotated functions and an arrow constant that return a value, one that already has @returns, and
// unannotated callables whose only returns are bare, undefined, void or inside nested callables.
const INFERRED_RETURN_SOURCE = `// File overview: inferred return fixture.
/**
 * Joins with an explicit return type.
 * @param left - first label
 */
export function joinExplicit(left: string): string {
  return left;
}

/**
 * Joins with an inferred return type after an early bare return.
 * @param left - first label
 */
export function joinInferred(left: string) {
  if (left === "") {
    return;
  }
  return left + "!";
}

/**
 * Resolves with an inferred promise.
 * @param left - first label
 */
export async function resolveInferred(left: string) {
  return left;
}

/**
 * Joins with a concise arrow body.
 * @param left - first label
 */
export const joinArrow = (left: string) => left;

/**
 * Joins with a documented inferred return.
 * @param left - first label
 * @returns the label
 */
export function joinDocumented(left: string) {
  return left;
}

/**
 * Logs with only bare and undefined returns.
 * @param left - first label
 */
export function logInferred(left: string) {
  if (left === "") {
    return;
  }
  console.log(left);
  return undefined;
}

/**
 * Discards a label with a void arrow body.
 * @param left - first label
 */
export const discardArrow = (left: string) => void left;

/**
 * Logs callbacks whose returns are not this function's.
 * @param left - first label
 */
export function registerNested(left: string) {
  const read = () => {
    return left;
  };
  console.log(read, [left].map(function (value) {
    return value;
  }));
}

/**
 * Logs a class whose method return is not this function's.
 * @param left - first label
 */
export function buildHolder(left: string) {
  class Holder {
    read() {
      return left;
    }
  }
  console.log(Holder);
}
`;

test("docs.missing-return-tag needs a return annotation at default settings and with only the param rule's everyCallable", () => {
  const expected = ["advisory joinExplicit Docblock for `joinExplicit` is missing @returns."];
  assert.deepEqual(exportFormTagFindings([INFERRED_RETURN_SOURCE]), expected);
  assert.deepEqual(exportFormTagFindings([INFERRED_RETURN_SOURCE], { config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), expected);
});

test("everyCallable on docs.missing-return-tag infers a returned value from the body, skipping bare, undefined, void and nested returns", () => {
  assert.deepEqual(exportFormTagFindings([INFERRED_RETURN_SOURCE], { config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "advisory joinArrow Docblock for `joinArrow` is missing @returns.",
    "advisory joinExplicit Docblock for `joinExplicit` is missing @returns.",
    "advisory joinInferred Docblock for `joinInferred` is missing @returns.",
    "advisory resolveInferred Docblock for `resolveInferred` is missing @returns.",
  ]);
});

// Fixture for the tag rules' everyCallable check on tags with no description: bare and dash-only
// tags, a type-only @param and a stale one beside a void @returns {void}, a description on a
// continuation line, and a widened arrow constant with a bare @param and a type-only @returns.
const BARE_TAG_SOURCE = `// File overview: bare tag fixture.
/**
 * Joins two labels with bare tags.
 * @param left
 * @param right -
 * @returns
 */
export function joinBare(left: string, right: string): string {
  return left + right;
}

/**
 * Joins two labels with described tags.
 * @param left - first label
 * @param {string} right
 *   second label, described on the next line
 * @returns the joined label
 */
export function joinDescribed(left: string, right: string): string {
  return left + right;
}

/**
 * Logs a label with type-only tags.
 * @param {string} label
 * @param {string} stale
 * @returns {void}
 */
export function logTyped(label: string): void {
  console.log(label);
}

/**
 * Picks a label with a type-only return tag.
 * @param label
 * @returns {string}
 */
export const pickTyped = (label: string) => label;
`;

// Collects the two tag rules' findings on BARE_TAG_SOURCE as "line message" strings in a stable sorted order.
function bareTagFindings(options: Parameters<typeof analyseFixture>[1] = {}): string[] {
  return analyseFixture(BARE_TAG_SOURCE, options)
    .findings.filter((finding) => TAG_RULE_IDS.includes(finding.ruleId))
    .map((finding) => `${finding.line} ${finding.severity} ${finding.message}`)
    .sort();
}

test("tag rules accept @param and @returns tags with no description at default settings", () => {
  assert.deepEqual(bareTagFindings(), []);
});

test("everyCallable on docs.missing-param-tag reports each parameter whose @param tag has no description, on the tag's line", () => {
  assert.deepEqual(bareTagFindings({ config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    "25 advisory Docblock for `logTyped` has no description for @param `label`.",
    "35 advisory Docblock for `pickTyped` has no description for @param `label`.",
    "4 advisory Docblock for `joinBare` has no description for @param `left`.",
    "5 advisory Docblock for `joinBare` has no description for @param `right`.",
  ]);
});

test("everyCallable on docs.missing-return-tag reports a @returns tag with no description only on a callable that returns a value", () => {
  assert.deepEqual(bareTagFindings({ config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), [
    "36 advisory Docblock for `pickTyped` has no description for @returns.",
    "6 advisory Docblock for `joinBare` has no description for @returns.",
  ]);
});

// Fixture for docs.missing-param-tag naming every missing parameter in one finding: `joinThree`
// documents only its middle parameter, and `joinNone` has no @param tag at all.
const MISSING_PARAMS_SOURCE = `// File overview: docblocks that leave out several parameters.

/**
 * Joins three labels in order.
 * @param second - the middle label
 * @returns the joined labels
 */
export function joinThree(first: string, second: string, third: string): string {
  return first + second + third;
}

/**
 * Joins two labels with nothing between them.
 * @returns the joined labels
 */
export function joinNone(left: string, right: string): string {
  return left + right;
}
`;

test("docs.missing-param-tag reports one finding per declaration that names every missing parameter at default settings", () => {
  const findings = analyseFixture(MISSING_PARAMS_SOURCE).findings.filter((finding) => finding.ruleId === "docs.missing-param-tag");
  assert.deepEqual(findings.map((finding) => [finding.symbol, finding.message, finding.metadata.parameter]), [
    ["joinThree", "Docblock for `joinThree` is missing @param for `first`, `third`.", "first, third"],
    ["joinNone", "Docblock for `joinNone` is missing @param for `left`, `right`.", "left, right"],
  ]);
});

// Fixture for docs.stale-param-tag naming every stale parameter in one finding behind
// docs.missing-param-tag's everyCallable switch: `joinRenamed` keeps tags for two parameters it no
// longer has, one of them twice, and `trimOneStale` keeps one.
const STALE_PARAMS_SOURCE = `// File overview: docblocks that keep tags for renamed parameters.

/**
 * @param first - the old first label
 * @param left - the first label
 * @param second - the old second label
 * @param first - the old first label again
 * @param right - the second label
 */
export function joinRenamed(left: string, right: string): string { return left + right; }

/**
 * @param raw - the old label
 * @param label - the label to trim
 */
export function trimOneStale(label: string): string { return label.trim(); }
`;

// Collects docs.stale-param-tag findings on STALE_PARAMS_SOURCE as [symbol, message, parameter] rows in their stable emission order.
function staleParamFindings(options: Parameters<typeof analyseFixture>[1] = {}): unknown[][] {
  return analyseFixture(STALE_PARAMS_SOURCE, options).findings.filter((finding) => finding.ruleId === "docs.stale-param-tag").map((finding) => [finding.symbol, finding.message, finding.metadata.parameter]);
}

test("docs.stale-param-tag keeps one finding per stale tag at default settings and under docs.missing-return-tag's everyCallable alone", () => {
  const expected = [["joinRenamed", "Docblock for `joinRenamed` has stale @param tag `first`.", "first"], ["trimOneStale", "Docblock for `trimOneStale` has stale @param tag `raw`.", "raw"]];
  assert.deepEqual(staleParamFindings(), expected);
  assert.deepEqual(staleParamFindings({ config: { rules: { "docs.missing-return-tag": { options: { everyCallable: true } } } } }), expected);
});

test("everyCallable on docs.missing-param-tag makes docs.stale-param-tag name every stale parameter once in one finding", () => {
  assert.deepEqual(staleParamFindings({ config: { rules: { "docs.missing-param-tag": { options: { everyCallable: true } } } } }), [
    ["joinRenamed", "Docblock for `joinRenamed` has stale @param tags `first`, `second`.", "first, second"],
    ["trimOneStale", "Docblock for `trimOneStale` has stale @param tag `raw`.", "raw"],
  ]);
});
