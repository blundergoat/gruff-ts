// Documentation and comment-rule tests for doc coverage, stale comments, fixture purpose, and suppressions.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject, largeFixtureSourceLines, TS_IGNORE_DIRECTIVE } from "./test-fixtures.ts";

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
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "parseDiagnostics"), true);

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
  ["docs.missing-file-overview", "docs.missing-interface-doc", "docs.missing-function-doc"].forEach((ruleId) => {
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
  const report = analyseFixture(`/**
 * Exercises stale comment references.
 */
// See \`src/missing-file.ts\` before changing this helper.
// Unknown scanner rule docs.removed-rule should be deleted.
// Run with --removed-flag when debugging.
// legacy migration note mentions \`src/old-file.ts\` intentionally.
function currentFeature(): void {}

// OldFeature function
function newFeature(): void {}
`);
  const staleFindings = report.findings.filter((finding) => finding.ruleId === "docs.stale-comment");
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "path" && finding.message.includes("src/missing-file.ts")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "ruleId" && finding.message.includes("docs.removed-rule")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--removed-flag")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "function" && finding.symbol === "newFeature"), true);
  assert.equal(staleFindings.some((finding) => finding.message.includes("src/old-file.ts")), false);
});

test("comment quality requires tracking for TODO markers", () => {
  const report = analyseFixture(`/**
 * Exercises tracked and untracked task-marker comments.
 */
// TODO owner: platform-runtime
// FIXME tracked in #123
// HACK .goat-flow/tasks/keep-fixture-intentional.md
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
  const routingBranches = branchFixtureLines(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]);
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

/** Throws when the required value is absent. */
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
`);
  const findingsByRule = new Map<string, Set<string>>();
  report.findings.forEach((finding) => {
    const symbols = findingsByRule.get(finding.ruleId) ?? new Set<string>();
    symbols.add(finding.symbol ?? String(finding.metadata.thresholdKind ?? "-"));
    findingsByRule.set(finding.ruleId, symbols);
  });

  documentationContextExpectations().forEach(([ruleId, symbol, expected]) => {
    assert.equal(findingsByRule.get(ruleId)?.has(symbol), expected, `${ruleId} ${symbol}`);
  });
});

/** Generates repeated branch lines without making the outer test look complex. */
function branchFixtureLines(values: string[]): string {
  return values.map((value) => `  if (value === "${value}") return "${value}";`).join("\n");
}

/** Lists expected documentation findings so the matrix test stays branch-light. */
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
    ["docs.missing-function-doc", "undocumentedSideEffect", true],
    ["docs.useless-docblock", "restatingComplexFlow", true],
    ["docs.missing-why-for-complex-code", "restatingComplexFlow", false],
  ];
}

// Fixture covers source-literal detection and fingerprint stability without private helper access.
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

// Fixture covers setup-block detection and stable fixture-purpose fingerprints.
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
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "undocumentedHelper"), true);

  const disabledReport = analyseFixture(source, {
    fileName: "fixture-purpose.test.ts",
    config: { rules: { "docs.fixture-purpose-missing": { enabled: false } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), false);
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "undocumentedHelper"), true);
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
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "loadValue"), true);
});

test("size file-length skips generated lockfiles", () => {
  const lockfile = Array.from({ length: 900 }, (_, index) => `"entry-${index}": "value"`).join("\n");
  const report = analyseProject({ "package-lock.json": lockfile });
  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length" && finding.filePath === "package-lock.json"), false);
});
