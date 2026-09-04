// Regression suite for the 2026-08 goat-flow false-positive report: prose about task markers
// must stay quiet, stated remediations must clear their findings, and graded severities must
// follow the evidence each rule already computes.
import assert from "node:assert/strict";
import test from "node:test";
import { makeFinding } from "./findings.ts";
import { ruleDescriptors } from "./rules.ts";
import { scoreReport } from "./scoring.ts";
import { analyseFixture } from "./test-fixtures.ts";
import type { Finding } from "./types.ts";

// Filters one scan down to a single rule so every case reads as fixture + expectation.
function ruleFindings(source: string, ruleId: string, fileName?: string) {
  const report = analyseFixture(source, fileName ? { fileName } : {});
  return report.findings.filter((entry) => entry.ruleId === ruleId);
}

// Minimal real finding for direct scoring-math tests; distinct lines keep each fingerprint unique.
function scoredFinding(ruleId: string, pillar: Finding["pillar"], severity: Finding["severity"], line: number): Finding {
  return makeFinding({ ruleId, message: `${ruleId} fired.`, filePath: "src/sample.ts", line, severity, pillar, confidence: "medium" });
}

test("composite counts clean pillars as perfect instead of dropping them", () => {
  // Covers the punished-finisher regression: a pillar with zero findings must average in at 100,
  // not vanish from the mean, so finishing a pillar can never lower the headline score.
  const expectedPillarUniverse = 11;
  const pillarUniverseCount = new Set(ruleDescriptors().map((descriptor) => descriptor.pillar)).size;
  assert.equal(pillarUniverseCount, expectedPillarUniverse);
  const score = scoreReport([
    scoredFinding("docs.missing-file-overview", "documentation", "advisory", 1),
    scoredFinding("security.process-exec", "security", "warning", 2),
  ], 10);
  // Both findings are medium confidence, which now weighs 0.75x: gruff-ts had no confidence
  // dimension before M06, so a low-confidence heuristic used to weigh exactly as much as a certain
  // defect. Over ten evaluated files documentation weighs 0.75 (density 0.075, score 78.57) and
  // security 3.00 (density 0.30, score 62.50).
  const documentationScore = 78.57;
  const securityScore = 62.5;
  const expectedComposite = (documentationScore + securityScore + 100 * (pillarUniverseCount - 2)) / pillarUniverseCount;
  assert.equal(score.composite, Math.round(expectedComposite * 100) / 100);
  assert.equal(score.pillars.find((pillar) => pillar.pillar === "documentation")?.score, documentationScore);
  assert.equal(score.pillars.find((pillar) => pillar.pillar === "security")?.score, securityScore);
});

test("removing any single finding never decreases the composite", () => {
  // Covers the report's invariant: fixing a finding must never read as a score regression.
  const findings = [
    scoredFinding("docs.missing-file-overview", "documentation", "advisory", 1),
    scoredFinding("security.process-exec", "security", "warning", 2),
    scoredFinding("security.eval-usage", "security", "error", 3),
    scoredFinding("size.file-length", "size", "warning", 4),
  ];
  const fullComposite = scoreReport(findings, 10).composite;
  findings.forEach((_finding, index) => {
    const reducedComposite = scoreReport(findings.filter((_entry, entryIndex) => entryIndex !== index), 10).composite;
    assert.equal((reducedComposite ?? 0) >= (fullComposite ?? 0), true, `removing finding ${index} lowered the composite`);
  });
});

test("stale-param-tag stays quiet for parenthesised parameter types", () => {
  // Covers the paren-type regression the shared AST parse fixed: every tag below is correct, so
  // indexed typeof, parenthesised unions, nested generics, and function types must all stay clean.
  const findings = ruleFindings(`const SECTIONS = ["a", "b"] as const;

/**
 * Accepts one section pick per call.
 *
 * @param section - one of the known sections
 * @param authority - the resolution authority
 * @param pair - union-typed spare values
 * @param picks - reads chosen section entries
 * @param onDone - completion callback
 * @returns whether the section was accepted
 */
export function withComplexTypes(
  section: (typeof SECTIONS)[number],
  authority: string,
  pair: (string | number)[],
  picks: Array<(typeof SECTIONS)[number]>,
  onDone: (value: string) => void,
): boolean {
  onDone(authority);
  return section.length > 0 && pair.length + picks.length >= 0;
}
`, "docs.stale-param-tag");
  assert.deepEqual(findings, []);
});

test("stale-param-tag still fires when a tag names a removed parameter", () => {
  // Covers detection preservation beside a parenthesised type: the stale tag must still report.
  const findings = ruleFindings(`/**
 * Formats the header row.
 *
 * @param removedName - no longer exists
 * @param value - the text to format
 * @returns the formatted text
 */
export function formatHeader(value: (string | null)[]): string {
  return String(value.length);
}
`, "docs.stale-param-tag");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata.parameter, "removedName");
});

test("todo-without-tracking stays quiet on prose describing marker words", () => {
  // Covers the marker-prose regression: a JSDoc and a line comment ABOUT "TODO" handling fired twice.
  const findings = ruleFindings(`/**
 * Find the placeholder an author left in a readiness answer.
 * Use when checking a section, so an unfilled "TODO", "???", or bare "Answer:" is reported
 * back to the author instead of shipping as though it were a real answer.
 *
 * @param line - one line as the author wrote it; empty means nothing to inspect
 * @returns the marker text, or null when the line is properly filled in
 */
export function unresolvedMarker(line: string): string | null {
  // The author parked the answer with a TODO/TBD marker, so name it back to them.
  if (line.includes("TODO")) return "TODO";
  return null;
}
`, "docs.todo-without-tracking");
  assert.deepEqual(findings, []);
});

test("todo-without-tracking stays quiet on quoted, backticked, and mid-sentence mentions", () => {
  // Covers the mention-shape regression: quoted, backticked, and mid-sentence marker words are prose.
  const findings = ruleFindings(`// "TODO" entries in the queue are rendered with a badge.
// The \`FIXME\` token is highlighted by the editor plugin.
// Rows keep their HACK column until the export finishes.
export const badge = "shown";
`, "docs.todo-without-tracking");
  assert.deepEqual(findings, []);
});

test("todo-without-tracking stays quiet on markers inside fenced doc examples", () => {
  // Covers the fenced-example regression: a marker shown inside a doc-comment code fence is a sample.
  const findings = ruleFindings(`/**
 * Renders the task list, keeping unfinished entries visible.
 *
 * \`\`\`ts
 * TODO: implement the fast path
 * \`\`\`
 */
export function renderTasks(): string {
  return "";
}
`, "docs.todo-without-tracking");
  assert.deepEqual(findings, []);
});

test("todo-without-tracking still reports real leading markers", () => {
  // Covers the detection-preservation contract: every conventional marker form keeps firing.
  const findings = ruleFindings(`// TODO: replace the retry shim once the upstream fix ships
// FIXME - overflow when the queue exceeds 32k entries
// HACK(matt) fall back to the slow path on Windows
// XXX
// todo: lowercase markers still count
export const retryEnabled = true;
`, "docs.todo-without-tracking");
  assert.deepEqual(findings.map((entry) => entry.metadata.marker), ["TODO", "FIXME", "HACK", "XXX", "TODO"]);
  assert.deepEqual(findings.map((entry) => entry.line), [1, 2, 3, 4, 5]);
});

test("todo-without-tracking keeps space-delimited markers and tracked exemptions", () => {
  // Covers the existing contract: bare continuation markers fire, tracked markers stay quiet.
  const findings = ruleFindings(`// TODO add the missing owner
// TODO #123 tracked reference stays quiet
// FIXME tracked in GH-456
export const ready = false;
`, "docs.todo-without-tracking");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.line, 1);
});

// Fixture covers the test-setup regression: a genuine purpose JSDoc without the rule's keyword
// vocabulary must still clear docs.fixture-purpose-missing.
const GENUINE_PURPOSE_SETUP_FIXTURE = `import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { it } from "node:test";

/**
 * Models a crash after draft deletion but before receipt creation. Writes a
 * stale owner marker and removes the complete disposable project afterward.
 */
it("rejects an orphaned stale claim when its draft is already gone", () => {
  const root = mkdtempSync("repro-");
  const capture = {
    projectRoot: root,
    intervalMs: 60_000,
    stableMs: 0,
    claimStaleMs: 0,
    stagingDir: root,
  };
  const nonce = "orphaned-stale-owner";
  const claimPath = capture.stagingDir + nonce;
  writeFileSync(claimPath, "{}");
  writeFileSync(root, "{}");
  writeFileSync(nonce, "{}");
  assert.equal(claimPath.length > 0, true);
});
`;

test("fixture-purpose-missing is cleared by a genuine purpose comment above the test", () => {
  const findings = ruleFindings(GENUINE_PURPOSE_SETUP_FIXTURE, "docs.fixture-purpose-missing", "recovery.test.ts");
  assert.deepEqual(findings, []);
});

test("fixture-purpose-missing reads a stacked // run above a fixture as one comment", () => {
  // Covers the stacked-header regression: vocabulary on the first line of a // run must count.
  const findings = ruleFindings(`// Covers the parser regression sweep for the recovery scanner.
// Each entry mirrors one incident crash shape.
const parserSweepFixture = \`
const a1 = 1;
const a2 = 2;
const a3 = 3;
const a4 = 4;
const a5 = 5;
const a6 = 6;
const a7 = 7;
const a8 = 8;
const a9 = 9;
const a10 = 10;
const a11 = 11;
const a12 = 12;
const a13 = 13;
\`;
`, "docs.fixture-purpose-missing", "sweep.test.ts");
  assert.deepEqual(findings, []);
});

test("fixture-purpose-missing names the setup shape and the accepted comment position", () => {
  // Covers the message-honesty contract: the reported fix must be the fix that clears the finding.
  const undocumented = GENUINE_PURPOSE_SETUP_FIXTURE.split("\n").filter((line) => !/^ \*|^\/\*\*|^ \*\//.test(line)).join("\n");
  const findings = ruleFindings(undocumented, "docs.fixture-purpose-missing", "recovery.test.ts");
  assert.equal(findings.length, 1);
  assert.match(findings[0]?.message ?? "", /builds a large fixture setup without a purpose comment/);
  assert.match(findings[0]?.remediation ?? "", /directly above the test declaration/);
  assert.equal(findings[0]?.metadata.targetKind, "test-setup");
});

test("fixture-purpose-missing is cleared by the remediation vocabulary above the test", () => {
  // Covers the stated-remediation contract: wording taken from the remediation text clears it.
  const reworded = GENUINE_PURPOSE_SETUP_FIXTURE.replace(
    /Models a crash after draft deletion but before receipt creation\. Writes a\n \* stale owner marker and removes the complete disposable project afterward\./,
    "Covers the stale-claim recovery regression.",
  );
  const findings = ruleFindings(reworded, "docs.fixture-purpose-missing", "recovery.test.ts");
  assert.deepEqual(findings, []);
});

// Matrix fixtures for the comment-style coupling report: a JSDoc block and an equivalent // run
// above the same declaration must trigger the same context-doc rules. The docblock tag pack
// (missing-param-tag / missing-return-tag) is the one deliberate asymmetry, pinned further down,
// because // comments cannot carry @param or @returns tags at all.
function commentStyleVariants(jsdocLines: string[], body: string): { jsdoc: string; lineRun: string } {
  return {
    jsdoc: ["/**", ...jsdocLines.map((line) => ` * ${line}`), " */", body, ""].join("\n"),
    lineRun: [...jsdocLines.map((line) => `// ${line}`), body, ""].join("\n"),
  };
}

test("missing-side-effect-doc treats JSDoc and // runs identically", () => {
  const sideEffectBody = `export function persistMarker(path: string): void {
  writeFileSync(path, "{}");
}`;
  const silentComment = commentStyleVariants(["Stores the run marker for later comparison."], sideEffectBody);
  assert.equal(ruleFindings(silentComment.jsdoc, "docs.missing-side-effect-doc").length, 1);
  assert.equal(ruleFindings(silentComment.lineRun, "docs.missing-side-effect-doc").length, 1);

  // The 0.4.0 trap: side-effect vocabulary on the FIRST line of a two-line comment must count.
  const documentedComment = commentStyleVariants(["Writes the run marker to disk so a later", "comparison can read it back."], sideEffectBody);
  assert.deepEqual(ruleFindings(documentedComment.jsdoc, "docs.missing-side-effect-doc"), []);
  assert.deepEqual(ruleFindings(documentedComment.lineRun, "docs.missing-side-effect-doc"), []);
});

test("missing-error-behavior-doc treats JSDoc and // runs identically", () => {
  const throwingBody = `export function requirePayload(value: string): string {
  if (value === "") {
    throw new Error("payload required");
  }
  return value;
}`;
  const silentComment = commentStyleVariants(["Validates the payload shape before use."], throwingBody);
  assert.equal(ruleFindings(silentComment.jsdoc, "docs.missing-error-behavior-doc").length, 1);
  assert.equal(ruleFindings(silentComment.lineRun, "docs.missing-error-behavior-doc").length, 1);

  const documentedComment = commentStyleVariants(["Throws when the payload is empty, otherwise", "returns it unchanged."], throwingBody);
  assert.deepEqual(ruleFindings(documentedComment.jsdoc, "docs.missing-error-behavior-doc"), []);
  assert.deepEqual(ruleFindings(documentedComment.lineRun, "docs.missing-error-behavior-doc"), []);
});

test("fixture-purpose-missing treats JSDoc and // run purpose comments identically", () => {
  const lineRunVariant = GENUINE_PURPOSE_SETUP_FIXTURE.replace(
    /\/\*\*\n \* Models a crash after draft deletion but before receipt creation\. Writes a\n \* stale owner marker and removes the complete disposable project afterward\.\n \*\//,
    "// Models a crash after draft deletion but before receipt creation. Writes a\n// stale owner marker and removes the complete disposable project afterward.",
  );
  assert.notEqual(lineRunVariant, GENUINE_PURPOSE_SETUP_FIXTURE);
  assert.deepEqual(ruleFindings(lineRunVariant, "docs.fixture-purpose-missing", "recovery.test.ts"), []);
});

test("docblock tag rules stay a deliberate JSDoc-only asymmetry", () => {
  // A // comment physically cannot carry @param or @returns, so the tag pack only audits JSDoc.
  const untaggedBody = `export function formatLabel(value: string): string {
  return value.trim();
}`;
  const variants = commentStyleVariants(["Formats a label for the report header."], untaggedBody);
  assert.equal(ruleFindings(variants.jsdoc, "docs.missing-param-tag").length, 1);
  assert.equal(ruleFindings(variants.jsdoc, "docs.missing-return-tag").length, 1);
  assert.deepEqual(ruleFindings(variants.lineRun, "docs.missing-param-tag"), []);
  assert.deepEqual(ruleFindings(variants.lineRun, "docs.missing-return-tag"), []);
});

test("acronym-case allows SCREAMING constants beside camelCase identifiers", () => {
  // Covers the idiomatic-mix regression: convention-forced casings carry no drift signal.
  const findings = ruleFindings(`const RAW_HTML_BLOCK_TAGS = /^(?:div|p|ul|table)$/iu;

export function startsHtmlBlock(line: string): boolean {
  if (line.trim().length === 0) return false;
  const inHtmlComment = line.startsWith("<!--");
  if (inHtmlComment) return false;
  return RAW_HTML_BLOCK_TAGS.test(line.replace(/[<>/]/gu, "").trim());
}
`, "naming.acronym-case");
  assert.deepEqual(findings, []);
});

test("acronym-case stays quiet when every acronym casing is convention-forced", () => {
  // Covers the forced-surfaces case: a screaming constant beside a lower_snake name is two conventions.
  const findings = ruleFindings(`const RAW_HTML_TAGS = "div";
const parse_html = "p";
console.log(RAW_HTML_TAGS, parse_html);
`, "naming.acronym-case");
  assert.deepEqual(findings, []);
});

test("acronym-case still fires on chosen-case drift within camel and Pascal names", () => {
  // Covers detection preservation: the author chose Html once and HTML once in the same file.
  const findings = ruleFindings(`const parsedHtml = "a";
const rawHTML = "b";
console.log(parsedHtml, rawHTML);
`, "naming.acronym-case");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.symbol, "rawHTML");
  assert.deepEqual(findings[0]?.metadata.variants, ["title", "upper"]);
});

test("delimited casing twins are not an acronym-case concern", () => {
  // Covers the report's HTML_TAGS/HTML_Tags example: the acronym HTML is upper in BOTH names, so
  // there is no acronym drift to report. The TAGS/Tags drift is general casing drift; the
  // inconsistent-casing rule boundary-filters SCREAMING constants (a 0.5.0 decision protecting
  // DTO-versus-constant pairs), so this half-screaming twin is deliberately quiet there too.
  const source = `const HTML_TAGS = "a";
const HTML_Tags = "b";
console.log(HTML_TAGS, HTML_Tags);
`;
  assert.deepEqual(ruleFindings(source, "naming.acronym-case"), []);
  assert.deepEqual(ruleFindings(source, "naming.inconsistent-casing"), []);
});

test("magic-threshold rationale on an earlier line of a stacked // run counts", () => {
  // Covers the stacked-header contract shared with fixture-purpose: rationale vocabulary on the
  // first line of a // run must clear the threshold finding.
  const findings = ruleFindings(`// This retry ceiling is tuned for flaky-network reruns, because three
// attempts cover the recovery cases we have observed.
const MAX_RETRY_CAP = 3;
export const usesCap = MAX_RETRY_CAP;
`, "docs.magic-threshold-without-rationale");
  assert.deepEqual(findings, []);
});

test("loop-in-test lets labeled data-driven loops opt out", () => {
  // Covers the parametrized-test contract: a per-case assertion message keeps a failing row
  // identifiable, which is exactly what this rule exists to protect.
  const labeled = ruleFindings(`test("runs every case", () => {
  for (const row of buildCases()) {
    assert.equal(run(row.input), row.expected, \`case \${row.name} failed\`);
  }
});
`, "test-quality.loop-in-test", "cases.test.ts");
  assert.deepEqual(labeled, []);

  const unlabeled = ruleFindings(`test("runs every case", () => {
  for (const row of buildCases()) {
    assert.equal(run(row.input), row.expected);
  }
});
`, "test-quality.loop-in-test", "cases.test.ts");
  assert.equal(unlabeled.length, 1);
  assert.match(unlabeled[0]?.message ?? "", /hides which iteration failed/);
  assert.equal(unlabeled[0]?.confidence, "medium");
});

test("loop-in-test handles destructured row bindings in both opt-outs", () => {
  // Covers the destructured-binding gap: the body brace must be found past the header parens,
  // not at the destructuring brace inside them.
  const labeled = ruleFindings(`test("runs destructured cases", () => {
  for (const { name, input } of buildCases()) {
    assert.equal(run(input), name, \`case \${name} failed\`);
  }
});
`, "test-quality.loop-in-test", "cases.test.ts");
  assert.deepEqual(labeled, []);

  const literalTable = ruleFindings(`test("sweeps the fixture table", () => {
  for (const { name } of [{ name: "a" }, { name: "b" }]) {
    assert.ok(name);
  }
});
`, "test-quality.loop-in-test", "cases.test.ts");
  assert.deepEqual(literalTable, []);

  const unlabeled = ruleFindings(`test("hides the failing case", () => {
  for (const { input } of buildCases()) {
    assert.equal(run(input), true);
  }
});
`, "test-quality.loop-in-test", "cases.test.ts");
  assert.equal(unlabeled.length, 1);
});

test("fixture-purpose-missing still fires on undocumented and trivially commented fixtures", () => {
  // Covers detection preservation: no comment and sub-sentence comments both keep reporting.
  const lines = Array.from({ length: 13 }, (_value, index) => `const b${index} = ${index};`).join("\n");
  const undocumentedFindings = ruleFindings(`const routeSweepFixture = \`\n${lines}\n\`;\n`, "docs.fixture-purpose-missing", "routes.test.ts");
  assert.equal(undocumentedFindings.length, 1);
  assert.equal(undocumentedFindings[0]?.line, 1);
  assert.equal(undocumentedFindings[0]?.symbol, "routeSweepFixture");
  assert.equal(Number(undocumentedFindings[0]?.metadata.fixtureLines) > 12, true);

  const trivialFindings = ruleFindings(`// setup data\nconst routeSweepFixture = \`\n${lines}\n\`;\n`, "docs.fixture-purpose-missing", "routes.test.ts");
  assert.equal(trivialFindings.length, 1);
});
