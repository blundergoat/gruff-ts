// Scan-surface guardrail tests: zero-file inputs report a note instead of a silent clean exit,
// huge files get a bounded deep scan with text-level rules intact, and generated/copied files
// drop docs/naming churn while keeping sensitive-data coverage.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { renderReport, renderSummary, renderSummaryJson } from "./report-renderers.ts";
import { analyseFixture, analyseProject, analyseProjectInCurrentDirectory, HIGH_ENTROPY_FIXTURE_VALUE, PRIVATE_KEY_HEADER_FIXTURE_VALUE } from "./test-fixtures.ts";

test("requested directory hidden by parent gitignore reports a no-analysable-files note", () => {
  // The adoption-scan repro: a nested project excluded by the parent's .gitignore analysed zero
  // files and exited clean. The note names the cause; diagnostics stay empty so exit codes hold.
  const report = analyseProject(
    {
      ".gitignore": "nested/\n",
      "nested/app.ts": "export const value = 1;\n",
      "root.ts": "export const root = 1;\n",
    },
    { paths: ["nested"] },
  );
  assert.equal(report.paths.analysedFiles, 0);
  assert.deepEqual(report.diagnostics, []);
  const notes = report.notes ?? [];
  assert.equal(notes.length, 1);
  assert.equal(notes[0]?.noteType, "no-analysable-files");
  assert.equal(notes[0]?.path, "nested");
  assert.match(notes[0]?.message ?? "", /excluded by ignore rules/);
});

test("one ignored input plus one analysed input notes only the ignored input", () => {
  // Multi-input runs must attribute the note per input - an input that contributed files gets none.
  const report = analyseProject(
    {
      ".gitignore": "nested/\n",
      "nested/app.ts": "export const value = 1;\n",
      "src/root.ts": "/** Root fixture value. */\nexport const root = 1;\n",
    },
    { paths: ["nested", "src"] },
  );
  assert.equal(report.paths.analysedFiles, 1);
  const notes = report.notes ?? [];
  assert.deepEqual(notes.map((note) => note.path), ["nested"]);
});

test("findings outside the run root use absolute paths", () => {
  const scanWorkingDirectory = mkdtempSync(join(tmpdir(), "gruff-run-root-"));
  const externalProjectDirectory = mkdtempSync(join(tmpdir(), "gruff-external-root-"));
  const originalWorkingDirectory = cwd();
  try {
    const externalSourcePath = join(externalProjectDirectory, "external.ts");
    writeFileSync(externalSourcePath, "export function run(input: string): unknown { return eval(input); }\n");
    chdir(scanWorkingDirectory);
    const report = analyseProjectInCurrentDirectory({ paths: [externalProjectDirectory] });
    const evalFinding = report.findings.find((entry) => entry.ruleId === "security.eval-call");

    assert.equal(evalFinding?.filePath, externalSourcePath.replaceAll("\\", "/"));
    assert.equal(evalFinding?.filePath.startsWith("../"), false);
  } finally {
    chdir(originalWorkingDirectory);
    rmSync(scanWorkingDirectory, { recursive: true, force: true });
    rmSync(externalProjectDirectory, { recursive: true, force: true });
  }
});

test("size file-length counts substantive lines instead of documentation padding", () => {
  const commentOnlyTypeScript = Array.from({ length: 1001 }, (_, index) => `// Documentation line ${index + 1}`).join("\n");
  const blockCommentTypeScript = ["/**", ...Array.from({ length: 1001 }, (_, index) => ` * Guide line ${index + 1}`), " */"].join("\n");
  const commentOnlyYaml = Array.from({ length: 1001 }, (_, index) => `# Configuration note ${index + 1}`).join("\n");
  const commentOnlyIni = Array.from({ length: 1001 }, (_, index) => `; Configuration note ${index + 1}`).join("\n");
  const commentOnlyXml = ["<!--", ...Array.from({ length: 1001 }, (_, index) => `Guide line ${index + 1}`), "-->"].join("\n");
  const substantiveJson = Array.from({ length: 1001 }, (_, index) => `"// route ${index}",`).join("\n");

  const typeScriptFinding = analyseFixture(commentOnlyTypeScript, { fileName: "help-guide.ts" }).findings.find((finding) => finding.ruleId === "size.file-length");
  const blockCommentFinding = analyseFixture(blockCommentTypeScript, { fileName: "block-guide.ts" }).findings.find((finding) => finding.ruleId === "size.file-length");
  const yamlFinding = analyseFixture(commentOnlyYaml, { fileName: "settings.yaml" }).findings.find((finding) => finding.ruleId === "size.file-length");
  const iniFinding = analyseFixture(commentOnlyIni, { fileName: "settings.ini" }).findings.find((finding) => finding.ruleId === "size.file-length");
  const xmlFinding = analyseFixture(commentOnlyXml, { fileName: "guide.xml" }).findings.find((finding) => finding.ruleId === "size.file-length");
  const substantiveFinding = analyseFixture(substantiveJson, { fileName: "large.json" }).findings.find((finding) => finding.ruleId === "size.file-length");

  assert.equal(typeScriptFinding, undefined);
  assert.equal(blockCommentFinding, undefined);
  assert.equal(yamlFinding, undefined);
  assert.equal(iniFinding, undefined);
  assert.equal(xmlFinding, undefined);
  assert.deepEqual(substantiveFinding?.metadata, { lines: 1001, threshold: 1000 });
});

test("a normally analysable scan carries no notes field", () => {
  // The additive field is present only when at least one note exists, so existing gruff.analysis.v2
  // consumers and golden outputs see byte-identical reports for ordinary scans.
  const report = analyseFixture("export const value = 1;\n");
  assert.equal(report.notes, undefined);
});

test("non-text script bytes are noted and skipped before parser diagnostics", () => {
  const report = analyseFixture("\0eval(userInput);\n", { fileName: "binary.js" });

  assert.deepEqual(report.diagnostics, []);
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
  assert.deepEqual((report.notes ?? []).map((note) => ({ type: note.noteType, path: note.path })), [
    { type: "non-text-file", path: "binary.js" },
  ]);
});

test("a script file over the default line budget keeps text rules and reports a non-fatal diagnostic", () => {
  // The 146k-line copied perf fixture timed out whole scans. Over-budget files still count as
  // analysed, still run size/sensitive-data/text rules, but skip deep script passes (the eval
  // call below would otherwise produce security.eval-call).
  const filler = Array.from({ length: 20_001 }, (_, index) => `export const filler${index} = ${index};`).join("\n");
  const hugeSource = `${filler}\nconst secret = "${HIGH_ENTROPY_FIXTURE_VALUE}";\neval("payload");\n`;
  const report = analyseProject(
    { "huge.ts": hugeSource },
    { paths: ["huge.ts"], config: { rules: { "size.file-length": { severity: "warning" } } } },
  );

  assert.equal(report.paths.analysedFiles, 1);
  const diagnostic = report.diagnostics.find((entry) => entry.diagnosticType === "bounded-deep-scan");
  assert.ok(diagnostic);
  assert.equal(diagnostic.filePath, "huge.ts");
  assert.equal(diagnostic.invalidatesRun, false);
  assert.match(diagnostic.message, /path=huge\.ts; lines=20004; bytes=\d+; maxLines=20000; maxBytes=2000000; override=default/);
  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
});

test("a smaller sibling file still receives full deep analysis next to a bounded file", () => {
  // The budget is per file: the eval in the small file keeps firing while the huge file is bounded.
  const filler = Array.from({ length: 20_001 }, (_, index) => `export const filler${index} = ${index};`).join("\n");
  const report = analyseProject({
    "huge.ts": `${filler}\neval("payload");\n`,
    "small.ts": `/** Small fixture. */\nexport function run(input: string): void {\n  eval(input);\n}\n`,
  });
  const evalFindings = report.findings.filter((finding) => finding.ruleId === "security.eval-call");
  assert.deepEqual(evalFindings.map((finding) => finding.filePath), ["small.ts"]);
  assert.deepEqual(report.diagnostics.filter((entry) => entry.diagnosticType === "bounded-deep-scan").map((entry) => entry.filePath), ["huge.ts"]);
});

test("config can trigger the byte bound and CLI settings take precedence or disable it", () => {
  const source = `/** Small fixture. */\nexport function run(input: string): void { eval(input); }\n`;
  const configured = analyseProject(
    { "small.ts": source },
    { config: { deepScanBudget: { enabled: true, maxLines: 100, maxBytes: 20 } } },
  );
  assert.match(configured.diagnostics[0]?.message ?? "", /maxLines=100; maxBytes=20; override=config/);
  assert.equal(configured.findings.some((finding) => finding.ruleId === "security.eval-call"), false);

  const overridden = analyseProject(
    { "small.ts": source },
    {
      config: { deepScanBudget: { enabled: true, maxLines: 1, maxBytes: 1 } },
      deepScanBudget: { enabled: true, maxLines: 100, maxBytes: 10_000 },
    },
  );
  assert.equal(overridden.diagnostics.some((entry) => entry.diagnosticType === "bounded-deep-scan"), false);
  assert.equal(overridden.findings.some((finding) => finding.ruleId === "security.eval-call"), true);

  const disabled = analyseProject(
    { "small.ts": source },
    { config: { deepScanBudget: { enabled: true, maxLines: 1, maxBytes: 1 } }, deepScanBudget: { enabled: false } },
  );
  assert.equal(disabled.diagnostics.some((entry) => entry.diagnosticType === "bounded-deep-scan"), false);
  assert.equal(disabled.findings.some((finding) => finding.ruleId === "security.eval-call"), true);
});

test("the deep-scan budget never applies to non-code text", () => {
  const report = analyseProject(
    { "notes.md": "secret prose\n".repeat(20) },
    { config: { deepScanBudget: { enabled: true, maxLines: 1, maxBytes: 1 } } },
  );
  assert.equal(report.diagnostics.some((entry) => entry.diagnosticType === "bounded-deep-scan"), false);
});

test("bounded deep-scan diagnostics are visible in every supported report surface", () => {
  const report = analyseProject(
    { "small.ts": "export const value = 1;\n" },
    { config: { deepScanBudget: { enabled: true, maxLines: 1, maxBytes: 1 } } },
  );
  for (const format of ["text", "json", "html", "markdown", "github", "hotspot", "sarif"] as const) {
    assert.match(renderReport(report, format), /bounded-deep-scan/, format);
  }
  assert.match(renderSummary(report), /bounded-deep-scan/);
  assert.match(renderSummaryJson(report), /bounded-deep-scan/);
});

test("generated files skip docs/naming findings but keep sensitive-data findings", () => {
  // D6 policy: a generated .d.ts with a bare lint suppression produces no suppression-rationale
  // or missing-doc findings, but a private-key marker in the same generated file must still flag.
  const eslintDisable = ["eslint", "-disable-next-line @typescript-eslint/no-explicit-any"].join("");
  const generatedSource = `// AUTO-GENERATED FROM schema.json - DO NOT EDIT
// ${eslintDisable}
export function generatedHelper(value: any): string {
  const embedded = "${PRIVATE_KEY_HEADER_FIXTURE_VALUE}";
  return String(value) + embedded;
}
`;
  const report = analyseFixture(generatedSource, { fileName: "generated-api.d.ts" });
  assert.equal(report.findings.some((finding) => finding.pillar === "documentation"), false);
  assert.equal(report.findings.some((finding) => finding.pillar === "naming"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.private-key"), true);
});

test("handwritten source with the same suppression still produces docs findings", () => {
  // The generated skip is marker-based; the identical suppression in maintainer-authored source
  // keeps its docs.suppression-without-rationale finding.
  const handwrittenSource = `// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function helper(value: any): string {
  return String(value);
}
`;
  const report = analyseFixture(handwrittenSource, { fileName: "handwritten.ts" });
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.suppression-without-rationale"), true);
});
