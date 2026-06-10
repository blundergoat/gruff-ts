// Scan-surface guardrail tests: zero-file inputs report a note instead of a silent clean exit,
// huge files get a bounded deep scan with text-level rules intact, and generated/copied files
// drop docs/naming churn while keeping sensitive-data coverage.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject, HIGH_ENTROPY_FIXTURE_VALUE, PRIVATE_KEY_HEADER_FIXTURE_VALUE } from "./test-fixtures.ts";

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

test("a normally analysable scan carries no notes field", () => {
  // The additive field is present only when at least one note exists, so existing gruff.analysis.v2
  // consumers and golden outputs see byte-identical reports for ordinary scans.
  const report = analyseFixture("export const value = 1;\n");
  assert.equal(report.notes, undefined);
});

test("a script file over the deep-scan budget keeps text rules and reports a bounded note", () => {
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
  const notes = report.notes ?? [];
  assert.equal(notes.length, 1);
  assert.equal(notes[0]?.noteType, "bounded-deep-scan");
  assert.equal(notes[0]?.path, "huge.ts");
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
  assert.deepEqual((report.notes ?? []).map((note) => note.path), ["huge.ts"]);
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
