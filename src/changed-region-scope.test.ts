// Tests for changed-region scope selection (symbol vs file) over file-wide and file-aggregate findings.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

const FILE_WIDE_PROJECT = { "src/long.ts": `${"const value = 1;\n".repeat(6)}export {};\n` };
const FILE_WIDE_DIFF_PATCH = "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -5,2 +5,2 @@\n const value = 1;\n-const previous = 1;\n+const next = 1;\n";
const LARGE_MODULE_PROJECT = {
  "src/large.ts": `${"export const largeValue = 1;\n".repeat(10)}`,
  "src/small-a.ts": "export const smallA = 1;\n",
  "src/small-b.ts": "export const smallB = 1;\n",
  "src/small-c.ts": "export const smallC = 1;\n",
};

test("symbol changed-region filtering drops file-wide findings away from their anchor", () => {
  const report = analyseProject(FILE_WIDE_PROJECT, {
    config: { rules: { "size.file-length": { threshold: 3 } } },
    diff: "-",
    diffPatch: FILE_WIDE_DIFF_PATCH,
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  assert.equal(report.suppressedCount !== undefined && report.suppressedCount > 0, true);
});

test("symbol changed-region filtering drops file-aggregate findings away from their anchor", () => {
  const report = analyseProject(LARGE_MODULE_PROJECT, {
    config: { rules: { "design.large-module-concentration": { threshold: 55, options: { minFiles: 4, minLines: 1 } } } },
    paths: ["."],
    changedRanges: "8-8",
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "design.large-module-concentration"), false);
  assert.equal(report.suppressedCount !== undefined && report.suppressedCount > 0, true);
});

test("symbol changed-region filtering keeps file-wide findings when the anchor is touched", () => {
  const report = analyseProject(FILE_WIDE_PROJECT, {
    config: { rules: { "size.file-length": { threshold: 3 } } },
    paths: ["src/long.ts"],
    changedRanges: "1-1",
  });

  const fileLength = report.findings.find((finding) => finding.ruleId === "size.file-length");
  assert.ok(fileLength);
  assert.deepEqual(fileLength.metadata, { lines: 8, threshold: 3 });
  assert.equal(typeof fileLength.remediation, "string");
});

test("file changed-region scope keeps file-wide findings for any touched hunk in the file", () => {
  const report = analyseProject(FILE_WIDE_PROJECT, {
    config: { rules: { "size.file-length": { threshold: 3 } } },
    diff: "-",
    diffPatch: FILE_WIDE_DIFF_PATCH,
    changedScope: "file",
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length"), true);
});

test("file changed-region scope keeps findings for deletion-only diffs", () => {
  const report = analyseProject(FILE_WIDE_PROJECT, {
    config: { rules: { "size.file-length": { threshold: 3 } } },
    diff: "-",
    diffPatch: "diff --git a/src/long.ts b/src/long.ts\n--- a/src/long.ts\n+++ b/src/long.ts\n@@ -5,2 +4,0 @@\n-const value = 1;\n-const value = 1;\n",
    changedScope: "file",
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length"), true);
});

test("full scans still report file-wide findings", () => {
  const report = analyseProject(FILE_WIDE_PROJECT, {
    config: { rules: { "size.file-length": { threshold: 3 } } },
    paths: ["src/long.ts"],
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length"), true);
});
