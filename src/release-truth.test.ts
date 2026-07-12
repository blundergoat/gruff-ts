// Release-truth tests protect facts that users and package consumers rely on between releases.
// This focused suite scans one unchanged project twice through the full analyser pipeline.
// Maintainers reach it when report generation changes ordering, identity, or volatile run metadata.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyseProjectInCurrentDirectory, setupAnalyseProjectDirectory } from "./test-fixtures.ts";
import type { AnalysisReport } from "./types.ts";

const EVALUATION_CALL = ["ev", "al"].join("");
const DETERMINISM_FIXTURE_SOURCE = [
  "// File overview: repeated release-report fixture.",
  "/** Executes a source expression so both scans contain a stable security finding. */",
  "export function executeUserExpression(source: string): unknown {",
  `  return ${EVALUATION_CALL}(source);`,
  "}",
].join("\n");

/*
 * Serializes the report as a JSON user receives it after removing the per-run timestamp.
 * Invariant: every path, finding, score, and ordering decision remains under byte comparison.
 */
function normalizedReportBytes(report: AnalysisReport): string {
  const normalizedReport = structuredClone(report);
  Reflect.deleteProperty(normalizedReport.run, "generatedAt");
  return JSON.stringify(normalizedReport);
}

/*
 * Scans one unchanged user project twice and compares its visible content and finding identities.
 * Side effect: writes and removes a temporary project on the filesystem after both scans.
 * Invariant: only each independently valid generation timestamp may vary.
 */
test("repeated scans differ only by run.generatedAt", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-release-truth-"));
  const originalWorkingDirectory = cwd();
  const scanOptions = { shouldSkipConfig: true } as const;

  // Both scans use one project root so path metadata represents the same user command and scope.
  try {
    setupAnalyseProjectDirectory(projectRoot, { "src/release-fixture.ts": DETERMINISM_FIXTURE_SOURCE }, scanOptions);
    chdir(projectRoot);
    const firstReport = analyseProjectInCurrentDirectory(scanOptions);
    const secondReport = analyseProjectInCurrentDirectory(scanOptions);

    assert.equal(new Date(firstReport.run.generatedAt).toISOString(), firstReport.run.generatedAt);
    assert.equal(new Date(secondReport.run.generatedAt).toISOString(), secondReport.run.generatedAt);
    assert.equal(firstReport.findings.length > 0, true, "fixture must exercise finding identity and order");
    assert.equal(normalizedReportBytes(firstReport), normalizedReportBytes(secondReport));

    // Ordered fingerprints prove the stable bytes did not conceal finding reordering or identity churn.
    const firstFindingFingerprints = firstReport.findings.map((finding) => finding.fingerprint);
    const secondFindingFingerprints = secondReport.findings.map((finding) => finding.fingerprint);
    assert.deepEqual(firstFindingFingerprints, secondFindingFingerprints);
  } finally {
    chdir(originalWorkingDirectory);
    rmSync(projectRoot, { recursive: true, force: true });
  }
});
