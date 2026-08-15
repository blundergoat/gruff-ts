// Release-truth tests protect facts that users and package consumers rely on between releases.
// This focused suite scans one unchanged project twice through the full analyser pipeline, pins which
// file kinds a scan accepts at all, and holds the documented rule counts to the live catalogue.
// Maintainers reach it when report generation changes ordering, identity, or volatile run metadata,
// or when they add or remove either a discovery extension or a rule descriptor.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { ruleDescriptors } from "./rules.ts";
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

// One fixture per file kind the discovery allowlist accepts. Contents are inert on purpose: the
// assertion counts analysed files, so nothing here needs to produce a finding.
const SCANNED_FIXTURE_FILES: Record<string, string> = {
  "asset.ts": "export const first = 1;\n",
  "asset.tsx": "export const second = 2;\n",
  "asset.js": "export const third = 3;\n",
  "asset.jsx": "export const fourth = 4;\n",
  "asset.mjs": "export const fifth = 5;\n",
  "asset.cjs": "module.exports = { sixth: 6 };\n",
  "asset.conf": "setting = on\n",
  "asset.config": "setting = on\n",
  "asset.env": "EXAMPLE_FLAG=1\n",
  "asset.ini": "[section]\nsetting = on\n",
  "asset.json": '{ "setting": true }\n',
  "asset.toml": "setting = true\n",
  "asset.xml": "<setting>on</setting>\n",
  "asset.yaml": "setting: true\n",
  "asset.yml": "setting: true\n",
  ".env": "EXAMPLE_FLAG=1\n",
  ".envrc": "export EXAMPLE_FLAG=1\n",
  ".netrc": "machine example.invalid\n",
  ".npmrc": "registry=https://registry.npmjs.org/\n",
  ".pypirc": "[distutils]\nindex-servers =\n",
};

// File kinds a scan must ignore. CSS is the load-bearing entry: it left discovery in 0.3.0, and the
// agent instruction files went on claiming it for two minor releases because nothing compared them.
const UNSCANNED_FIXTURE_FILES: Record<string, string> = {
  "asset.css": "a { color: red; }\n",
  "asset.scss": "a { color: red; }\n",
  "asset.html": "<p>text</p>\n",
  "asset.md": "# heading\n",
  "asset.txt": "text\n",
};

// Which file kinds gruff reads is repeated in prose across the docs and every agent instruction file,
// and no single edit updates them all. A failure here hands the maintainer that sweep list.
const SCAN_SURFACE_SWEEP_NOTE =
  "discovery allowlist changed - sweep the scan-surface sentence in CLAUDE.md, AGENTS.md, .github/copilot-instructions.md, README.md, docs/rules.md, .goat-flow/architecture.md, and .goat-flow/glossary.md";

/*
 * Scans a throwaway project containing exactly the supplied files and reports how many were analysed.
 * Side effect: writes and removes a temporary project directory on the filesystem.
 * Invariant: the count reflects the discovery allowlist alone, because the fixture ships no config.
 */
function analysedFileCount(files: Record<string, string>): number {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-scan-surface-"));
  const originalWorkingDirectory = cwd();
  const scanOptions = { shouldSkipConfig: true } as const;

  try {
    setupAnalyseProjectDirectory(projectRoot, files, scanOptions);
    chdir(projectRoot);
    return analyseProjectInCurrentDirectory(scanOptions).paths.analysedFiles;
  } finally {
    chdir(originalWorkingDirectory);
    rmSync(projectRoot, { recursive: true, force: true });
  }
}

/*
 * Pins both directions of the discovery allowlist so a widened or narrowed scan surface cannot ship
 * while the documentation still describes the old one.
 * Invariant: adding or removing an extension in `pushSourceFile` fails one of these two counts.
 */
test("discovery allowlist matches the documented scan surface", () => {
  const expectedScannedCount = Object.keys(SCANNED_FIXTURE_FILES).length;

  assert.equal(analysedFileCount(SCANNED_FIXTURE_FILES), expectedScannedCount, SCAN_SURFACE_SWEEP_NOTE);
  assert.equal(analysedFileCount(UNSCANNED_FIXTURE_FILES), 0, SCAN_SURFACE_SWEEP_NOTE);
});

// Files that state the catalogue size in prose, with how many times each one states it. README says it
// twice, so pinning the tally also catches a claim being deleted rather than merely going stale.
const RULE_COUNT_SURFACES = [
  { path: "package.json", claimCount: 1 },
  { path: "README.md", claimCount: 2 },
  { path: "docs/rules.md", claimCount: 1 },
  { path: ".goat-flow/architecture.md", claimCount: 1 },
];

// The per-pillar tally is duplicated in two files with different markup. Both rows carry the pillar
// name and its count, so one pattern each is enough to read them back.
const PILLAR_COUNT_SURFACES = [
  { path: "docs/rules.md", rowPattern: /^- ([a-z-]+): (\d+)$/gmu },
  { path: "README.md", rowPattern: /^\| `([a-z-]+)` \| (\d+) \|$/gmu },
];

// Adding or removing a rule touches six separate prose claims across four files, and no single edit
// updates them together. A failure here names them so the maintainer does not have to remember.
const RULE_COUNT_SWEEP_NOTE =
  "rule catalogue size changed - update package.json description, README.md (summary row, catalogue intro, and pillar table), docs/rules.md (header and Pillar Counts), and .goat-flow/architecture.md";

/*
 * Tallies how many rules each pillar contributes to the live catalogue.
 * Invariant: the returned map is the comparison target for every documented per-pillar table.
 */
function livePillarCounts(): Map<string, number> {
  const counts = new Map<string, number>();

  for (const descriptor of ruleDescriptors()) {
    counts.set(descriptor.pillar, (counts.get(descriptor.pillar) ?? 0) + 1);
  }
  return counts;
}

/*
 * Reads back the pillar/count rows a documentation file publishes.
 * Invariant: the pattern matches only tally rows, so a stray prose number cannot enter the result.
 */
function documentedPillarCounts(path: string, rowPattern: RegExp): Map<string, number> {
  const rows = [...readFileSync(path, "utf8").matchAll(rowPattern)];

  return new Map(rows.map((row) => [String(row[1]), Number(row[2])]));
}

/*
 * Reads back every catalogue-size number a file states in prose, in the order it states them.
 * Invariant: the pattern only matches an "N rules" phrase, so surrounding prose cannot inflate it.
 */
function documentedTotals(path: string): number[] {
  return [...readFileSync(path, "utf8").matchAll(/\b(\d+) rules\b/gu)].map((match) => Number(match[1]));
}

/*
 * Holds every published rule count to the live descriptor catalogue, totals and per-pillar alike.
 * Invariant: adding or removing a descriptor fails here until all four documents are reconciled.
 * Each side is assembled whole and compared once, so the failure names the file rather than an
 * anonymous loop iteration.
 */
test("documented rule counts match the live catalogue", () => {
  const liveTotal = ruleDescriptors().length;
  const livePillars = livePillarCounts();

  const publishedTotals = new Map(RULE_COUNT_SURFACES.map((surface) => [surface.path, documentedTotals(surface.path)]));
  const expectedTotals = new Map(RULE_COUNT_SURFACES.map((surface) => [surface.path, Array<number>(surface.claimCount).fill(liveTotal)]));
  assert.deepEqual(publishedTotals, expectedTotals, RULE_COUNT_SWEEP_NOTE);

  const publishedPillars = new Map(PILLAR_COUNT_SURFACES.map((surface) => [surface.path, documentedPillarCounts(surface.path, surface.rowPattern)]));
  const expectedPillars = new Map(PILLAR_COUNT_SURFACES.map((surface) => [surface.path, livePillars]));
  assert.deepEqual(publishedPillars, expectedPillars, RULE_COUNT_SWEEP_NOTE);
});
