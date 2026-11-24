// Changed-region regression for the native filter and v3 machine adapter. Native analysis retains
// `suppressedCount` for internal consumers; JSON publishes the same partition as
// `diff.filteredFindings` and `summary.suppressedFindings`. The cases also guard in-region findings,
// canonical `file` paths, and the `advisory|warning|error` vocabulary. The separate
// `gruff.hook.v1` adapter remains unchanged. See docs/agent-hook.md and ADR-008 ("the changed-code
// gate is the agent gate").
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";
import { renderReport } from "./report-renderers.ts";
import { exitFor } from "./scoring.ts";
import type { AnalysisOptions, ChangedScopeMode } from "./types.ts";
import { analyseProject, gitAvailable, REPO_ROOT, writeFixtureFiles } from "./test-fixtures.ts";

// Region-scoping regression: one exported interface and two functions, each carrying findings on
// different symbols, so a changed-region selection keeps exactly one symbol's findings (widened from
// an interior line) and suppresses the rest. The layout is load-bearing for the ranges below -
// `PaymentRequest` spans lines 1-4, `chargeCard`'s signature anchors its block, and `settleBatch`'s
// eval sink sits on line 11. This fixture covers the symbol-widening and hunk-no-widening cases.
const REGION_FIXTURE = `export interface PaymentRequest {
  amount: number;
  currency: string;
}

function chargeCard(unusedToken: string): void {
  doWork();
}

function settleBatch(amount: string): unknown {
  return eval(amount);
}
`;

// Fixture purpose: two functions that each contain an eval sink, so a generated baseline captures both
// and the test can prove `--no-baseline` re-surfaces only the in-region sink. The stale sink sits on
// STALE_EVAL_LINE and the changed sink on CHANGED_EVAL_LINE.
const DUAL_EVAL_FIXTURE = `export function stale(userInput: string): unknown {
  return eval(userInput);
}

export function changed(value: string): unknown {
  return eval(value);
}
`;

const SYMBOL_SCOPE_CLI_FIXTURES = [
  {
    file: "plain.ts",
    changedLine: 4,
    findingLine: 5,
    source: `// File overview: plain CLI symbol-scope fixture.
const script = "reviewed";
export function plain(value: string): void {
  const touched = value;
  eval(script);
}
`,
  },
  {
    file: "generic.ts",
    changedLine: 6,
    findingLine: 7,
    source: `// File overview: generic CLI symbol-scope fixture.
const script = "reviewed";
export function generic<T extends string>(
  value: T,
): void {
  const touched = value;
  eval(script);
}
export function sibling(): void {
  eval(script);
}
`,
  },
] as const;

// Eval-call findings carry no symbol, so the dual-eval tests distinguish the two sinks by line.
const STALE_EVAL_LINE = 2;
const CHANGED_EVAL_LINE = 6;

// The hook's read surface over the rendered JSON: the canonical `file` alias (not the deprecated
// `filePath`), the severity vocabulary, and the line used to confirm scoping.
interface MachineFinding {
  ruleId: string;
  file: string;
  line?: number;
  severity: string;
}

// Machine v3 read surface for changed-region CLI assertions.
// Invariant: `diff.filteredFindings` and `summary.suppressedFindings` describe the same partition.
interface MachineAnalysisReport {
  schemaVersion: "gruff.analysis.v3";
  findings: MachineFinding[];
  summary: { suppressedFindings?: number };
  diff?: { enabled: true; filteredFindings: number; mode: "changed-regions" };
}

// Full-project scan of the region fixture with no changed-region scope, used as the invariant baseline.
function fullRegion(): AnalysisReport {
  return analyseProject({ "region.ts": REGION_FIXTURE }, { paths: ["region.ts"] });
}

// Runs one changed-region selection over the region fixture and returns the stable AnalysisReport
// contract for the requested range and scope mode.
function scopeRegion(range: string, scope: ChangedScopeMode): AnalysisReport {
  return analyseProject({ "region.ts": REGION_FIXTURE }, { paths: ["region.ts"], changedRanges: range, changedScope: scope });
}

// Checks the hook's count invariant by comparing the kept and suppressed totals in scoped with the total in the full scan report.
// Returns nothing. It checks count equality before requiring positive suppression. A missing suppressedCount is treated as zero.
function assertExhaustivePartition(scoped: AnalysisReport, full: AnalysisReport): void {
  const suppressed = scoped.suppressedCount ?? 0;
  assert.equal(scoped.findings.length + suppressed, full.findings.length);
  assert.equal(suppressed > 0, true);
}

// Base analyse options for the dual-eval baseline fixture: JSON, no config, symbol scope, baseline
// skipped by default. Tests override the target paths, changed-region selection or baseline settings as needed.
function regionScanOptions(): AnalysisOptions {
  return {
    paths: ["dual.ts"],
    shouldSkipConfig: true,
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedScope: "symbol",
    shouldSkipBaseline: true,
  };
}

test("symbol scope widens an interior interface edit to its declaration-anchored finding", () => {
  const full = fullRegion();
  const scoped = scopeRegion("2-2", "symbol");

  // Editing an interior field (line 2) keeps the interface's missing-doc finding anchored at line 1.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc" && finding.symbol === "PaymentRequest"), true);
  // A finding on a different symbol (the eval sink in settleBatch) is out of region and suppressed.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
  assertExhaustivePartition(scoped, full);
});

test("symbol scope widens an interior function-body edit to its signature finding", () => {
  const full = fullRegion();
  const scoped = scopeRegion("7-7", "symbol");

  // Editing the body (line 7) keeps the missing-doc finding anchored on chargeCard's signature.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "docs.missing-internal-function-doc" && finding.symbol === "chargeCard"), true);
  // Other symbols' findings stay suppressed.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc"), false);
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
  assertExhaustivePartition(scoped, full);
});

test("hunk scope does not widen an interior edit to its enclosing declaration", () => {
  const full = fullRegion();
  const scoped = scopeRegion("2-2", "hunk");

  // Hunk scope keeps only findings on the changed lines; the interface's declaration-anchored
  // finding is not widened in.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc"), false);
  assertExhaustivePartition(scoped, full);
});

test("file scope keeps every finding from a touched file", () => {
  const full = fullRegion();
  const scoped = scopeRegion("7-7", "file");

  assert.deepEqual(scoped.findings.map((finding) => finding.fingerprint).sort(), full.findings.map((finding) => finding.fingerprint).sort());
  assert.equal(scoped.suppressedCount, 0);
});

test("suppressedCount accounts for every full-scan finding across symbol selections", () => {
  const full = fullRegion();
  const keptCounts = new Set(
    ["2-2", "7-7", "11-11"].map((range) => {
      const scoped = scopeRegion(range, "symbol");
      assertExhaustivePartition(scoped, full);
      return scoped.findings.length;
    }),
  );

  // Different symbols keep different finding sets, proving real scoping rather than a constant filter.
  assert.equal(keptCounts.size > 1, true);
});

test("--no-baseline re-surfaces a baselined finding inside the changed region", () => {
  const projectDir = mkdtempSync(join(tmpdir(), "gruff-ts-nobaseline-"));
  const previous = cwd();
  try {
    writeFixtureFiles(projectDir, { "dual.ts": DUAL_EVAL_FIXTURE });
    chdir(projectDir);
    const baselinePath = join(projectDir, "gruff-baseline.json");

    // Capture every current finding into the baseline with no region scope.
    analyse({ ...regionScanOptions(), generateBaseline: baselinePath });

    // Baseline applied (no --no-baseline): the in-region eval is suppressed before region filtering runs.
    const baselined = analyse({ ...regionScanOptions(), shouldSkipBaseline: false, baseline: baselinePath, changedRanges: "6-6" });
    assert.equal(baselined.findings.some((finding) => finding.ruleId === "security.eval-call"), false);

    // --no-baseline skips the baseline, so the changed-region eval re-surfaces while the out-of-region
    // sink stays suppressed by the region filter.
    const noBaseline = analyse({ ...regionScanOptions(), changedRanges: "6-6" });
    assert.equal(noBaseline.findings.some((finding) => finding.ruleId === "security.eval-call" && finding.line === CHANGED_EVAL_LINE), true);
    assert.equal(noBaseline.findings.some((finding) => finding.ruleId === "security.eval-call" && finding.line === STALE_EVAL_LINE), false);
    assert.equal((noBaseline.suppressedCount ?? 0) > 0, true);
  } finally {
    chdir(previous);
    rmSync(projectDir, { recursive: true, force: true });
  }
});

test("delegated CLI invocation emits canonical v3 changed-region fields and finding vocabulary", () => {
  const projectDir = mkdtempSync(join(tmpdir(), "gruff-ts-hook-"));
  try {
    writeFixtureFiles(projectDir, { "dual.ts": DUAL_EVAL_FIXTURE });

    // Mirrors the exact delegated invocation the agent hook sends. The fixed bash + REPO_ROOT vector
    // keeps the executable path static so the process-exec rule stays focused on dynamic commands.
    const output = execFileSync(
      "bash",
      [join(REPO_ROOT, "bin/gruff-ts"), "analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "--changed-ranges", "6-6", "--changed-scope", "symbol", "dual.ts"],
      { cwd: projectDir, encoding: "utf8" },
    );
    const payload = JSON.parse(output) as MachineAnalysisReport;

    // Both changed-region counters are present, positive, and equal.
    assert.equal(payload.schemaVersion, "gruff.analysis.v3");
    assert.equal(typeof payload.diff?.filteredFindings, "number");
    assert.equal((payload.diff?.filteredFindings ?? 0) > 0, true);
    assert.equal(payload.summary.suppressedFindings, payload.diff?.filteredFindings);

    // Only the in-region eval (changed, line 6) survives; the out-of-region eval (stale) is excluded.
    const evalLines = payload.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.line);
    assert.deepEqual(evalLines, [CHANGED_EVAL_LINE]);

    // Every finding must expose the canonical `file` alias and a severity from the hook's vocabulary.
    assert.equal(payload.findings.every((finding) => typeof finding.file === "string"), true);
    assert.equal(payload.findings.every((finding) => ["advisory", "warning", "error"].includes(finding.severity)), true);
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

test("delegated CLI symbol scope keeps eval findings in plain and generic callables", () => {
  const projectDir = mkdtempSync(join(tmpdir(), "gruff-ts-symbol-cli-"));
  try {
    writeFixtureFiles(projectDir, Object.fromEntries(SYMBOL_SCOPE_CLI_FIXTURES.map((fixture) => [fixture.file, fixture.source])));

    for (const fixture of SYMBOL_SCOPE_CLI_FIXTURES) {
      const output = execFileSync(
        "bash",
        [join(REPO_ROOT, "bin/gruff-ts"), "analyse", "--format", "json", "--fail-on", "none", "--no-baseline", "--changed-ranges", `${fixture.changedLine}-${fixture.changedLine}`, "--changed-scope", "symbol", fixture.file],
        { cwd: projectDir, encoding: "utf8" },
      );
      const payload = JSON.parse(output) as MachineAnalysisReport;
      const evalLines = payload.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.line);
      assert.deepEqual(evalLines, [fixture.findingLine]);
    }
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

// Root-versus-subdirectory parity fixtures: an unstaged eval sink appears inside a nested package.
// Git emits repo-root-relative diff paths while findings use analysis-root-relative display paths,
// so the nested run only matches once the diff is read in the analysis root's comparison space.
const PARITY_BASE_SOURCE = `// File overview: parity fixture.
export const initial = 1;
`;
const PARITY_CHANGED_SOURCE = `// File overview: parity fixture.
export const initial = 1;
export function risky(input: string): unknown {
  return eval(input);
}
`;

// Builds a git repo with two packages, commits the clean state, then leaves both packages with the
// same unstaged eval-introducing edit so diff scoping has real hunks on both subtrees.
// Returns nothing. It writes fixture files to the scratch directory repoDir and spawns git subprocesses there.
function initParityRepo(repoDir: string): void {
  execFileSync("git", ["init", "-q"], { cwd: repoDir });
  execFileSync("git", ["config", "user.email", "gruff-test@example.com"], { cwd: repoDir });
  execFileSync("git", ["config", "user.name", "gruff-test"], { cwd: repoDir });
  writeFixtureFiles(repoDir, { "packages/app/src/index.ts": PARITY_BASE_SOURCE, "packages/sibling/src/index.ts": PARITY_BASE_SOURCE });
  execFileSync("git", ["add", "."], { cwd: repoDir });
  execFileSync("git", ["commit", "-qm", "init", "--no-gpg-sign"], { cwd: repoDir });
  writeFixtureFiles(repoDir, { "packages/app/src/index.ts": PARITY_CHANGED_SOURCE, "packages/sibling/src/index.ts": PARITY_CHANGED_SOURCE });
}

test("diff-scoped analysis reports the same findings from repo root and a nested package directory", { skip: !gitAvailable() }, () => {
  const repoDir = mkdtempSync(join(tmpdir(), "gruff-ts-parity-"));
  const previous = cwd();
  try {
    initParityRepo(repoDir);

    chdir(repoDir);
    const fromRoot = analyse({ ...regionScanOptions(), paths: ["packages/app"], diff: "unstaged" });
    const rootEvals = fromRoot.findings.filter((finding) => finding.ruleId === "security.eval-call");

    chdir(join(repoDir, "packages", "app"));
    const fromSubdir = analyse({ ...regionScanOptions(), paths: ["."], diff: "unstaged" });
    const subdirEvals = fromSubdir.findings.filter((finding) => finding.ruleId === "security.eval-call");

    // The root run anchors the regression: the changed eval is a changed-region finding there.
    assert.equal(rootEvals.length, 1);
    assert.equal(rootEvals[0]?.filePath, "packages/app/src/index.ts");

    // Parity: the nested run keeps the same finding, expressed in its own root's display path.
    assert.equal(subdirEvals.length, 1);
    assert.equal(subdirEvals[0]?.filePath, "src/index.ts");
    assert.equal(subdirEvals[0]?.line, rootEvals[0]?.line);

    // The sibling package changed too; nothing from it may leak into the nested run's findings.
    assert.equal(fromSubdir.findings.every((finding) => !finding.filePath.includes("sibling")), true);
  } finally {
    chdir(previous);
    rmSync(repoDir, { recursive: true, force: true });
  }
});

test("diff-scoped diagnostics are file-scoped: unchanged broken context never blocks a clean diff", { skip: !gitAvailable() }, () => {
  const repoDir = mkdtempSync(join(tmpdir(), "gruff-ts-diagnostics-"));
  const previous = cwd();
  try {
    execFileSync("git", ["init", "-q"], { cwd: repoDir });
    execFileSync("git", ["config", "user.email", "gruff-test@example.com"], { cwd: repoDir });
    execFileSync("git", ["config", "user.name", "gruff-test"], { cwd: repoDir });
    writeFixtureFiles(repoDir, {
      "broken.ts": "// File overview: pre-existing broken context.\nexport const dangling = {\n",
      "clean.ts": "// File overview: clean changed file.\nexport const fine = 1;\n",
    });
    execFileSync("git", ["add", "."], { cwd: repoDir });
    execFileSync("git", ["commit", "-qm", "init", "--no-gpg-sign"], { cwd: repoDir });
    writeFixtureFiles(repoDir, { "clean.ts": "// File overview: clean changed file.\nexport const fine = 1;\nexport const added = 2;\n" });
    chdir(repoDir);

    // Full scans keep failing on every parse diagnostic - the scanner cannot vouch for broken files.
    const full = analyse({ ...regionScanOptions(), paths: ["."] });
    assert.equal(full.diagnostics.some((diagnostic) => diagnostic.diagnosticType === "parse-error" && diagnostic.filePath === "broken.ts"), true);
    assert.equal(exitFor(full, "none"), 2);

    // Diff scope: the broken file is unchanged context, so its diagnostic is excluded and the
    // clean diff passes - the intentional, documented loosening for diff/since runs.
    const diffed = analyse({ ...regionScanOptions(), paths: ["."], diff: "unstaged" });
    assert.equal(diffed.diagnostics.length, 0);
    assert.equal(exitFor(diffed, "none"), 0);

    // An out-of-hunk error in a CHANGED file stays: diagnostics are file-scoped, never range-scoped.
    writeFixtureFiles(repoDir, { "broken.ts": "// File overview: pre-existing broken context.\nexport const dangling = {\nexport const appended = 1;\n" });
    const changedBroken = analyse({ ...regionScanOptions(), paths: ["."], diff: "unstaged" });
    assert.equal(changedBroken.diagnostics.some((diagnostic) => diagnostic.filePath === "broken.ts"), true);
    assert.equal(exitFor(changedBroken, "none"), 2);

    // Explicit changed-ranges keep every diagnostic of each requested file, even outside the range.
    const ranged = analyse({ ...regionScanOptions(), paths: ["broken.ts"], changedRanges: "3-3" });
    assert.equal(ranged.diagnostics.some((diagnostic) => diagnostic.filePath === "broken.ts"), true);
    assert.equal(exitFor(ranged, "none"), 2);
  } finally {
    chdir(previous);
    rmSync(repoDir, { recursive: true, force: true });
  }
});

test("changed-region SARIF excludes inline-suppressed findings from unchanged files", () => {
  const files = {
    "src/unchanged.ts": "// File overview: unchanged file.\nexport function untouched(code: string): void {\n  new Function(code); // eslint-disable-line no-new-func\n}\n",
    "src/changed.ts": "// File overview: changed file.\nexport function edited(): number {\n  return 1;\n}\n",
  };
  const diffPatch = [
    "diff --git a/src/changed.ts b/src/changed.ts",
    "--- a/src/changed.ts",
    "+++ a/src/changed.ts",
    "@@ -2,1 +2,2 @@",
    " export function edited(): number {",
    "+  return 1;",
    "",
  ].join("\n");
  const report = analyseProject(files, { diff: "-", diffPatch });
  const sarif = JSON.parse(renderReport(report, "sarif")) as { runs: Array<{ results: Array<{ suppressions?: unknown[] }> }> };
  const suppressedResults = (sarif.runs[0]?.results ?? []).filter((result) => (result.suppressions?.length ?? 0) > 0);
  assert.equal(suppressedResults.length, 0);
});

// Fixture purpose: exercises a real git repo with staged and unstaged edits to verify working-tree diff line coordinates stay aligned.
// Stable contract: writes a temporary Git repository, runs git and analyse(), and removes the directory in finally.
test("working-tree diff aligns staged and unstaged line coordinates", () => {
  if (!gitAvailable()) {
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-wt-coords-"));
  const { GIT_DIR: _gitDir, GIT_WORK_TREE: _gitWorkTree, GIT_INDEX_FILE: _gitIndexFile, ...env } = process.env;
  try {
    const baseLines = ["// File overview: coordinate fixture.", ...Array.from({ length: 10 }, (_, idx) => `export const base${idx} = ${idx};`)];
    writeFixtureFiles(dir, { "app.ts": `${baseLines.join("\n")}\n` });
    execFileSync("git", ["init"], { cwd: dir, env, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: dir, env, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Fixture"], { cwd: dir, env, stdio: "ignore" });
    execFileSync("git", ["add", "app.ts"], { cwd: dir, env, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "base"], { cwd: dir, env, stdio: "ignore" });

    // Stage an eval at line 12, then prepend 3 unstaged lines above it so eval now lives at line 15 in the working tree.
    const stagedLines = [...baseLines, "export function bad(input: string): void { eval(input); }"];
    writeFixtureFiles(dir, { "app.ts": `${stagedLines.join("\n")}\n` });
    execFileSync("git", ["add", "app.ts"], { cwd: dir, env, stdio: "ignore" });
    const unstagedLines = [baseLines[0] ?? "", "export const shift1 = 1;", "export const shift2 = 2;", "export const shift3 = 3;", ...stagedLines.slice(1)];
    writeFixtureFiles(dir, { "app.ts": `${unstagedLines.join("\n")}\n` });

    const report = analyse({
      paths: [join(dir, "app.ts")],
      shouldSkipConfig: true,
      shouldSkipBaseline: true,
      format: "json",
      failOn: "none",
      shouldIncludeIgnored: false,
      changedScope: "hunk",
      diff: "working-tree",
    });
    const evalFinding = report.findings.find((finding) => finding.ruleId === "security.eval-call");
    assert.equal(evalFinding?.line, 15);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
