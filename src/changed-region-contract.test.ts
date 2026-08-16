// Hook-contract regression for the native changed-region trio (`--changed-ranges`, `--changed-scope`,
// `--no-baseline`). Guards the exact JSON surface the downstream agent hook reads when it delegates
// scoping to gruff-ts: in-region findings only, the canonical `file` alias on every finding, the
// `advisory|warning|error` severity vocabulary, and the top-level `suppressedCount` whose arithmetic
// invariant (kept + suppressedCount == full-scan total) lets the hook report the backlog it did not
// show. The hook trusts this scoping and does not re-filter by line. See docs/agent-hook.md and
// ADR-008 ("the changed-code gate is the agent gate").
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";
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
interface HookFinding {
  ruleId: string;
  file: string;
  line?: number;
  severity: string;
}

// Top-level shape the hook parses: the findings array plus the `suppressedCount` it reads first.
interface HookReport {
  findings: HookFinding[];
  suppressedCount?: number;
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

// Asserts the changed-region partition the hook depends on: kept findings plus suppressedCount equal
// the full-scan total, so the reported backlog never drops or double-counts a finding, and proves the
// selection suppressed something. This is the stable invariant the changed-region contract must keep.
function assertExhaustivePartition(scoped: AnalysisReport, full: AnalysisReport): void {
  const suppressed = scoped.suppressedCount ?? 0;
  assert.equal(scoped.findings.length + suppressed, full.findings.length);
  assert.equal(suppressed > 0, true);
}

// Base analyse options for the dual-eval baseline fixture: JSON, no config, symbol scope, baseline
// skipped by default so each test layers only the baseline fields it is exercising.
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

  // Editing the body (line 7) keeps the unused-parameter finding anchored on chargeCard's signature.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "waste.unused-parameter" && finding.symbol === "chargeCard"), true);
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

test("delegated CLI invocation emits the file alias, severity vocabulary, and top-level suppressedCount", () => {
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
    const payload = JSON.parse(output) as HookReport;

    // Top-level suppressedCount is the field the hook reads first; it must be a present, positive number.
    assert.equal(typeof payload.suppressedCount, "number");
    assert.equal((payload.suppressedCount ?? 0) > 0, true);

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
      const payload = JSON.parse(output) as HookReport;
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
// Writes fixture files to the temp filesystem and spawns git subprocesses against that repo.
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
