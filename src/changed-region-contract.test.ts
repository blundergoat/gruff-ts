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
import type { AnalysisOptions, ChangedScopeMode } from "./types.ts";
import { analyseProject, REPO_ROOT, writeFixtureFiles } from "./test-fixtures.ts";

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

  // Hunk scope keeps only findings on the changed lines (plus file-wide anchors); the interface's
  // declaration-anchored finding is not widened in.
  assert.equal(scoped.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc"), false);
  assertExhaustivePartition(scoped, full);
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
