// Changed-region parsing tests cover the public option-to-scope boundary near the implementation.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { changedRegionScope } from "./changed-regions.ts";
import { gitAvailable, REPO_ROOT } from "./test-fixtures.ts";
import type { AnalysisOptions } from "./types.ts";

const BASE_OPTIONS: AnalysisOptions = {
  paths: ["src/app.ts"],
  shouldSkipConfig: true,
  format: "json",
  failOn: "none",
  shouldIncludeIgnored: false,
  changedScope: "symbol",
  shouldSkipBaseline: true,
};
const CONTEXT_DIFF_PATCH = [
  "diff --git a/src/app.ts b/src/app.ts",
  "--- a/src/app.ts",
  "+++ b/src/app.ts",
  "@@ -10,5 +10,5 @@",
  " context();",
  "-oldValue();",
  "+newValue();",
  " unchanged();",
  "",
].join("\n");
const DELETION_ONLY_DIFF_PATCH = [
  "diff --git a/src/app.ts b/src/app.ts",
  "--- a/src/app.ts",
  "+++ b/src/app.ts",
  "@@ -5,1 +5,0 @@",
  "-oldValue();",
  "",
].join("\n");

test("changedRegionScope merges explicit changed ranges", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    changedRanges: "2-4,4,8",
    changedScope: "hunk",
  });

  assert.equal(scope?.mode, "hunk");
  assert.deepEqual(scope?.explicitRanges, [{ start: 2, end: 4 }, { start: 8, end: 8 }]);
});

test("changedRegionScope parses added target lines from context diffs", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    diff: "-",
    diffPatch: CONTEXT_DIFF_PATCH,
  });

  assert.deepEqual(scope?.rangesByFile.get("src/app.ts"), [{ start: 11, end: 11 }]);
});

test("changedRegionScope skips deletion-only hunks", () => {
  const scope = changedRegionScope({
    ...BASE_OPTIONS,
    diff: "-",
    diffPatch: DELETION_ONLY_DIFF_PATCH,
  });

  assert.deepEqual(scope?.rangesByFile.get("src/app.ts"), undefined);
});

test("changedRegionScope rejects direct stdin diff calls without a patch body", () => {
  assert.throws(() => changedRegionScope({ ...BASE_OPTIONS, diff: "-" }), /requires diffPatch input/);
});

// Fixture purpose: proves --diff-base - reads a unified diff from stdin, and both --diff-base staged and
// --since staged resolve a branch named staged rather than colliding with --diff staged mode.
// Stable contract: explicit ref flags stay separate from --diff mode keywords. Spawns git and the CLI in a temp directory.
test("CLI supports --diff-base - from stdin and treats --diff-base staged and --since staged as Git refs", () => {
  if (!gitAvailable()) {
    return;
  }
  const root = mkdtempSync(join(tmpdir(), "gruff-changed-diff-base-"));
  const bin = join(REPO_ROOT, "bin/gruff-ts");
  try {
    writeFileSync(join(root, "app.ts"), "// File overview: diff-base fixture.\nexport function run(input: string): string {\n  return input;\n}\n");
    execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Fixture"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "base"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["branch", "staged"], { cwd: root, stdio: "ignore" });

    writeFileSync(join(root, "app.ts"), "// File overview: diff-base fixture.\nexport function run(input: string): unknown {\n  return eval(input);\n}\n");
    execFileSync("git", ["add", "app.ts"], { cwd: root, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "add eval"], { cwd: root, stdio: "ignore" });

    const patch = [
      "diff --git a/app.ts b/app.ts",
      "--- a/app.ts",
      "+++ b/app.ts",
      "@@ -3,1 +3,1 @@",
      "-  return input;",
      "+  return eval(input);",
      "",
    ].join("\n");
    const stdinRun = spawnSync("bash", [bin, "analyse", "app.ts", "--no-config", "--no-baseline", "--fail-on=none", "--format=json", "--diff-base", "-"], {
      cwd: root,
      input: patch,
      encoding: "utf8",
    });
    assert.equal(stdinRun.status, 0, stdinRun.stderr);
    const stdinReport = JSON.parse(stdinRun.stdout) as { findings: Array<{ ruleId: string }> };
    assert.equal(stdinReport.findings.some((finding) => finding.ruleId === "security.eval-call"), true);

    for (const refFlags of [["--diff-base", "staged"], ["--since", "staged"]]) {
      const refRun = spawnSync("bash", [bin, "analyse", "app.ts", "--no-config", "--no-baseline", "--fail-on=none", "--format=json", ...refFlags], {
        cwd: root,
        encoding: "utf8",
      });
      assert.equal(refRun.status, 0, `${refFlags.join(" ")}: ${refRun.stderr}`);
      const refReport = JSON.parse(refRun.stdout) as { findings: Array<{ ruleId: string }> };
      assert.equal(refReport.findings.some((finding) => finding.ruleId === "security.eval-call"), true, refFlags.join(" "));
    }

    const diffModeRun = spawnSync("bash", [bin, "analyse", "app.ts", "--no-config", "--no-baseline", "--fail-on=none", "--format=json", "--diff", "staged"], {
      cwd: root,
      encoding: "utf8",
    });
    assert.equal(diffModeRun.status, 0, diffModeRun.stderr);
    const diffModeReport = JSON.parse(diffModeRun.stdout) as { findings: Array<{ ruleId: string }> };
    assert.equal(diffModeReport.findings.length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
