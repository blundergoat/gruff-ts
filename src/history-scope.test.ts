// History-scope CLI tests protect the trend file shown to users and dashboard reviewers.
// They spawn real analyse and summary commands because rejection must precede output and writes.
// Full-scan controls prove valid history still appends while filtered requests fail closed.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gitAvailable, REPO_ROOT } from "./test-fixtures.ts";

const GRUFF_BINARY = join(REPO_ROOT, "bin/gruff-ts");
const EXPECTED_USAGE_ERROR_EXIT_CODE = 2;
const EXISTING_HISTORY = JSON.stringify([{ recordedAt: "2026-07-12T00:00:00.000Z", findings: 3, score: 91 }], null, 2);
const FILTERED_HISTORY_CASES = [
  { fileName: "analyse-diff.json", args: ["analyse", "clean.ts", "--diff=working-tree"] },
  { fileName: "analyse-since.json", args: ["analyse", "clean.ts", "--since=HEAD"] },
  { fileName: "analyse-ranges.json", args: ["analyse", "clean.ts", "--changed-ranges=1-1"] },
  { fileName: "summary-diff.json", args: ["summary", "clean.ts", "--diff=working-tree"] },
] as const;

/**
 * Gives one test a committed temporary project matching a user's normal CLI working directory.
 * Stable contract: filesystem writes and git subprocesses stay inside the root removed afterward.
 */
function withHistoryProject(run: (projectRoot: string) => void): void {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-history-scope-"));
  try {
    writeFileSync(join(projectRoot, "clean.ts"), "// File overview: history fixture.\nexport const healthy = 1;\n");
    execFileSync("git", ["init"], { cwd: projectRoot, stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: projectRoot, stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Fixture"], { cwd: projectRoot, stdio: "ignore" });
    execFileSync("git", ["add", "."], { cwd: projectRoot, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "history fixture"], { cwd: projectRoot, stdio: "ignore" });
    run(projectRoot);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
}

// Fixture purpose: every filtered history combination must fail before a report or file mutation.
// Stable contract: spawns filtered commands and keeps existing trend rows byte-identical.
test("filtered history requests exit 2 without output or history writes", () => {
  // Git-backed diff cases cannot run when the host test environment has no git executable.
  if (!gitAvailable()) {
    return;
  }
  withHistoryProject((projectRoot) => {
    // Each command gets its own existing history file so one failure cannot hide another mutation.
    FILTERED_HISTORY_CASES.forEach(({ fileName, args }) => {
      const historyPath = join(projectRoot, fileName);
      writeFileSync(historyPath, EXISTING_HISTORY);
      const result = spawnSync(
        "bash",
        [GRUFF_BINARY, ...args, "--format=json", "--history-file", historyPath, "--fail-on=none", "--no-config", "--no-baseline"],
        { cwd: projectRoot, encoding: "utf8" },
      );

      assert.equal(result.status, EXPECTED_USAGE_ERROR_EXIT_CODE, fileName);
      assert.equal(result.stdout, "", fileName);
      assert.match(result.stderr, /history.*full scan/i, fileName);
      assert.equal(readFileSync(historyPath, "utf8"), EXISTING_HISTORY, fileName);
    });
  });
});

// Fixture purpose: valid full scans protect the existing history feature on both user commands.
// Stable contract: spawns both full scans and verifies each filesystem append.
test("full analyse and summary scans still append history", () => {
  withHistoryProject((projectRoot) => {
    const historyPath = join(projectRoot, "full-scan-history.json");
    // Both user commands share the same valid trend series and must append independently.
    ["analyse", "summary"].forEach((commandName) => {
      const result = spawnSync(
        "bash",
        [GRUFF_BINARY, commandName, "clean.ts", "--format=json", "--history-file", historyPath, "--fail-on=none", "--no-config", "--no-baseline"],
        { cwd: projectRoot, encoding: "utf8" },
      );
      assert.equal(result.status, 0, commandName);
      assert.notEqual(result.stdout, "", commandName);
      assert.equal(result.stderr, "", commandName);
    });
    const historyRows = JSON.parse(readFileSync(historyPath, "utf8")) as unknown[];
    assert.equal(historyRows.length, 2);
  });
});

// Fixture purpose: command help tells users the constraint before they attempt a filtered scan.
// Stable contract: spawns both help commands and verifies their user guidance.
test("analyse and summary history help states the full-scan-only contract", () => {
  const analyseHelp = execFileSync("bash", [GRUFF_BINARY, "analyse", "--help"], { encoding: "utf8" });
  const summaryHelp = execFileSync("bash", [GRUFF_BINARY, "summary", "--help"], { encoding: "utf8" });
  assert.match(analyseHelp.replace(/\s+/g, " "), /full scans only; incompatible with --diff, --since, and --changed-ranges/i);
  assert.match(summaryHelp.replace(/\s+/g, " "), /full scans only; incompatible with --diff/i);
});
