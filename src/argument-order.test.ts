/*
 * Pins the argument-order clause FAMILY-CONTRACT.md section 7 ratifies on 2026-09-06.
 *
 * Every operand-accepting command must produce the same output and the same exit code whether its flags are written
 * before or after the path. The defect the clause exists to prevent is real and was shipped: gruff-go silently
 * discarded flags placed after a path, so `analyse . --fail-on=error` ran at the default threshold and a CI gate
 * nobody had disabled stopped gating.
 *
 * Reach for this file when adding a command that takes paths, or when changing how commander is wired.
 * Spawns the built binary once per case in a temporary project; it writes nothing outside that directory.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { REPO_ROOT } from "./test-fixtures.ts";

const BIN = join(REPO_ROOT, "bin/gruff-ts");

// The one field two runs of the same command are allowed to differ on.
const TIMESTAMP = /\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?/gu;

// Every operand-accepting command, with the flags whose placement is under test.
const ORDER_CASES = [
  { command: "analyse", flags: ["--no-config", "--fail-on", "none", "--format", "json"] },
  { command: "summary", flags: ["--no-config", "--fail-on", "none", "--format", "json"] },
  { command: "report", flags: ["--no-config", "--fail-on", "none", "--format", "json"] },
  { command: "hook", flags: ["--no-config", "--format", "json"] },
  { command: "check-ignore", flags: ["--no-config", "--format", "json"] },
] as const;

// Builds a one-file project the ordering comparison can scan, runs the callback in it, then removes it.
// Writes only inside a fresh temporary directory, which is removed again whether the callback threw or not.
function withProbeProject(run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-argument-order-"));
  try {
    writeFileSync(join(dir, "probe.ts"), "/** A probe module. */\nexport function probe(rx: number): number {\n  return rx + rx;\n}\n");
    writeFileSync(join(dir, "README.md"), "Argument-order fixture.\n");
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Runs one gruff-ts invocation in a project directory and returns what a user would see.
// Spawns the built binary; it reads the project and writes nothing outside whatever the command itself writes.
function runInProject(dir: string, args: string[]): { status: number | null; output: string } {
  const result = spawnSync("bash", [BIN, "--no-interaction", ...args], { cwd: dir, encoding: "utf8" });

  return { status: result.status, output: `${result.stdout ?? ""}${result.stderr ?? ""}`.replaceAll(TIMESTAMP, "<timestamp>") };
}

test("every operand-accepting command accepts its flags after the path", () => {
  withProbeProject((dir) => {
    for (const { command, flags } of ORDER_CASES) {
      const before = runInProject(dir, [command, ...flags, "probe.ts"]);
      const after = runInProject(dir, [command, "probe.ts", ...flags]);

      assert.equal(after.status, before.status, `${command} exits differently when its flags follow the path`);
      assert.equal(after.output, before.output, `${command} prints differently when its flags follow the path`);
    }
  });
});

test("a double dash ends flag parsing so a leading-dash operand stays a path", () => {
  withProbeProject((dir) => {
    writeFileSync(join(dir, "-dashed.ts"), "/** A dashed module. */\nexport function dashed(rx: number): number {\n  return rx + rx;\n}\n");
    const result = runInProject(dir, ["analyse", "--no-config", "--fail-on", "none", "--format", "json", "--", "-dashed.ts"]);

    assert.equal(result.status, 0, result.output);
    assert.equal(result.output.includes("-dashed.ts"), true, "the terminated operand was not scanned as a path");
  });
});

test("a flag-shaped token that is not registered is an error wherever it appears", () => {
  withProbeProject((dir) => {
    const afterPath = runInProject(dir, ["analyse", "probe.ts", "--not-a-registered-flag"]);

    // Exit 2 is the family's usage exit; treating the token as an operand would scan a file nobody named.
    assert.equal(afterPath.status, 2, afterPath.output);
  });
});

test("a command taking no operands rejects a stray one", () => {
  withProbeProject((dir) => {
    const result = runInProject(dir, ["init", "stray-operand"]);

    assert.equal(result.status, 2, result.output);
  });
});
