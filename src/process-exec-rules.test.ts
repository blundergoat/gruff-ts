// Focused process-exec false-positive coverage for safe wrappers and fixed test harnesses.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

test("process exec exempts safe wrappers and fixed test harness invocations", () => {
  const report = analyseProject({
    "src/cli/server/safe-exec.ts": `import { spawn } from "node:child_process";

export function execSafely(opts: { command: string; args: string[]; cwd: string }): void {
  if (!["git", "npm"].includes(opts.command)) throw new Error("command-not-in-allow-list");
  spawn(opts.command, opts.args, { cwd: opts.cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] });
}
`,
    "src/detect.ts": `import { execFileSync } from "node:child_process";

function detect(agent: { terminalBinary: string }): void {
  const whichCmd = process.platform === "win32" ? "where" : "which";
  execFileSync(whichCmd, [agent.terminalBinary], { timeout: 3000 });
  execFileSync(agent.terminalBinary, ["--version"], { timeout: 3000 });
}
`,
    "test/unit/cli-harness.test.ts": `import { execSync, spawnSync } from "node:child_process";

function runHarness(full: string, userCommand: string): void {
  spawnSync(process.execPath, ["./bin/gruff-ts", "--version"], { timeout: 1000 });
  execSync(\`bash -n "\${full}"\`, { timeout: 1000 });
  execSync("node scripts/check-instruction-parity.mjs", { timeout: 1000 });
  execSync(userCommand);
}
`,
  });

  const processExecFindings = report.findings.filter((finding) => finding.ruleId === "security.process-exec");
  assert.deepEqual(processExecFindings.map((finding) => `${finding.filePath}:${finding.line}`), ["test/unit/cli-harness.test.ts:7"]);
});
