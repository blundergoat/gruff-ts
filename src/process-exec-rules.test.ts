// Focused process-exec false-positive coverage for safe wrappers and fixed test harnesses.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject } from "./test-fixtures.ts";

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

test("process exec severity follows shell mode and command-source evidence", () => {
  // Covers the graded-severity contract: only a shell-enabled dynamic command stays a warning.
  const report = analyseProject({
    "src/probe.ts": `import { spawnSync } from "node:child_process";

const VERSION_ARGS = ["--version"] as const;

export function isExecutableBinary(binaryPath: string): boolean {
  const result = spawnSync(binaryPath, [...VERSION_ARGS], { encoding: "utf-8", shell: false });
  return result.status === 0;
}
`,
    "src/worker.ts": `import { fork } from "node:child_process";

export function startWorker(): void {
  fork("./worker.js");
}
`,
    "src/shelly.ts": `import { exec, execSync } from "node:child_process";

export function runUserCommand(command: string, dir: string): void {
  exec(command);
  execSync(\`ls \${dir}\`);
  execSync("git status");
}
`,
  });
  const findingsBySite = new Map(
    report.findings.filter((finding) => finding.ruleId === "security.process-exec").map((finding) => [`${finding.filePath}:${finding.line}`, finding]),
  );

  // The report's repro: a parameter command with the shell disabled is reviewable, not a warning.
  assert.equal(findingsBySite.get("src/probe.ts:6")?.severity, "advisory");

  // A fixed literal command with the shell disabled says what would make it dangerous.
  const forkFinding = findingsBySite.get("src/worker.ts:4");
  assert.equal(forkFinding?.severity, "advisory");
  assert.match(forkFinding?.message ?? "", /fixed command with shell disabled/);

  // Shell-enabled dynamic commands keep the warning and the review message.
  assert.equal(findingsBySite.get("src/shelly.ts:4")?.severity, "warning");
  assert.equal(findingsBySite.get("src/shelly.ts:5")?.severity, "warning");

  // A shell-enabled fixed literal sits between: advisory, keeping the review prompt.
  const gitStatusFinding = findingsBySite.get("src/shelly.ts:6");
  assert.equal(gitStatusFinding?.severity, "advisory");
  assert.match(gitStatusFinding?.message ?? "", /validate arguments are not user-controlled/);
});

test("process exec findings include dynamic argument source metadata", () => {
  const report = analyseProject({
    "src/runner.ts": `import { spawn } from "node:child_process";

function run(input: string): void {
  spawn(buildCommand(input), ["status"], { shell: false });
}
`,
  });

  const processExecFinding = report.findings.find((finding) => finding.ruleId === "security.process-exec");

  assert.equal(processExecFinding?.metadata.callName, "spawn");
  assert.equal(processExecFinding?.metadata.argumentSource, "local-builder");
  assert.equal(processExecFinding?.metadata.shellEnabled, false);
});

// Fixture purpose: a concatenated command is dynamic no matter that one half is a literal. The
// declaration scan accepted any initializer containing a quoted fragment, so `"echo " + input`
// graded as a fixed vector and a shell-enabled command-injection candidate dropped to advisory.
// Stable contract: only a wholly literal initializer counts as a fixed command vector.
test("a concatenated const command stays dynamic and keeps warning severity", () => {
  // This fixture covers the shell-enabled concatenated command that used to grade as fixed.
  const concatenatedReport = analyseFixture(`// File overview: concatenated shell command.
import { exec } from "node:child_process";

/**
 * Runs a shell command built from caller input.
 *
 * @param input - untrusted fragment appended to the command
 */
export function runEcho(input: string): void {
  const command = "echo " + input;
  exec(command);
}
`);
  const concatenated = concatenatedReport.findings.find((entry) => entry.ruleId === "security.process-exec");
  assert.notEqual(concatenated, undefined);
  assert.notEqual(concatenated?.metadata.argumentSource, "local-const");
  assert.equal(concatenated?.severity, "warning");

  // A genuinely fixed literal command must still grade as a fixed vector.
  const fixedReport = analyseFixture(`// File overview: fixed shell command.
import { exec } from "node:child_process";

/**
 * Runs one fixed shell command.
 */
export function runStatus(): void {
  const command = "git status";
  exec(command);
}
`);
  const fixed = fixedReport.findings.find((entry) => entry.ruleId === "security.process-exec");
  assert.equal(fixed?.metadata.argumentSource, "local-const");
  assert.equal(fixed?.severity, "advisory");
});
