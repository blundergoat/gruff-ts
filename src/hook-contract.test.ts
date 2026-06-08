// Conformance tests for the gruff.hook.v1 agent-hook contract.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { gitAvailable, REPO_ROOT } from "./test-fixtures.ts";

const BIN = join(REPO_ROOT, "bin/gruff-ts");
const SEVERITIES = new Set(["advisory", "warning", "error"]);
const SCOPES = new Set(["line", "symbol", "file", "project"]);
const THRESHOLD_RULE_IDS = new Set([
  "complexity.cognitive",
  "complexity.cyclomatic",
  "design.deep-relative-import",
  "design.large-module-concentration",
  "sensitive-data.hardcoded-env-value",
  "sensitive-data.high-entropy-string",
  "size.file-length",
  "size.function-length",
  "size.parameter-count",
]);
const FIXTURE_FILE_LINES = 760;
const FILE_LENGTH_THRESHOLD = 750;
const FIXTURE_EVAL_LINE = 500;

// Parsed gruff.hook.v1 payload as the conformance tests read it; mirrors the analyzer output contract.
interface HookPayload {
  contractVersion: string;
  analyzer: { name: string; version: string };
  supports?: Record<string, boolean>;
  flags?: Record<string, string>;
  flagOrder?: string;
  findings: HookFinding[];
  suppressed: { count: number };
  ignored: { paths: Array<{ path: string; source: string; pattern: string }> };
  config: { schemaOk: boolean; error: string | null };
}

// One finding entry as the tests read it from the hook contract, with the stable identity and fingerprint.
interface HookFinding {
  ruleId: string;
  severity: string;
  scope: string;
  file: string;
  line?: number;
  symbol: string | null;
  remediation: string;
  metadata: Record<string, unknown>;
  stableIdentity: string;
  fingerprint: string;
}

test("hook capabilities advertises gruff.hook.v1", () => {
  const capabilities = runHook(REPO_ROOT, ["hook", "--capabilities", "--format", "json"]);

  assert.equal(capabilities.contractVersion, "gruff.hook.v1");
  assert.deepEqual(capabilities.analyzer.name, "gruff-ts");
  assert.equal(capabilities.supports?.changedRanges, true);
  assert.equal(capabilities.supports?.diff, true);
  assert.equal(capabilities.supports?.baseline, true);
  assert.equal(capabilities.supports?.scopeField, true);
  assert.equal(capabilities.supports?.metadata, true);
  assert.equal(capabilities.supports?.stableIdentity, true);
  assert.equal(capabilities.supports?.ignoreReport, true);
  assert.equal(capabilities.supports?.newOnly, true);
  assert.deepEqual(capabilities.flags, { changedRanges: "--changed-ranges", diff: "--diff", baseline: "--baseline" });
  assert.equal(capabilities.flagOrder, "any");
});

test("hook changed-region scope omits inherited file findings but keeps changed line findings", () => {
  withProject({ "long.ts": longSource(FIXTURE_FILE_LINES, FIXTURE_EVAL_LINE) }, (dir) => {
    const full = runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]);
    const fullFileLength = requiredFinding(full, "size.file-length");
    const fullEval = requiredFinding(full, "security.eval-call");

    assert.equal(fullFileLength.scope, "file");
    assert.equal(fullFileLength.metadata.measured, FIXTURE_FILE_LINES);
    assert.equal(fullFileLength.metadata.threshold, FILE_LENGTH_THRESHOLD);
    assert.equal(fullEval.scope, "line");

    const changed = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "500-500", "long.ts"]);
    assert.equal(changed.findings.some((finding) => finding.ruleId === "size.file-length"), false);
    assert.equal(changed.findings.some((finding) => finding.ruleId === "security.eval-call"), true);
    assert.equal(changed.suppressed.count > 0, true);

    const anchorChanged = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "1-1", "long.ts"]);
    assert.equal(anchorChanged.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });
});

test("hook findings carry remediation, enum values, and threshold metadata", () => {
  withProject({ "long.ts": longSource(760, 500) }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]);

    assert.equal(payload.findings.length > 0, true);
    assert.equal(payload.findings.every((finding) => SEVERITIES.has(finding.severity)), true);
    assert.equal(payload.findings.every((finding) => SCOPES.has(finding.scope)), true);
    assert.equal(payload.findings.every((finding) => typeof finding.remediation === "string" && finding.remediation.length > 0), true);
    assert.equal(payload.findings.every((finding) => /^[0-9a-f]{16}$/.test(finding.stableIdentity)), true);
    const thresholdFindings = payload.findings.filter((finding) => THRESHOLD_RULE_IDS.has(finding.ruleId));
    assert.equal(thresholdFindings.every((finding) => typeof finding.metadata.measured === "number" && typeof finding.metadata.threshold === "number"), true);
  });
});

test("hook stableIdentity survives line shifts and measured-value changes", () => {
  withProject({ "shift.ts": evalSource(3) }, (dir) => {
    const first = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "shift.ts"]), "security.eval-call");
    writeProjectFile(dir, "shift.ts", evalSource(4));
    const shifted = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "shift.ts"]), "security.eval-call");

    assert.equal(first.stableIdentity, shifted.stableIdentity);
    assert.notEqual(first.fingerprint, shifted.fingerprint);
  });

  withProject({ "long.ts": longSource(760, 0) }, (dir) => {
    const first = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");
    writeProjectFile(dir, "long.ts", longSource(820, 0));
    const grown = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");

    assert.equal(first.stableIdentity, grown.stableIdentity);
  });
});

test("hook stableIdentity distinguishes multiple same-rule line findings in one file", () => {
  // Assembled from sub-24-char halves so this test's own source does not trip the high-entropy rule;
  // the file written into the temp project still holds the full secret literal for the scan to find.
  const firstSecret = "aB3xY7kLmN9pQ2rS5" + "tU8vW1zC4dE6fG0hJ2kQ8w";
  const secondSecret = "zX9wV3uT6sR1qP8oN5" + "mL2kJ4iH7gF0eD3cB6aZ1y";
  const twoSecrets = [
    "// File overview: hook contract fixture.",
    `export const firstSecret = "${firstSecret}";`,
    `export const secondSecret = "${secondSecret}";`,
  ].join("\n");
  withProject({ "secrets.ts": twoSecrets }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "secrets.ts"]);
    const secrets = payload.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(secrets.length, 2);
    assert.notEqual(secrets[0]?.stableIdentity, secrets[1]?.stableIdentity);
    assert.equal(typeof secrets[0]?.metadata.measured, "number");
    assert.equal(typeof secrets[0]?.metadata.threshold, "number");

    // Baseline only the first secret; the second is new and must survive new-only filtering rather
    // than collapsing onto the first secret's identity.
    writeBaseline(dir, secrets.slice(0, 1));
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "secrets.ts"]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]?.stableIdentity, secrets[1]?.stableIdentity);
  });
});

test("hook reports operational failures as in-band JSON with exit 2", () => {
  withProject({ "long.ts": longSource(760, 500) }, (dir) => {
    const result = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--baseline", "missing-baseline.json", "long.ts"], { cwd: dir, encoding: "utf8" });
    const payload = JSON.parse(result.stdout) as HookPayload;

    assert.equal(result.status, 2);
    assert.equal(payload.config.schemaOk, false);
    assert.equal(payload.findings.length, 0);
    assert.match(String(payload.config.error), /baseline|ENOENT|no such file/i);
  });
});

test("hook baseline new-only uses stableIdentity for file-scope findings", () => {
  withProject({ "long.ts": longSource(760, 0) }, (dir) => {
    const first = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");
    writeBaseline(dir, [first]);
    writeProjectFile(dir, "long.ts", longSource(820, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(740, 0) }, (dir) => {
    writeBaseline(dir, []);
    writeProjectFile(dir, "long.ts", longSource(760, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

test("hook diff new-only uses stableIdentity for file-scope findings", () => {
  if (!gitAvailable()) {
    return;
  }
  withProject({ "long.ts": longSource(760, 0) }, (dir) => {
    initGitCommit(dir);
    writeProjectFile(dir, "long.ts", longSource(820, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "working-tree", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(740, 0) }, (dir) => {
    initGitCommit(dir);
    writeProjectFile(dir, "long.ts", longSource(760, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "working-tree", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

test("hook unstaged new-only compares against the index", () => {
  if (!gitAvailable()) {
    return;
  }
  withProject({ "long.ts": longSource(760, 0) }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "long.ts", longSource(820, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(740, 0) }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "long.ts", longSource(760, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

test("hook does not double-count a re-emitted file finding as suppressed", () => {
  withProject({ "long.ts": longSource(760, 0) }, (dir) => {
    writeBaseline(dir, []);
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "--changed-ranges", "1-1", "long.ts"]);

    assert.equal(payload.findings.some((finding) => finding.ruleId === "size.file-length"), true);
    assert.equal(payload.suppressed.count, 0);
  });
});

test("hook flags parse before and after paths", () => {
  withProject({ "long.ts": longSource(760, 500) }, (dir) => {
    const before = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "500-500", "long.ts"]);
    const after = runHook(dir, ["hook", "long.ts", "--format", "json", "--no-config", "--changed-ranges", "500-500"]);

    assert.deepEqual(hookFindingKeys(after), hookFindingKeys(before));
    assert.equal(after.suppressed.count, before.suppressed.count);
  });
});

test("hook exits zero with findings", () => {
  withProject({ "long.ts": longSource(760, 500) }, (dir) => {
    const result = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "long.ts"], { cwd: dir, encoding: "utf8" });
    const payload = JSON.parse(result.stdout) as HookPayload;

    assert.equal(result.status, 0);
    assert.equal(payload.findings.length > 0, true);
  });
});

test("hook reports ignored paths and config errors in-band", () => {
  withProject({
    ".gruff-ts.yaml": "schemaVersion: gruff-ts.config.v0.1\npaths:\n  ignore:\n    - ignored.ts\n",
    "ignored.ts": "eval('ignored');\n",
  }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "ignored.ts"]);

    assert.equal(payload.findings.length, 0);
    assert.deepEqual(payload.ignored.paths, [{ path: "ignored.ts", source: "config", pattern: "ignored.ts" }]);
  });

  withProject({
    ".gruff-ts.yaml": "paths:\n  ignore: []\n",
    "bad.ts": "eval('bad');\n",
  }, (dir) => {
    const result = spawnSync("bash", [BIN, "hook", "--format", "json", "bad.ts"], { cwd: dir, encoding: "utf8" });
    const payload = JSON.parse(result.stdout) as HookPayload;

    assert.equal(result.status, 2);
    assert.equal(payload.config.schemaOk, false);
    assert.match(String(payload.config.error), /schemaVersion/);
    assert.match(String(payload.config.error), /gruff-ts init/);
  });
});

// Runs the gruff-ts hook command and parses its stdout JSON; spawns the CLI binary through bash.
function runHook(cwdPath: string, args: string[]): HookPayload {
  return JSON.parse(execFileSync("bash", [BIN, ...args], { cwd: cwdPath, encoding: "utf8" })) as HookPayload;
}

// Creates a temp project, writes the given files into it, runs the callback, then removes the dir.
function withProject(files: Record<string, string>, run: (dir: string) => void): void {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-hook-"));
  try {
    for (const [file, source] of Object.entries(files)) {
      writeProjectFile(dir, file, source);
    }
    run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Writes one fixture file under the temp project root, creating parent dirs on the filesystem.
function writeProjectFile(root: string, file: string, source: string): void {
  const path = join(root, file);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, source);
}

// Finds the first finding for a rule id or fails the test; returns the stable contract finding.
function requiredFinding(payload: HookPayload, ruleId: string): HookFinding {
  const finding = payload.findings.find((entry) => entry.ruleId === ruleId);
  assert.ok(finding, `expected ${ruleId}`);
  return finding;
}

// Writes a gruff.baseline.v1 file from the given findings, keyed by their stable identity.
function writeBaseline(root: string, findings: HookFinding[]): void {
  writeProjectFile(root, "gruff-baseline.json", JSON.stringify({
    schemaVersion: "gruff.baseline.v1",
    entries: findings.map((finding) => ({
      stableIdentity: finding.stableIdentity,
      ruleId: finding.ruleId,
      filePath: finding.file,
      line: finding.line,
      message: finding.ruleId,
    })),
  }));
}

// Initialises a git repo and stages the fixtures without committing; spawns git via execFileSync.
function initGitAdd(root: string): void {
  execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Fixture"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
}

// Initialises a git repo in the temp project and commits the fixtures; spawns git via execFileSync.
function initGitCommit(root: string): void {
  execFileSync("git", ["init"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "fixture@example.test"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Fixture"], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["add", "."], { cwd: root, stdio: "ignore" });
  execFileSync("git", ["commit", "-m", "initial"], { cwd: root, stdio: "ignore" });
}

// Builds a stable per-finding key so two hook runs can be compared deterministically.
function hookFindingKeys(payload: HookPayload): string[] {
  return payload.findings.map((finding) => `${finding.ruleId}:${finding.scope}:${finding.file}:${finding.line ?? 0}:${finding.stableIdentity}`).sort();
}

// Builds source with an eval call on the given line, padded with filler consts.
function evalSource(evalLine: number): string {
  return Array.from({ length: Math.max(1, evalLine) }, (_, index) => (index + 1 === evalLine ? "eval('shifted');" : `const filler${index} = ${index};`)).join("\n");
}

// Builds a file of the given length with a one-line overview and an optional eval call.
function longSource(lines: number, evalLine: number): string {
  return Array.from({ length: lines }, (_, index) => {
    const line = index + 1;
    if (line === 1) {
      return "// File overview: hook contract fixture.";
    }
    if (line === evalLine) {
      return "eval('hook');";
    }
    return `const filler${line} = ${line};`;
  }).join("\n");
}
