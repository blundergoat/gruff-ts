// Hook conformance tests cover the JSON findings and outcomes coding agents receive from `gruff-ts hook`.
//
// Fixtures protect changed-scope filtering, stable identities, baselines, and diagnostics.
// Sensitive findings must reach hook users with fixed markers and no matched text or length metadata.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse, analyseHookReports } from "./analyser.ts";
import { renderHookReport } from "./hook-contract.ts";
import { gitAvailable, REPO_ROOT } from "./test-fixtures.ts";
import type { AnalysisOptions, AnalysisReport } from "./types.ts";

const BIN = join(REPO_ROOT, "bin/gruff-ts");
const SEVERITIES = new Set(["advisory", "warning", "error"]);
const SCOPES = new Set(["line", "symbol", "file", "project"]);
const HOOK_MEASUREMENT_RULE_IDS = new Set([
  "complexity.cognitive",
  "complexity.cyclomatic",
  "design.deep-relative-import",
  "design.large-module-concentration",
  "size.file-length",
  "size.function-length",
  "size.parameter-count",
]);
const FIXTURE_FILE_LINES = 1010;
const FIXTURE_SUBSTANTIVE_LINES = FIXTURE_FILE_LINES - 1;
const FILE_LENGTH_THRESHOLD = 1000;
const FIXTURE_EVAL_LINE = 500;
const GENERIC_SYMBOL_HOOK_SOURCE = `// File overview: generic hook symbol-scope fixture.
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
`;

// Parsed gruff.hook.v2 payload as the conformance tests read it; mirrors the analyzer output contract.
interface HookPayload {
  contractVersion: string;
  analyzer: { name: string; version: string };
  run?: { mode: string; scope: string; paths: string[]; analysedFiles: number; baseline: { applied: boolean; schemaVersion: string | null; path: string | null } };
  supports?: Record<string, boolean>;
  flags?: Record<string, string>;
  flagOrder?: string;
  findings: HookFinding[];
  diagnostics?: Array<{ type: string; severity: string; message: string; file?: string; line?: number; invalidatesRun?: false }>;
  suppressed: { count: number };
  suppressions?: Array<{ rule: string; path: string; symbol?: string; reason: string; suppressed: number }>;
  ignored: { paths: Array<{ path: string; source: string; pattern: string }> };
  config: { schemaOk: boolean; error: { message: string; remediation: string } | null };
}

// One finding entry as the tests read it from the hook contract, with the ratified identity and the port-local fingerprint.
interface HookFinding {
  ruleId: string;
  severity: string;
  confidence: string;
  scope: string;
  file: string;
  line?: number;
  endLine?: number;
  column?: number;
  symbol: string | null;
  symbolOrdinal: number;
  message: string;
  remediation: string;
  metadata: Record<string, unknown>;
  // Null for a sensitive finding, which the identity contract never names.
  stableIdentity: string | null;
  baselineStatus: string | null;
  fingerprint: string;
}

test("hook capabilities advertises gruff.hook.v2", () => {
  const capabilities = runHook(REPO_ROOT, ["hook", "--capabilities", "--format", "json"]);

  assert.equal(capabilities.contractVersion, "gruff.hook.v2");
  assert.deepEqual(capabilities.analyzer.name, "gruff-ts");
  // The twelve family capabilities, each true only because the behaviour behind it exists here.
  assert.deepEqual(Object.keys(capabilities.supports ?? {}).sort(), [
    "baseline", "baselineV3", "changedRanges", "confidenceGate", "deepScanBudget",
    "diagnostics", "diff", "ignoreReport", "metadata", "newOnly", "scopeField", "stableIdentity",
  ]);
  assert.equal(Object.values(capabilities.supports ?? {}).every((supported) => supported === true), true);
  assert.deepEqual(capabilities.flags, {
    baseline: "--baseline",
    changedRanges: "--changed-ranges",
    deepScanBudget: "--deep-scan-budget",
    diff: "--diff",
    failOnDiagnostics: "--fail-on-diagnostics",
    minConfidence: "--min-confidence",
  });
  assert.equal(capabilities.flagOrder, "any");
});

test("hook reports diagnostics in-band with exit 0 and honors --fail-on-diagnostics", () => {
  // A lone unterminated brace is a real parse diagnostic; the default hook contract still exits 0
  // and surfaces it in the diagnostics field, so non-opting consumers keep old semantics. Only the explicit
  // --fail-on-diagnostics request turns it into a blocked edit, which section 6 makes exit 1 rather than 2.
  withProject({ "broken.ts": "// File overview: diagnostics fixture.\nexport const dangling = {\n" }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "broken.ts"]);
    assert.equal(payload.diagnostics?.length, 1);
    assert.equal(payload.diagnostics?.[0]?.type, "parse-error");
    assert.equal(payload.diagnostics?.[0]?.file, "broken.ts");
    assert.equal(typeof payload.diagnostics?.[0]?.message, "string");

    // The explicit consumer request flips the same run to exit 1 while keeping identical JSON.
    const requested = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--fail-on-diagnostics", "broken.ts"], { cwd: dir, encoding: "utf8" });
    assert.equal(requested.status, 1);
    const requestedPayload = JSON.parse(requested.stdout) as HookPayload;
    assert.equal(requestedPayload.diagnostics?.length, 1);
  });

  // No relevant diagnostics: the flag must not change the exit code of a clean run.
  withProject({ "clean.ts": "// File overview: diagnostics fixture.\nexport const fine = 1;\n" }, (dir) => {
    const clean = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--fail-on-diagnostics", "clean.ts"], { cwd: dir, encoding: "utf8" });
    assert.equal(clean.status, 0);
    const cleanPayload = JSON.parse(clean.stdout) as HookPayload;
    assert.equal(cleanPayload.diagnostics?.length, 0);
  });
});

test("hook changed-region scope omits inherited file findings but keeps changed line findings", () => {
  withProject({ "long.ts": longSource(FIXTURE_FILE_LINES, FIXTURE_EVAL_LINE) }, (dir) => {
    const full = runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]);
    const fullFileLength = requiredFinding(full, "size.file-length");
    const fullEval = requiredFinding(full, "security.eval-call");

    assert.equal(fullFileLength.scope, "file");
    assert.equal(fullFileLength.metadata.measured, FIXTURE_SUBSTANTIVE_LINES);
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

test("hook symbol scope keeps eval findings inside generic multi-line callables", () => {
  withProject({ "generic.ts": GENERIC_SYMBOL_HOOK_SOURCE }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "6-6", "generic.ts"]);

    assert.equal(payload.contractVersion, "gruff.hook.v2");
    assert.deepEqual(Object.keys(payload).sort(), ["analyzer", "config", "contractVersion", "diagnostics", "findings", "ignored", "run", "suppressed", "suppressions"]);
    // The audit block says what ran, so a consumer can tell a targeted run from one that analysed nothing.
    assert.equal(payload.run?.mode, "changed-ranges");
    assert.equal(payload.run?.scope, "symbol");
    assert.equal(payload.run?.analysedFiles, 1);
    assert.deepEqual(payload.run?.baseline, { applied: false, schemaVersion: null, path: null });
    assert.deepEqual(payload.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.line), [7]);
  });
});

test("hook projects bounded deep-scan diagnostics without making them fatal", () => {
  const filler = Array.from({ length: 20_001 }, (_, index) => `export const filler${index} = ${index};`).join("\n");
  withProject({ "huge.ts": `${filler}\neval("payload");\n` }, (dir) => {
    const full = runHook(dir, ["hook", "--format", "json", "--no-config", "huge.ts"]);
    assert.equal("notes" in full, false);
    assert.deepEqual(full.diagnostics?.map((diagnostic) => ({ type: diagnostic.type, severity: diagnostic.severity, file: diagnostic.file, invalidatesRun: diagnostic.invalidatesRun })), [
      { type: "bounded-deep-scan", severity: "warning", file: "huge.ts", invalidatesRun: false },
    ]);
    assert.equal(full.findings.some((finding) => finding.ruleId === "size.file-length"), true);
    assert.equal(full.findings.some((finding) => finding.ruleId === "security.eval-call"), false);

    const changed = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "1-1", "huge.ts"]);
    assert.equal("notes" in changed, false);
    assert.equal(changed.diagnostics?.[0]?.type, "bounded-deep-scan");
    assert.equal(changed.findings.some((finding) => finding.ruleId === "size.file-length"), false);
    assert.equal(changed.suppressed.count, 1);
  });
});

test("hook render reuses one analysis for changed-region views", () => {
  withProject({ "long.ts": longSource(FIXTURE_FILE_LINES, FIXTURE_EVAL_LINE) }, (dir) => {
    withCwd(dir, () => {
      const noRegion = hookRenderInput(baseHookOptions(["long.ts"]), baseHookOptions(["long.ts"]), false);
      assertHookRenderCalls(noRegion, 1);

      const changedScoped = baseHookOptions(["long.ts"], { changedRanges: "500-500" });
      assertHookRenderCalls(hookRenderInput(currentHookOptions(changedScoped), changedScoped, true), 1);
    });
  });

  if (!gitAvailable()) {
    return;
  }
  withProject({ "long.ts": longSource(FIXTURE_FILE_LINES, FIXTURE_EVAL_LINE) }, (dir) => {
    withCwd(dir, () => {
      initGitCommit(dir);
      writeProjectFile(dir, "long.ts", longSource(FIXTURE_FILE_LINES + 20, FIXTURE_EVAL_LINE));

      const diffScoped = baseHookOptions(["long.ts"], { diff: "working-tree" });
      assertHookRenderCalls(hookRenderInput(currentHookOptions(diffScoped), diffScoped, true, "working-tree"), 2);

      const sinceScoped = baseHookOptions(["long.ts"], { since: "HEAD" });
      assertHookRenderCalls(hookRenderInput(currentHookOptions(sinceScoped), sinceScoped, true, "HEAD"), 2);
    });
  });
});

test("hook findings carry remediation, enum values, and threshold metadata", () => {
  withProject({ "long.ts": longSource(1010, 500) }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]);

    assert.equal(payload.findings.length > 0, true);
    assert.equal(payload.findings.every((finding) => SEVERITIES.has(finding.severity)), true);
    assert.equal(payload.findings.every((finding) => SCOPES.has(finding.scope)), true);
    assert.equal(payload.findings.every((finding) => typeof finding.remediation === "string" && finding.remediation.length > 0), true);
    assert.equal(payload.findings.every((finding) => /^[0-9a-f]{16}$/.test(String(finding.stableIdentity))), true);
    // The four fields v1 never published: without them a finding cannot be gated, located, or recomputed.
    assert.equal(payload.findings.every((finding) => ["low", "medium", "high"].includes(finding.confidence)), true);
    assert.equal(payload.findings.every((finding) => finding.endLine !== undefined && finding.endLine >= (finding.line ?? 0)), true);
    assert.equal(payload.findings.every((finding) => Number.isInteger(finding.symbolOrdinal)), true);
    // No baseline was applied, so no finding may claim a status a consumer could misread as reviewed.
    assert.equal(payload.findings.every((finding) => finding.baselineStatus === null), true);
    const thresholdFindings = payload.findings.filter((finding) => HOOK_MEASUREMENT_RULE_IDS.has(finding.ruleId));
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

  withProject({ "long.ts": longSource(1010, 0) }, (dir) => {
    const first = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");
    writeProjectFile(dir, "long.ts", longSource(1070, 0));
    const grown = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");

    assert.equal(first.stableIdentity, grown.stableIdentity);
  });
});

test("hook keeps multiple same-rule secrets in one file separately actionable and unnameable", () => {
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
    // A secret is never named, because a stored identity is what would let a review hide it.
    assert.deepEqual(secrets.map((finding) => finding.stableIdentity), [null, null]);
    // The port-local fingerprint still separates them, so a consumer can act on each one.
    assert.notEqual(secrets[0]?.fingerprint, secrets[1]?.fingerprint);
    assert.equal(secrets[0]?.metadata.measured, undefined);
    assert.equal(typeof secrets[0]?.metadata.threshold, "number");
    assert.equal(secrets[0]?.metadata.preview, "[redacted]");
    assert.equal("length" in (secrets[0]?.metadata ?? {}), false);

    // A baseline generated from this very run stores no secret, so both keep reporting until they are fixed.
    execFileSync("bash", [BIN, "analyse", "--generate-baseline", "gruff-baseline.json", "--fail-on", "none", "--no-config", "."], { cwd: dir, encoding: "utf8" });
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "secrets.ts"]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(remaining.length, 2);
    assert.equal(remaining.every((finding) => finding.baselineStatus === "notEligible"), true);
  });
});

test("hook keeps two same-line secrets independently classifiable", () => {
  // Sub-threshold fragments keep this fixture safe; both assembled values sit on one line.
  // The ADR-017 column discriminator is what keeps the second finding separately actionable.
  const firstSecret = "aB3xY7kLmN9pQ2rS5" + "tU8vW1zC4dE6fG0hJ2kQ8w";
  const secondSecret = "zX9wV3uT6sR1qP8oN5" + "mL2kJ4iH7gF0eD3cB6aZ1y";
  const sameLine = [
    "// File overview: hook same-line contract fixture.",
    `export const firstSecret = "${firstSecret}"; export const secondSecret = "${secondSecret}";`,
  ].join("\n");
  withProject({ "secrets.ts": sameLine }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "secrets.ts"]);
    const secrets = payload.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(secrets.length, 2);
    assert.deepEqual(secrets.map((finding) => finding.stableIdentity), [null, null]);
    // The port-local fingerprint keys on the line, so a same-line pair deliberately shares one.
    assert.equal(secrets[0]?.fingerprint, secrets[1]?.fingerprint);
    // The match column is the only thing that separates them, which is what keeps the second one actionable.
    assert.notEqual(secrets[0]?.column, secrets[1]?.column);

    // A generated baseline stores neither, so both same-line secrets keep reporting.
    execFileSync("bash", [BIN, "analyse", "--generate-baseline", "gruff-baseline.json", "--fail-on", "none", "--no-config", "."], { cwd: dir, encoding: "utf8" });
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "secrets.ts"]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(remaining.length, 2);
  });
});

// Fixture purpose: models a hook user still holding the 0.5 baseline four ports used to read.
// Stable contract: it is refused with the migration command named, never applied under rules nobody ratified.
// Writes the legacy file into a temp project and spawns the CLI there; both are removed when the fixture ends.
test("hook refuses a 0.5 baseline and names the migration command", () => {
  const previewPolicySecret = ["a1B2c3D4", "e5F6g7H8"].join("");
  withProject({ ".env": `API_TOKEN=${previewPolicySecret}\n` }, (dir) => {
    writeProjectFile(dir, "legacy-preview-baseline.json", JSON.stringify({ schemaVersion: "gruff.baseline.v1", entries: [] }));

    const result = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--baseline", "legacy-preview-baseline.json", ".env"], { cwd: dir, encoding: "utf8" });
    const payload = JSON.parse(result.stdout) as HookPayload;

    assert.equal(result.status, 2);
    assert.equal(payload.findings.length, 0);
    assert.equal(payload.diagnostics?.[0]?.severity, "fatal");
    assert.match(String(payload.diagnostics?.[0]?.message), /--migrate-baseline/);
  });
});

test("hook stableIdentity uses the canonical circular-import SCC symbol", () => {
  // The SCC has two simple cycles through `a.ts`, but M09 reports one project finding keyed by the
  // canonical sorted member list. Baselining that component should suppress the whole SCC.
  const cycleProject = {
    "src/cycle/a.ts": ['import { fromB } from "./b";', 'import { fromC } from "./c";', "export function fromA(): string {", "  return fromB() + fromC();", "}", ""].join("\n"),
    "src/cycle/b.ts": ['import { fromA } from "./a";', "export function fromB(): string {", "  return fromA();", "}", ""].join("\n"),
    "src/cycle/c.ts": ['import { fromA } from "./a";', "export function fromC(): string {", "  return fromA();", "}", ""].join("\n"),
  };
  const cyclePaths = ["src/cycle/a.ts", "src/cycle/b.ts", "src/cycle/c.ts"];
  withProject(cycleProject, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", ...cyclePaths]);
    const cycles = payload.findings.filter((finding) => finding.ruleId === "design.circular-import");
    assert.equal(cycles.length, 1);
    assert.equal(cycles[0]?.scope, "project");
    assert.equal(cycles[0]?.symbol, "src/cycle/a.ts -> src/cycle/b.ts -> src/cycle/c.ts");
    assert.deepEqual(cycles[0]?.metadata.files, ["src/cycle/a.ts", "src/cycle/b.ts", "src/cycle/c.ts"]);

    const reordered = runHook(dir, ["hook", "--format", "json", "--no-config", ...[...cyclePaths].reverse()]);
    const reorderedCycle = reordered.findings.find((finding) => finding.ruleId === "design.circular-import");
    assert.equal(reorderedCycle?.stableIdentity, cycles[0]?.stableIdentity);

    // Baselining the SCC suppresses the entire component, not an arbitrary simple-cycle variant.
    writeBaseline(dir, cycles.slice(0, 1));
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", ...cyclePaths]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "design.circular-import");
    assert.equal(remaining.length, 0);
  });
});

test("hook changed-ranges reports a circular import through the requested file", () => {
  const cycleProject = {
    "src/cycle/a.ts": ['import { fromB } from "./sub/b";', "export function fromA(): string {", "  return fromB();", "}", ""].join("\n"),
    "src/cycle/sub/b.ts": ['import { fromA } from "../a";', "export function fromB(): string {", "  return fromA();", "}", ""].join("\n"),
  };
  withProject(cycleProject, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "1-1", "src/cycle/sub/b.ts"]);
    const cycles = payload.findings.filter((finding) => finding.ruleId === "design.circular-import");
    assert.equal(cycles.length, 1);
    assert.equal(cycles[0]?.scope, "project");
    assert.equal(cycles[0]?.file, "src/cycle/a.ts");
    assert.deepEqual(cycles[0]?.metadata.files, ["src/cycle/a.ts", "src/cycle/sub/b.ts"]);
  });
});

test("hook changed-ranges keeps a circular import when the range misses the canonical anchor line", () => {
  // The agent edits line 3 of a non-anchor member while the SCC anchor import remains on line 1.
  // Attribution must therefore come from component membership rather than an accidental line overlap.
  const cycleProject = {
    "src/cycle/a.ts": ['import { fromB } from "./sub/b";', "export function fromA(): string {", "  return fromB();", "}", ""].join("\n"),
    "src/cycle/sub/b.ts": ['import { fromA } from "../a";', "export function fromB(): string {", "  return fromA();", "}", ""].join("\n"),
  };
  withProject(cycleProject, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "3-3", "src/cycle/sub/b.ts"]);
    const cycles = payload.findings.filter((finding) => finding.ruleId === "design.circular-import");
    assert.equal(cycles.length, 1);
    assert.equal(cycles[0]?.scope, "project");
    assert.equal(cycles[0]?.file, "src/cycle/a.ts");
  });
});

test("hook reports operational failures as in-band JSON with exit 2", () => {
  withProject({ "long.ts": longSource(1010, 500) }, (dir) => {
    const result = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--baseline", "missing-baseline.json", "long.ts"], { cwd: dir, encoding: "utf8" });
    const payload = JSON.parse(result.stdout) as HookPayload;

    assert.equal(result.status, 2);
    assert.equal(payload.findings.length, 0);
    // A run that could not happen says so in the diagnostics, so a consumer never reads it as a clean file.
    assert.equal(payload.diagnostics?.[0]?.type, "baseline");
    assert.equal(payload.diagnostics?.[0]?.severity, "fatal");
    assert.match(String(payload.diagnostics?.[0]?.message), /baseline|ENOENT|no such file/i);
  });
});

test("hook baseline new-only uses stableIdentity for file-scope findings", () => {
  withProject({ "long.ts": longSource(1010, 0) }, (dir) => {
    const first = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "long.ts"]), "size.file-length");
    writeBaseline(dir, [first]);
    writeProjectFile(dir, "long.ts", longSource(1070, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(990, 0) }, (dir) => {
    writeBaseline(dir, []);
    writeProjectFile(dir, "long.ts", longSource(1010, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

test("hook diff new-only uses stableIdentity for file-scope findings", () => {
  if (!gitAvailable()) {
    return;
  }
  withProject({ "long.ts": longSource(1010, 0) }, (dir) => {
    initGitCommit(dir);
    writeProjectFile(dir, "long.ts", longSource(1070, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "working-tree", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(990, 0) }, (dir) => {
    initGitCommit(dir);
    writeProjectFile(dir, "long.ts", longSource(1010, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "working-tree", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

test("hook unstaged new-only compares against the index", () => {
  if (!gitAvailable()) {
    return;
  }
  withProject({ "long.ts": longSource(1010, 0) }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "long.ts", longSource(1070, 0));

    const grown = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "long.ts"]);
    assert.equal(grown.findings.some((finding) => finding.ruleId === "size.file-length"), false);
  });

  withProject({ "long.ts": longSource(990, 0) }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "long.ts", longSource(1010, 0));

    const crossed = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "long.ts"]);
    assert.equal(crossed.findings.some((finding) => finding.ruleId === "size.file-length"), true);
  });
});

// Fixture covers the diff-base materialization contract: every SCC member must replay at the base ref.
test("hook diff new-only materializes SCC members so pre-existing cycles stay suppressed", () => {
  if (!gitAvailable()) {
    return;
  }
  const anchorSource = [
    "// Cycle fixture: module a imports b and derives a number from it.",
    "",
    'import { valueFromB } from "./b";',
    "",
    "/**",
    " * Derives the a-side value.",
    " * @returns The b-derived value plus one.",
    " */",
    "export function valueFromA(): number {",
    "  return valueFromB() + 1;",
    "}",
    "",
  ].join("\n");
  const cyclingMemberSource = [
    "// Cycle fixture: module b imports a back, closing the import cycle.",
    "",
    'import { valueFromA } from "./a";',
    "",
    "/**",
    " * Provides the seed value.",
    " * @returns A fixed seed value.",
    " */",
    "export function valueFromB(): number {",
    "  return 2;",
    "}",
    "",
    "/**",
    " * Round-trips through module a.",
    " * @returns The a-side derived value.",
    " */",
    "export function roundTrip(): number {",
    "  return valueFromA();",
    "}",
    "",
  ].join("\n");
  const harmlessAddition = [
    "/**",
    " * Reports the fixture label.",
    " * @returns The fixture label.",
    " */",
    "export function fixtureLabel(): string {",
    '  return "cycle-b";',
    "}",
    "",
  ].join("\n");

  // Pre-existing cycle: the edited member anchors no findings, so only member materialization can
  // reconstruct the SCC at the base; the cycle must not be reported as new.
  withProject({ "src/a.ts": anchorSource, "src/b.ts": cyclingMemberSource }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "src/b.ts", cyclingMemberSource + "\n" + harmlessAddition);

    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "src/b.ts"]);
    assert.equal(payload.findings.some((finding) => finding.ruleId === "design.circular-import"), false);
  });

  const cycleFreeMemberSource = [
    "// Cycle fixture: module b starts cycle-free.",
    "",
    "/**",
    " * Provides the seed value.",
    " * @returns A fixed seed value.",
    " */",
    "export function valueFromB(): number {",
    "  return 2;",
    "}",
    "",
  ].join("\n");

  // New cycle: the unstaged edit adds the cycle-closing import, so the cycle is genuinely new and
  // must still be reported.
  withProject({ "src/a.ts": anchorSource, "src/b.ts": cycleFreeMemberSource }, (dir) => {
    initGitAdd(dir);
    writeProjectFile(dir, "src/b.ts", cyclingMemberSource);

    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--diff", "unstaged", "src/b.ts"]);
    const cycles = payload.findings.filter((finding) => finding.ruleId === "design.circular-import");
    assert.equal(cycles.length, 1);
    assert.equal(cycles[0]?.scope, "project");
  });
});

test("hook does not double-count a re-emitted file finding as suppressed", () => {
  withProject({ "long.ts": longSource(1010, 0) }, (dir) => {
    writeBaseline(dir, []);
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "--changed-ranges", "1-1", "long.ts"]);

    assert.equal(payload.findings.some((finding) => finding.ruleId === "size.file-length"), true);
    assert.equal(payload.suppressed.count, 0);
  });
});

test("hook flags parse before and after paths", () => {
  withProject({ "long.ts": longSource(1010, 500) }, (dir) => {
    const before = runHook(dir, ["hook", "--format", "json", "--no-config", "--changed-ranges", "500-500", "long.ts"]);
    const after = runHook(dir, ["hook", "long.ts", "--format", "json", "--no-config", "--changed-ranges", "500-500"]);

    assert.deepEqual(hookFindingKeys(after), hookFindingKeys(before));
    assert.equal(after.suppressed.count, before.suppressed.count);
  });
});

test("hook exits zero with findings", () => {
  withProject({ "long.ts": longSource(1010, 500) }, (dir) => {
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
    // The error is an object, so a consumer reads the fix from a field rather than parsing a sentence.
    assert.match(String(payload.config.error?.message), /schemaVersion/);
    assert.match(String(payload.config.error?.remediation), /gruff-ts init/);
    assert.equal(payload.diagnostics?.[0]?.severity, "fatal");
  });
});

test("two secrets on one line reach the hook as separately trackable findings", () => {
  // Split so this test file carries no scannable key of its own; the written fixture holds both.
  const firstKey = ["AKIAJ7SVBRXYZ", "Q2KLMNP"].join("");
  const secondKey = ["AKIAQ4TWMZPLK", "D8RVNXC"].join("");
  withProject({
    "keys.ts": `const first = "${firstKey}"; const second = "${secondKey}";\n`,
  }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json"]);
    const secrets = payload.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");

    assert.equal(secrets.length, 2);
    const [first, second] = secrets;
    assert.ok(first && second);
    // Both keys use the same fixed category marker, so no matched characters or lengths distinguish them.
    assert.equal(first.message, second.message);
    // Neither is named: the identity contract refuses to name a secret, so no review can ever hide one.
    assert.deepEqual([first.stableIdentity, second.stableIdentity], [null, null]);
    // The port-local fingerprint keys on the line, so the pair deliberately shares one.
    assert.equal(first.fingerprint, second.fingerprint);
    // The column is what lets a consumer act on the second key instead of collapsing it onto the first.
    assert.notEqual(first.column, second.column);
  });
});

// Models the one baseline the hook reads: the same v3 file `analyse --generate-baseline` writes.
// A secret is counted there and stored nowhere, so a generated baseline never hides one from the agent.
// Stable contract: one review carries across analyse and hook, because both read the identical file.
test("hook reads the same generated baseline analyse writes, and it hides no secret", () => {
  const secret = "aB3xY7kLmN9pQ2rS5" + "tU8vW1zC4dE6fG0hJ2kQ8w";
  const source = ["// File overview: hook baseline-format fixture.", `export const token = "${secret}";`].join("\n");
  withProject({ "secret.ts": source }, (dir) => {
    const before = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "secret.ts"]), "sensitive-data.high-entropy-string");
    assert.equal(typeof before.column, "number");
    assert.equal(before.stableIdentity, null);
    execFileSync("bash", [BIN, "analyse", "--generate-baseline", "on-disk-baseline.json", "--fail-on", "none", "--no-config", "."], { cwd: dir, encoding: "utf8" });

    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "on-disk-baseline.json", "secret.ts"]);
    const secrets = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(secrets.length, 1);
    assert.equal(secrets[0]?.baselineStatus, "notEligible");
    assert.equal(filtered.run?.baseline.applied, true);
    assert.equal(filtered.run?.baseline.schemaVersion, "gruff.baseline.v3");
  });
});

// Runs the gruff-ts hook command and parses its stdout JSON; spawns the CLI binary through bash.
function runHook(cwdPath: string, args: string[]): HookPayload {
  return JSON.parse(execFileSync("bash", [BIN, ...args], { cwd: cwdPath, encoding: "utf8" })) as HookPayload;
}

// Runs a callback from a temp project root and restores the process cwd afterward.
function withCwd(path: string, run: () => void): void {
  const previous = cwd();
  try {
    chdir(path);
    run();
  } finally {
    chdir(previous);
  }
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

type HookRenderInput = Parameters<typeof renderHookReport>[1];

type CountingHookRunner = ((options: AnalysisOptions) => AnalysisReport) & {
  hookViews?: (currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean) => {
    currentReport: AnalysisReport;
    scopedReport: AnalysisReport;
  };
};

// Base hook analysis options matching cli-program's hook defaults for direct render tests.
function baseHookOptions(paths: string[], selectors: Partial<Pick<AnalysisOptions, "changedRanges" | "diff" | "since">> = {}): AnalysisOptions {
  return {
    paths,
    shouldSkipConfig: true,
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedScope: "symbol",
    shouldSkipBaseline: true,
    ...selectors,
  };
}

// Removes changed-region selectors so expected current-report calls always analyse the full file set.
function currentHookOptions(options: AnalysisOptions): AnalysisOptions {
  const { changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

// Builds the hook renderer input with an optional diff base only when the test needs base replay.
function hookRenderInput(currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean, diffBase?: string): HookRenderInput {
  return {
    currentOptions,
    scopedOptions,
    hasChangedRegion,
    ...(diffBase ? { diffBase } : {}),
  };
}

// Compares fallback and optimized hook renderers and asserts the optimized call count.
function assertHookRenderCalls(input: HookRenderInput, expectedCalls: number): void {
  const fallback = countingHookRunner(false);
  const optimized = countingHookRunner(true);
  const before = renderHookReport(fallback.runner, input);
  const after = renderHookReport(optimized.runner, input);
  assert.equal(after, before);
  assert.equal(optimized.calls(), expectedCalls);
  assert.equal(fallback.calls(), expectedCalls + (input.hasChangedRegion ? 1 : 0));
}

// Stable test contract: counts full analyse calls and optional hook-view calls behind one runner.
function countingHookRunner(shouldUseHookViews: boolean): { runner: CountingHookRunner; calls: () => number } {
  let analyseCalls = 0;
  let hookViewCalls = 0;
  const runner = ((options: AnalysisOptions): AnalysisReport => {
    analyseCalls += 1;
    return analyse(options);
  }) as CountingHookRunner;
  if (shouldUseHookViews) {
    runner.hookViews = (currentOptions, scopedOptions, hasChangedRegion) => {
      hookViewCalls += 1;
      return analyseHookReports(currentOptions, scopedOptions, hasChangedRegion);
    };
  }
  return { runner, calls: () => analyseCalls + hookViewCalls };
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
    schemaVersion: "gruff.baseline.v3",
    toolLanguage: "ts",
    generatedAt: new Date().toISOString(),
    // A sensitive finding carries no identity at all, so it can never reach a reviewed row.
    occurrences: findings
      .filter((finding) => finding.stableIdentity !== null)
      .map((finding) => ({ identity: finding.stableIdentity, count: 1, ruleId: finding.ruleId, path: finding.file, subject: baselineSubjectOf(finding) })),
    sensitive: { eligible: false, reason: "A sensitive finding is never stored.", counts: { total: 0, byRule: {} } },
  }));
}

// Rebuilds the subject the ratified identity hashed, which is what a generated baseline stores beside it.
// Stable contract: the same finding always yields the same subject, so a hand-built row matches a generated one.
function baselineSubjectOf(finding: HookFinding): string {
  return finding.symbol === null ? finding.message.replace(/[0-9]+(?:[.,][0-9]+)*/gu, "#") : `${finding.symbol}#${finding.symbolOrdinal}`;
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
