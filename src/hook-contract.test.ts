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

// Parsed gruff.hook.v1 payload as the conformance tests read it; mirrors the analyzer output contract.
interface HookPayload {
  contractVersion: string;
  analyzer: { name: string; version: string };
  supports?: Record<string, boolean>;
  flags?: Record<string, string>;
  flagOrder?: string;
  findings: HookFinding[];
  diagnostics?: Array<{ type: string; message: string; file?: string; line?: number; invalidatesRun?: false }>;
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
  column?: number;
  symbol: string | null;
  message: string;
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
  assert.equal(capabilities.supports?.diagnostics, true);
  assert.deepEqual(capabilities.flags, { changedRanges: "--changed-ranges", diff: "--diff", baseline: "--baseline", failOnDiagnostics: "--fail-on-diagnostics" });
  assert.equal(capabilities.flagOrder, "any");
});

test("hook reports diagnostics in-band with exit 0 and honors --fail-on-diagnostics", () => {
  // A lone unterminated brace is a real parse diagnostic; the default hook contract still exits 0
  // and surfaces it in the additive diagnostics field, so non-opting consumers keep old semantics.
  withProject({ "broken.ts": "// File overview: diagnostics fixture.\nexport const dangling = {\n" }, (dir) => {
    const payload = runHook(dir, ["hook", "--format", "json", "--no-config", "broken.ts"]);
    assert.equal(payload.diagnostics?.length, 1);
    assert.equal(payload.diagnostics?.[0]?.type, "parse-error");
    assert.equal(payload.diagnostics?.[0]?.file, "broken.ts");
    assert.equal(typeof payload.diagnostics?.[0]?.message, "string");

    // The explicit consumer request flips the same run to exit 2 while keeping identical JSON.
    const requested = spawnSync("bash", [BIN, "hook", "--format", "json", "--no-config", "--fail-on-diagnostics", "broken.ts"], { cwd: dir, encoding: "utf8" });
    assert.equal(requested.status, 2);
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

    assert.equal(payload.contractVersion, "gruff.hook.v1");
    assert.deepEqual(Object.keys(payload).sort(), ["analyzer", "config", "contractVersion", "diagnostics", "findings", "ignored", "suppressed"]);
    assert.deepEqual(payload.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.line), [7]);
  });
});

test("hook projects bounded deep-scan diagnostics without making them fatal", () => {
  const filler = Array.from({ length: 20_001 }, (_, index) => `export const filler${index} = ${index};`).join("\n");
  withProject({ "huge.ts": `${filler}\neval("payload");\n` }, (dir) => {
    const full = runHook(dir, ["hook", "--format", "json", "--no-config", "huge.ts"]);
    assert.equal("notes" in full, false);
    assert.deepEqual(full.diagnostics?.map((diagnostic) => ({ type: diagnostic.type, file: diagnostic.file, invalidatesRun: diagnostic.invalidatesRun })), [
      { type: "bounded-deep-scan", file: "huge.ts", invalidatesRun: false },
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
    assert.equal(payload.findings.every((finding) => /^[0-9a-f]{16}$/.test(finding.stableIdentity)), true);
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
    assert.equal(secrets[0]?.metadata.measured, undefined);
    assert.equal(typeof secrets[0]?.metadata.threshold, "number");
    assert.equal(secrets[0]?.metadata.preview, "[redacted]");
    assert.equal("length" in (secrets[0]?.metadata ?? {}), false);

    // Baseline only the first secret; the second is new and must survive new-only filtering rather
    // than collapsing onto the first secret's identity.
    writeBaseline(dir, secrets.slice(0, 1));
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "secrets.ts"]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]?.stableIdentity, secrets[1]?.stableIdentity);
  });
});

test("hook keeps two same-line secrets independently classifiable", () => {
  // Sub-threshold fragments keep this fixture safe; both assembled values sit on one line and share a fingerprint.
  // The ADR-017 column discriminator keeps the second finding alive for hook classification.
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
    assert.notEqual(secrets[0]?.stableIdentity, secrets[1]?.stableIdentity);

    // Baseline only the first same-line secret; the second must survive through its column-aware identity.
    writeBaseline(dir, secrets.slice(0, 1));
    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "gruff-baseline.json", "secrets.ts"]);
    const remaining = filtered.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]?.stableIdentity, secrets[1]?.stableIdentity);
  });
});

// Fixture purpose: models a hook user carrying a baseline entry with the former short preview.
// Stable contract: presentation churn resurfaces the credential once for fail-safe review.
test("hook resurfaces a finding after its redaction preview policy changes", () => {
  const previewPolicySecret = ["a1B2c3D4", "e5F6g7H8"].join("");
  const legacyPreview = `${previewPolicySecret.slice(0, 4)}...${previewPolicySecret.slice(-4)} (redacted, ${previewPolicySecret.length} chars)`;
  const legacyMessage = `Environment-style value \`API_TOKEN\` appears to be hardcoded with secret-like content. Redacted preview: ${legacyPreview}.`;
  withProject({ ".env": `API_TOKEN=${previewPolicySecret}\n` }, (dir) => {
    const currentFinding = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", ".env"]), "sensitive-data.hardcoded-env-value");
    // A baseline without a stored identity recomputes the old message-derived hook identity.
    writeProjectFile(dir, "legacy-preview-baseline.json", JSON.stringify({
      schemaVersion: "gruff.baseline.v1",
      entries: [{
        ruleId: currentFinding.ruleId,
        filePath: currentFinding.file,
        line: currentFinding.line,
        message: legacyMessage,
      }],
    }));

    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "legacy-preview-baseline.json", ".env"]);
    // The hook user must see the changed preview again instead of silently retaining suppression.
    assert.equal(filtered.findings.some((finding) => finding.ruleId === currentFinding.ruleId), true);
    assert.equal(filtered.suppressed.count, 0);
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
    assert.equal(payload.config.schemaOk, false);
    assert.equal(payload.findings.length, 0);
    assert.match(String(payload.config.error), /baseline|ENOENT|no such file/i);
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
    assert.match(String(payload.config.error), /schemaVersion/);
    assert.match(String(payload.config.error), /gruff-ts init/);
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
    // gruff.baseline.v1 keys on line, so the pair deliberately shares one fingerprint.
    assert.equal(first.fingerprint, second.fingerprint);
    // Column and identity are what let a consumer act on the second key instead of collapsing it.
    assert.notEqual(first.column, second.column);
    assert.notEqual(first.stableIdentity, second.stableIdentity);
  });
});

// Models an on-disk baseline with no stable identity or column.
// A column-bearing finding must still match, preventing identity enrichment from resurfacing every accepted finding.
test("hook suppression survives a baseline written in the on-disk format", () => {
  const secret = "aB3xY7kLmN9pQ2rS5" + "tU8vW1zC4dE6fG0hJ2kQ8w";
  const source = ["// File overview: hook baseline-format fixture.", `export const token = "${secret}";`].join("\n");
  withProject({ "secret.ts": source }, (dir) => {
    const before = requiredFinding(runHook(dir, ["hook", "--format", "json", "--no-config", "secret.ts"]), "sensitive-data.high-entropy-string");
    assert.equal(typeof before.column, "number");
    // Exactly the entry shape `writeBaseline` persists: no stableIdentity, no column.
    writeProjectFile(dir, "on-disk-baseline.json", JSON.stringify({
      schemaVersion: "gruff.baseline.v1",
      entries: [{ fingerprint: before.fingerprint, ruleId: before.ruleId, filePath: before.file, line: before.line, message: before.message }],
    }));

    const filtered = runHook(dir, ["hook", "--format", "json", "--no-config", "--baseline", "on-disk-baseline.json", "secret.ts"]);
    assert.equal(filtered.findings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string"), false);
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
