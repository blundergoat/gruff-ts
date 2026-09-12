// CLI and dashboard surface tests covering command help, render formats, SARIF, and HTML controls.
import { findingIdentities } from "./baseline-identity.ts";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyse, buildProgram, renderReport, ruleDescriptors } from "./cli.ts";
import { VERSION } from "./constants.ts";
import type { AnalysisReport } from "./cli.ts";
import { analyseFixture, REPO_ROOT } from "./test-fixtures.ts";

const VERSION_PATTERN = VERSION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("root CLI exposes gruff console command and option parity", () => {
  const list = execFileSync("./bin/gruff-ts", [], { encoding: "utf8" });
  const help = execFileSync("./bin/gruff-ts", ["--help"], { encoding: "utf8" });
  const explicitList = execFileSync("./bin/gruff-ts", ["list"], { encoding: "utf8" });
  const version = execFileSync("./bin/gruff-ts", ["--version"], { encoding: "utf8" });

  assert.equal(help, list);
  assert.equal(explicitList, list);
  assert.equal(version, `gruff-ts ${VERSION}\n`);
  assert.match(list, new RegExp(`^gruff-ts ${VERSION_PATTERN}\\n\\nUsage:\\n  command \\[options\\] \\[arguments\\]`));
  ["-h, --help", "--silent", "-q, --quiet", "-V, --version", "--ansi|--no-ansi", "-n, --no-interaction", "-v|vv|vvv, --verbose"].forEach((option) => {
    assert.match(list, new RegExp(option.replace(/[|]/g, "\\|")));
  });
  ["analyse", "completion", "dashboard", "help", "hook", "init", "list", "list-profiles", "list-rules", "report", "summary"].forEach((command) => {
    assert.match(list, new RegExp(`^  ${command}\\s+`, "m"));
  });
});

test("root CLI mirrors gruff php ANSI menu styling", () => {
  const ansiMenu = execFileSync("./bin/gruff-ts", ["--ansi"], { encoding: "utf8" });
  const plainMenu = execFileSync("./bin/gruff-ts", ["--no-ansi"], { encoding: "utf8" });

  assert.match(ansiMenu, new RegExp(`gruff-ts \\x1B\\[32m${VERSION_PATTERN}\\x1B\\[39m`));
  assert.match(ansiMenu, /\u001b\[33mUsage:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[33mOptions:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[32m-h, --help\u001b\[39m/);
  assert.match(ansiMenu, /display help for the \u001b\[32mlist\u001b\[39m command/i);
  assert.match(ansiMenu, /\u001b\[33mAvailable commands:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[32manalyse\u001b\[39m/);
  assert.equal(/\u001b\[[0-9;]*m/.test(plainMenu), false);
});

test("list-rules CLI prints text and deterministic json", () => {
  assert.equal(assertRuleListTextOutput(), true);
  assert.equal(assertRuleListJsonOutput(), true);
});

test("list-rules <ruleId> prints labelled per-rule detail in text mode", () => {
  // M08: positional argument switches to single-rule explain mode. The text section carries every
  // populated descriptor field plus the config-key list so an operator can see knobs without
  // grepping `src/config.ts`.
  const output = execFileSync("./bin/gruff-ts", ["list-rules", "complexity.cognitive"], { encoding: "utf8" });
  assert.match(output, /Rule:\s+complexity\.cognitive/);
  assert.match(output, /Pillar:\s+complexity/);
  assert.match(output, /Severity:\s+warning/);
  assert.match(output, /Confidence:\s+high/);
  assert.match(output, /Threshold:\s+15/);
  assert.match(output, /Description: /);
  assert.match(output, /Remediation: /);
  assert.match(output, /rules\.complexity\.cognitive\.enabled/);
  assert.match(output, /rules\.complexity\.cognitive\.threshold \(int, default: 15\)/);
});

test("list-rules <ruleId> renders JSON envelope with tool + rule + configKeys", () => {
  // JSON variant for docs/integration consumers. Shape: `{ tool: {name, version}, rule: { …listed record, configKeys: [...] } }`,
  // where the listed record is the same family shape the catalogue publishes (`id`, `defaultSeverity`, `thresholds`).
  const text = execFileSync("./bin/gruff-ts", ["list-rules", "naming.generic-parameter", "--format=json"], { encoding: "utf8" });
  const payload = JSON.parse(text);
  assert.equal(payload.tool?.name, "gruff-ts");
  assert.equal(payload.rule?.id, "naming.generic-parameter");
  assert.equal(typeof payload.rule?.defaultSeverity, "string");
  assert.equal("ruleId" in payload.rule, false);
  assert.equal("severity" in payload.rule, false);
  assert.deepEqual(payload.rule?.optionKeys, ["minCyclomatic", "minLineCount", "minParameters"]);

  const thresholded = JSON.parse(execFileSync("./bin/gruff-ts", ["list-rules", "complexity.cognitive", "--format=json"], { encoding: "utf8" }));
  assert.deepEqual(thresholded.rule?.thresholds, { maxComplexity: 15 });
  assert.equal("threshold" in thresholded.rule, false);
  assert.equal(Array.isArray(payload.rule?.configKeys), true);
  const enabledKey = payload.rule.configKeys.find((entry: { key: string }) => entry.key === "rules.naming.generic-parameter.enabled");
  assert.equal(enabledKey?.type, "bool");
});

test("list-rules <ruleId> prints reviewed false-positive guidance in both formats", () => {
  // M04: guidance reaches users only if the surfaces carry it. The JSON branch spreads the
  // descriptor so it gains the field for free, but both text renderers hand-format each field and
  // would drop it silently, which is what this guard exists to catch.
  const text = execFileSync("./bin/gruff-ts", ["list-rules", "security.async-foreach"], { encoding: "utf8" });
  assert.match(text, /Known false positives:/);
  assert.match(text, /\n {4}-> /);

  const payload = JSON.parse(execFileSync("./bin/gruff-ts", ["list-rules", "security.async-foreach", "--format=json"], { encoding: "utf8" }));
  assert.equal(Array.isArray(payload.rule?.falsePositiveShapes), true);
  assert.ok(payload.rule.falsePositiveShapes.length > 0);
  const malformed = payload.rule.falsePositiveShapes
    .filter((entry: { shape: unknown; mitigation: unknown }) => typeof entry.shape !== "string" || typeof entry.mitigation !== "string");
  assert.deepEqual(malformed, []);

  // A high-confidence rule omits the field, so its detail card shows no guidance heading at all.
  const highConfidence = execFileSync("./bin/gruff-ts", ["list-rules", "security.eval-call"], { encoding: "utf8" });
  assert.equal(highConfidence.includes("Known false positives:"), false);
});

test("list-rules unknown id exits 2 with the documented stderr message", () => {
  // Commander's `program.error({ exitCode: 2 })` is the canonical "usage error" code in this CLI;
  // hoisting it into a named constant keeps the assertion intent explicit.
  const expectedUsageErrorExitCode = 2;
  let exitCode = 0;
  let stderr = "";
  try {
    execFileSync("./bin/gruff-ts", ["list-rules", "not-a-real-rule"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (error: unknown) {
    const failure = error as { status?: number; stderr?: string };
    exitCode = failure.status ?? 0;
    stderr = failure.stderr ?? "";
  }
  assert.equal(exitCode, expectedUsageErrorExitCode);
  assert.match(stderr, /unknown rule "not-a-real-rule"/);
});

test("list-rules (no argument) output is byte-identical across runs", () => {
  // Regression guard: the new positional must not change the no-arg behaviour. Two runs return
  // identical bytes; the first run is what users have always seen.
  const firstRun = execFileSync("./bin/gruff-ts", ["list-rules"], { encoding: "utf8" });
  const secondRun = execFileSync("./bin/gruff-ts", ["list-rules"], { encoding: "utf8" });
  assert.equal(firstRun, secondRun);
});

/** Spawns the rule catalogue command and verifies representative metadata. */
function assertRuleListTextOutput(): boolean {
  const text = execFileSync("./bin/gruff-ts", ["list-rules"], { encoding: "utf8" });
  assert.match(text, new RegExp(`gruff-ts ${VERSION_PATTERN} rules \\(\\d+\\)`));
  assert.match(text, /security\.eval-call \| security \| error \| high \|/);
  assert.match(text, /complexity\.cyclomatic \| complexity \| warning \| high \| .*threshold: 15/);
  return true;
}

/** Verifies the JSON rule catalogue stays deterministic and complete enough for consumers. */
function assertRuleListJsonOutput(): boolean {
  const parsed = readDeterministicRuleListJson();
  assert.equal(parsed.schemaVersion, undefined);
  assert.equal(parsed.tool?.name, "gruff-ts");
  // The family listing shape: `id`, `defaultSeverity`, and a named threshold map under `thresholds`.
  // A rule whose id has a gruff-go knob name borrows it; one with no knob name anywhere publishes
  // the one-key `threshold` map; a rule with no threshold omits the key.
  assert.equal(ruleListJsonHasThreshold(parsed, "complexity.cognitive", { maxComplexity: 15 }), true);
  assert.equal(ruleListJsonHasThreshold(parsed, "design.deep-relative-import", { threshold: 2 }), true);
  assert.equal(ruleListJsonHasThreshold(parsed, "sensitive-data.high-entropy-string", { minLength: 32 }), true);
  assert.equal(parsed.rules?.find((rule) => rule.id === "security.eval-call")?.thresholds, undefined);
  assert.equal(parsed.rules?.every((rule) => typeof rule.id === "string" && typeof rule.defaultSeverity === "string"), true);
  assert.equal(parsed.rules?.some((rule) => "ruleId" in rule || "severity" in rule || "threshold" in rule), false);
  assert.equal(ruleListJsonHasOptionKey(parsed, "design.large-module-concentration", "minFiles"), true);
  return true;
}

type RuleListJsonRule = {
  id?: string;
  pillar?: string;
  defaultSeverity?: string;
  confidence?: string;
  description?: string;
  thresholds?: Record<string, number>;
  optionKeys?: string[];
};

type RuleListJsonPayload = {
  schemaVersion?: string;
  tool?: { name?: string; version?: string };
  rules?: RuleListJsonRule[];
};

/** Reads two JSON catalogue renders and proves the bytes are stable. */
function readDeterministicRuleListJson(): RuleListJsonPayload {
  const firstJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  const secondJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  assert.equal(firstJsonText, secondJsonText);
  return JSON.parse(firstJsonText) as RuleListJsonPayload;
}

/** Checks one rule's threshold map without making the catalogue test branch-heavy. */
function ruleListJsonHasThreshold(payload: RuleListJsonPayload, ruleId: string, thresholds: Record<string, number>): boolean {
  return payload.rules?.some((rule) => rule.id === ruleId && JSON.stringify(rule.thresholds) === JSON.stringify(thresholds)) ?? false;
}

/** Checks one rule option key without making the catalogue test branch-heavy. */
function ruleListJsonHasOptionKey(payload: RuleListJsonPayload, ruleId: string, optionKey: string): boolean {
  return payload.rules?.some((rule) => rule.id === ruleId && rule.optionKeys?.includes(optionKey)) ?? false;
}

test("console globals suppress normal output and completion emits a script", () => {
  const quietRules = execFileSync("./bin/gruff-ts", ["--quiet", "list-rules"], { encoding: "utf8" });
  assert.equal(quietRules, "");

  const completion = execFileSync("./bin/gruff-ts", ["completion"], { encoding: "utf8" });
  assert.match(completion, /complete -F _gruff_ts_completion gruff-ts/);
  assert.match(completion, /commands="analyse check-ignore completion dashboard hook init list list-profiles list-rules migrate-config report summary"/);
  assert.match(completion, /text json html markdown github hotspot sarif/);

  const analyseHelp = execFileSync("./bin/gruff-ts", ["analyse", "--help"], { encoding: "utf8" });
  assert.match(analyseHelp, /sarif/);
  assert.match(analyseHelp, /--changed-ranges <ranges>/);
  assert.match(analyseHelp, /--since <ref>/);
  assert.match(analyseHelp, /--changed-scope <scope>/);
  assert.match(analyseHelp, /--profile <spec>/);
});

test("summary CLI prints compact scan digest without per-finding spam", () => {
  const output = execFileSync("./bin/gruff-ts", ["summary", "fixtures/sample.ts", "--fail-on=none", "--no-config", "--no-baseline"], { encoding: "utf8" });
  assert.match(output, new RegExp(`^gruff-ts ${VERSION_PATTERN} summary`));
  assert.equal(output.includes(`Path: ${join(process.cwd(), "fixtures/sample.ts")}\n`), true);
  assert.match(output, /^Duration: (?:\d+ms|\d+\.\d{2}s)$/m);
  assert.match(output, /^Pillars$/m);
  assert.match(output, /^ {2}\S+\s+[A-F]\s+\d+\.\d{2} findings=\d+/m);
  assert.match(output, /Top 10 rules:/);
  assert.match(output, /Top 10 file offenders:/);
  assert.equal(/^Baseline:/m.test(output), false);
  assert.equal(output.includes("Findings:\n- ["), false);
});

test("summary JSON is the exact v3 analysis projection", () => {
  const output = execFileSync(
    "./bin/gruff-ts",
    ["summary", "fixtures/sample.ts", "--format=json", "--top=1", "--fail-on=none", "--no-config", "--no-baseline"],
    { encoding: "utf8" },
  );
  const payload = JSON.parse(output) as Record<string, unknown>;
  const analysis = JSON.parse(execFileSync(
    "./bin/gruff-ts",
    ["analyse", "fixtures/sample.ts", "--format=json", "--fail-on=none", "--no-config", "--no-baseline"],
    { encoding: "utf8" },
  )) as Record<string, unknown>;
  delete analysis.findings;
  analysis.schemaVersion = "gruff.summary.v3";

  assert.equal(payload.schemaVersion, "gruff.summary.v3");
  assert.equal("findings" in payload, false);
  assert.equal("topRules" in payload, false);
  assert.equal("topOffenders" in payload, false);
  assert.deepEqual(payload, analysis);
  const score = payload.score as Record<string, unknown>;
  const pillars = score.pillars as unknown[] | undefined;
  assert.ok(Array.isArray(pillars) && pillars.length > 0);
  pillars.forEach(assertPillarRowShape);
});

/** Validates one pillar row from the `gruff.summary.v3` JSON output. Accepts the raw parsed
 * value so the test does not need a typed interface mirroring the wire schema - the schema
 * contract lives in `renderSummaryJson`, this helper just confirms the row carries the
 * documented keys with the documented value types. */
function assertPillarRowShape(rawRow: unknown): void {
  assert.ok(rawRow && typeof rawRow === "object");
  const row = rawRow as Record<string, unknown>;
  assert.equal(typeof row.pillar, "string");
  assert.equal(typeof row.score, "number");
  assert.equal(typeof row.penalty, "number");
  assert.equal(typeof row.findings, "number");
}

test("summary CLI reports generated and applied baseline metadata", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-summary-baseline-"));
  try {
    const samplePath = join(projectRoot, "sample.ts");
    const baselinePath = join(projectRoot, "gruff-baseline.json");
    writeFileSync(samplePath, "eval('bad');\n");
    const generated = execFileSync(
      "./bin/gruff-ts",
      ["summary", samplePath, "--generate-baseline", baselinePath, "--fail-on=none", "--no-config"],
      { encoding: "utf8" },
    );
    assert.match(generated, /^Baseline: generated .*gruff-baseline\.json; current findings still shown$/m);
    assert.match(generated, /^Findings: [1-9]\d* total/m);

    const applied = execFileSync(
      "./bin/gruff-ts",
      ["summary", samplePath, "--baseline", baselinePath, "--fail-on=none", "--no-config"],
      { encoding: "utf8" },
    );
    assert.match(applied, /^Baseline: explicit .*gruff-baseline\.json; suppressed [1-9]\d* findings$/m);
    assert.match(applied, /^Findings: 0 total · 0 error · 0 warning · 0 advisory$/m);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("json report uses schema version", () => {
  const report = analyse({
    paths: [],
    shouldSkipConfig: true,
    format: "json",
    failOn: "none",
    shouldIncludeIgnored: false,
    changedScope: "symbol",
    shouldSkipBaseline: true,
  });
  const rendered = renderReport(report, "json");
  assert.match(rendered, /"schemaVersion": "gruff\.analysis\.v3"/);
});

test("json report emits only canonical v3 paths without mutating findings", () => {
  const report = analyseFixture(`function run(value: string): void {
  eval(value);
}
`);
  const before = JSON.stringify(report);
  const payload = JSON.parse(renderReport(report, "json")) as {
    findings: Array<{ file: string; stableIdentity: string; metadata: { locationPrecision: string } }>;
    score: { topOffenders: Array<{ file: string }> };
  };
  const [finding] = payload.findings;
  const [offender] = payload.score.topOffenders;
  const [nativeFinding] = report.findings;
  assert.ok(finding);
  assert.equal(finding.file, nativeFinding?.filePath);
  assert.equal("filePath" in finding, false);
  assert.match(finding.stableIdentity, /^[0-9a-f]{16}$/);
  assert.equal(finding.metadata.locationPrecision, "line-only");
  assert.ok(offender);
  assert.equal(offender.file, report.score.topOffenders[0]?.filePath);
  assert.equal("filePath" in offender, false);
  assert.ok(nativeFinding);
  assert.equal(JSON.stringify(report), before);
  assert.equal("file" in nativeFinding, false);
});

// Fixture for the SARIF render test. Hoisted out of the test body so the test reaches its first
// assertion within the setup-bloat threshold; the fixture data itself is non-trivial because it
// encodes the cross-pillar coverage SARIF must round-trip.
const SARIF_FIXTURE_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v3",
  tool: { name: "gruff-ts", version: "0.1.0-test" },
  run: { projectRoot: "/tmp/project", format: "sarif", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
  summary: { advisory: 1, warning: 1, error: 1, total: 3 },
  paths: { analysedFiles: 1, ignoredPaths: [], skipped: [], missingPaths: [] },
  diagnostics: [],
  suppressions: [],
  findings: [
    { ruleId: "security.eval-call", message: "Avoid eval().", filePath: "./src\\bad.ts", line: 7, endLine: 10, column: 3, severity: "error", pillar: "security", secondaryPillars: ["sensitive-data"], tier: "v0.1", confidence: "high", symbol: "run", remediation: "Use a dispatch table.", metadata: { target: "eval" }, fingerprint: "abc123", stableIdentity: "stable-abc123" },
    { ruleId: "waste.console-log", message: "Avoid console logging.", filePath: "src\\warn.ts", line: 8, severity: "warning", pillar: "maintainability", secondaryPillars: [], tier: "v0.1", confidence: "high", metadata: {}, fingerprint: "def456", stableIdentity: "stable-def456" },
    { ruleId: "docs.missing-public-doc", message: "Document public exports.", filePath: "./src/docs.ts", line: 9, severity: "advisory", pillar: "documentation", secondaryPillars: [], tier: "v0.1", confidence: "medium", metadata: { exported: true }, fingerprint: "ghi789", stableIdentity: "stable-ghi789" },
  ],
  score: {
    composite: 91,
    grade: "A",
    evaluatedFiles: 10,
    clusters: [],
    ruleAttribution: [],
    scoredPillars: ["security"],
    pillars: [{ pillar: "security", applicable: true, score: 91, grade: "A", penalty: 9, findings: 1 }],
    topOffenders: [{ filePath: "src/bad.ts", score: 91, penalty: 9, findings: 1 }],
  },
};

test("sarif report renders code scanning contract without mutating native json schema", () => {
  const report = SARIF_FIXTURE_REPORT;
  const beforeSarif = JSON.stringify(report);
  const payload = JSON.parse(renderReport(report, "sarif"));
  assert.equal(JSON.stringify(report), beforeSarif);
  const rules = payload.runs[0].tool.driver.rules as Array<{
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string };
    properties: Record<string, unknown>;
  }>;
  const descriptors = ruleDescriptors();
  const ruleIds = rules.map((rule) => rule.id);
  const results = payload.runs[0].results;
  const result = results[0];
  const evalDescriptor = descriptors.find((descriptor) => descriptor.ruleId === "security.eval-call");
  const evalRule = rules.find((rule) => rule.id === "security.eval-call");

  assert.equal(payload.version, "2.1.0");
  assert.equal(payload.runs[0].tool.driver.name, "gruff-ts");
  assert.equal(payload.runs[0].tool.driver.semanticVersion, "0.1.0-test");
  assert.deepEqual(ruleIds, [...ruleIds].sort());
  assert.deepEqual(ruleIds, descriptors.map((descriptor) => descriptor.ruleId));
  assert.ok(evalDescriptor);
  assert.ok(evalRule);
  assert.equal(evalRule.name, evalDescriptor.ruleId);
  assert.equal(evalRule.shortDescription.text, evalDescriptor.description);
  assert.equal(evalRule.fullDescription.text, evalDescriptor.description);
  assert.equal(evalRule.help.text, evalDescriptor.remediation);
  assert.equal(evalRule.properties.pillar, evalDescriptor.pillar);
  assert.equal(evalRule.properties.defaultSeverity, evalDescriptor.severity);
  assert.equal(evalRule.properties.confidence, evalDescriptor.confidence);
  assert.equal(evalRule.properties.defaultEnabled, true);
  results.forEach((sarifResult: SarifResult) => {
    assert.equal(rules[sarifResult.ruleIndex ?? -1]?.id ?? sarifResult.ruleId, sarifResult.ruleId);
    assert.equal(typeof sarifResult.partialFingerprints?.gruffFingerprint, "string");
    assert.equal("primary" in (sarifResult.partialFingerprints ?? {}), false);
    assert.equal("codeFlows" in sarifResult, false);
    assert.equal("threadFlows" in sarifResult, false);
    assert.equal("fixes" in sarifResult, false);
    assert.equal("relatedLocations" in sarifResult, false);
    assert.equal("suppressions" in sarifResult, false);
  });
  assert.equal(result.ruleId, "security.eval-call");
  assert.equal(result.ruleIndex, ruleIds.indexOf("security.eval-call"));
  assert.equal(result.level, "error");
  assert.equal(result.message.text, "Avoid eval().");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/bad.ts");
  const expectedStartLine = 7;
  const expectedStartColumn = 3;
  const expectedEndLine = 10;
  assert.equal(result.locations[0].physicalLocation.region.startLine, expectedStartLine);
  assert.equal(result.locations[0].physicalLocation.region.startColumn, expectedStartColumn);
  assert.equal(result.locations[0].physicalLocation.region.endLine, expectedEndLine);
  // Code scanning groups alerts by the ratified durable identity, not by the line-bearing fingerprint.
  assert.equal(result.partialFingerprints.gruffFingerprint, findingIdentities(SARIF_FIXTURE_REPORT.findings.slice(0, 1))[0]?.identity);
  assert.equal(result.properties.severity, "error");
  assert.equal(result.properties.pillar, "security");
  assert.deepEqual(result.properties.secondaryPillars, ["sensitive-data"]);
  assert.equal(result.properties.symbol, "run");
  assert.equal(result.properties.remediation, "Use a dispatch table.");
  assert.equal(result.properties.metadata.target, "eval");
  assert.equal(results[1].level, "warning");
  assert.equal(results[1].locations[0].physicalLocation.artifactLocation.uri, "src/warn.ts");
  assert.equal(results[1].properties.severity, "warning");
  assert.deepEqual(results[1].properties.metadata, {});
  assert.equal(results[2].level, "note");
  assert.equal(results[2].locations[0].physicalLocation.artifactLocation.uri, "src/docs.ts");
  assert.equal(results[2].properties.severity, "advisory");
  assert.equal(payload.runs[0].properties.gruffSchemaVersion, "gruff.analysis.v3");
  assert.equal(payload.runs[0].properties.generatedAt, "2026-05-15T00:00:00.000Z");
  const expectedScore = 91;
  assert.equal(payload.runs[0].properties.score, expectedScore);
  assert.equal(payload.runs[0].properties.grade, "A");
  assert.equal(JSON.parse(renderReport(report, "json")).schemaVersion, "gruff.analysis.v3");
  assert.equal(JSON.stringify(report), beforeSarif);
});

test("machine renderers escape SARIF URIs and GitHub annotation properties", () => {
  const [baseFinding] = SARIF_FIXTURE_REPORT.findings;
  assert.ok(baseFinding);
  const report: AnalysisReport = {
    ...SARIF_FIXTURE_REPORT,
    findings: [
      {
        ...baseFinding,
        ruleId: "docs.rule,with:colon",
        filePath: "./src/path with #hash,comma%.ts",
      },
    ],
  };

  const sarif = JSON.parse(renderReport(report, "sarif"));
  const github = renderReport(report, "github");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "src/path%20with%20%23hash%2Ccomma%25.ts");
  assert.match(github, /^::error file=src\/path with #hash%2Ccomma%25.ts,line=7,title=docs\.rule%2Cwith%3Acolon::Avoid eval\(\)\.$/);
});

type SarifResult = {
  ruleId: string;
  ruleIndex?: number;
  // Absent for a sensitive result, which has no durable identity to publish.
  partialFingerprints?: { gruffFingerprint: unknown } & Record<string, unknown>;
  properties?: { pillar?: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
};

// Asserts a single SARIF result's invariant shape: rule-index/ruleId stable identity, fingerprint
// presence, and POSIX-style normalised URI. Factored out of the test body so the loop carries no
// inline conditional branches.
function assertSarifResultShape(rules: Array<{ id: string }>, sarifResult: SarifResult): void {
  // An ordinary result carries the ratified identity; a secret carries no fingerprints at all.
  const isSensitive = sarifResult.ruleId.startsWith("sensitive-data.") || sarifResult.properties?.pillar === "sensitive-data";
  assert.equal(typeof sarifResult.partialFingerprints?.gruffFingerprint, isSensitive ? "undefined" : "string");
  const indexedRule = typeof sarifResult.ruleIndex === "number" ? rules[sarifResult.ruleIndex] : undefined;
  assert.equal(indexedRule?.id ?? sarifResult.ruleId, sarifResult.ruleId);
  const uri = sarifResult.locations[0]?.physicalLocation.artifactLocation.uri ?? "";
  assert.equal(uri.startsWith("./"), false);
  assert.equal(uri.includes("\\"), false);
}

test("analyse CLI emits parseable sarif for both format syntaxes", () => {
  ([
    ["--format", "sarif"],
    ["--format=sarif"],
  ] as const).forEach((formatArgs) => {
    const output = execFileSync("./bin/gruff-ts", ["analyse", "fixtures/sample.ts", ...formatArgs, "--fail-on=none", "--no-config", "--no-baseline"], { encoding: "utf8" });
    const payload = JSON.parse(output);
    const rules = payload.runs[0].tool.driver.rules;
    const ruleIds = rules.map((rule: { id: string }) => rule.id);
    const results = payload.runs[0].results;

    assert.equal(payload.version, "2.1.0");
    assert.equal(payload.runs.length, 1);
    assert.equal(payload.runs[0].tool.driver.name, "gruff-ts");
    assert.equal(payload.runs[0].tool.driver.semanticVersion, VERSION);
    assert.deepEqual(ruleIds, [...ruleIds].sort());
    assert.equal(results.length > 0, true);
    results.forEach((sarifResult: SarifResult) => assertSarifResultShape(rules, sarifResult));
  });
});

test("sarif fail-on preserves error exit behavior", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-sarif-fail-on-"));
  try {
    const target = join(dir, "bad.ts");
    writeFileSync(
      target,
      `export function run(source: string): unknown {
  return eval(source);
}
`,
    );

    const result = spawnSync("./bin/gruff-ts", ["analyse", target, "--format", "sarif", "--fail-on", "error", "--no-config", "--no-baseline"], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.version, "2.1.0");
    assert.equal(payload.runs[0].results.some((sarifResult: { ruleId?: string }) => sarifResult.ruleId === "security.eval-call"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Fixture for the HTML render test. Hoisted out of the test body to keep setup-bloat under
// threshold; the fixture intentionally embeds HTML metacharacters that the renderer must escape.
const ESCAPING_FIXTURE_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v3",
  tool: { name: "gruff-ts", version: "0.1.0-test<script>" },
  run: { projectRoot: "/tmp/project", format: "html", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
  summary: { advisory: 0, warning: 1, error: 1, total: 2 },
  paths: { analysedFiles: 1, ignoredPaths: [], skipped: [], missingPaths: [] },
  diagnostics: [],
  suppressions: [],
  findings: [
    { ruleId: "docs.<script>", message: "Message with <script>alert(1)</script>", filePath: "src/<bad>.ts", line: 7, severity: "warning", pillar: "documentation", secondaryPillars: [], tier: "v0.1", confidence: "high", symbol: "badSymbol", metadata: {}, fingerprint: "abc123", stableIdentity: "stable-abc123" },
    { ruleId: "complexity.cyclomatic", message: "Function has cyclomatic complexity 12.", filePath: "src/Complex.ts", line: 11, severity: "error", pillar: "complexity", secondaryPillars: [], tier: "v0.1", confidence: "high", symbol: "run", metadata: {}, fingerprint: "def456", stableIdentity: "stable-def456" },
  ],
  score: {
    composite: 82.5,
    grade: "B",
    evaluatedFiles: 10,
    clusters: [],
    ruleAttribution: [],
    scoredPillars: ["documentation"],
    pillars: [{ pillar: "documentation", applicable: true, score: 84, grade: "B", penalty: 16, findings: 1 }],
    topOffenders: [{ filePath: "src/<bad>.ts", score: 88, penalty: 16, findings: 1 }],
  },
};

test("html report uses dashboard parity anchors and escapes values", () => {
  const rendered = renderReport(ESCAPING_FIXTURE_REPORT, "html");

  ["paper", "masthead", "wordmark", "verdict", "grade-stamp", "pillar-grid", "offender-list", "chart-section", "finding"].forEach((anchor) => {
    assert.match(rendered, new RegExp(`class="${anchor}`));
  });
  assert.match(rendered, /gruff-ts/);
  assert.match(rendered, /inspected for human sign-off/);
  assert.match(rendered, /src\/&lt;bad&gt;\.ts/);
  assert.match(rendered, /docs\.&lt;script&gt;/);
  assert.match(rendered, /Message with &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.equal(rendered.includes("0.1.0-test<script>"), false);
  assert.equal(rendered.includes("src/<bad>.ts"), false);
  assert.equal(rendered.includes("<script>alert(1)</script>"), false);
});

test("html report renders canonical 7-column Pillars table matching text/json shape", () => {
  const rendered = renderReport(ESCAPING_FIXTURE_REPORT, "html");
  const pillarsMatch = rendered.match(/<section class="pillars">[\s\S]*?<\/section>/);
  assert.ok(pillarsMatch, "pillars section not found");
  const section = pillarsMatch[0];

  assert.match(section, /<h2 class="section-head">Pillars\s/);
  assert.match(section, /<table class="pillar-table">/);
  assertHtmlPillarHeaders(section);

  const rows = parseHtmlPillarRows(section);
  assert.ok(rows.length > 0, "no pillar rows rendered");
  assertHtmlPillarRowsSorted(rows);
  assertHtmlPillarScoresWellFormed(rows);
});

// Parsed shape of one row from the HTML pillar table. Cells may legitimately be undefined if the
// renderer omits decoration spans, so the typed shape mirrors that uncertainty rather than coerce.
interface ParsedHtmlPillarRow {
  pillar: string | undefined;
  grade: string | undefined;
  score: string | undefined;
  findings: number;
  advisory: number;
  warning: number;
  error: number;
}

const pillarHeaderColumns = ["pillar", "grade", "score", "findings", "advisory", "warning", "error"] as const;

/** Confirms every required column header is present with the expected `class="num"` decoration
 * and that headers appear in the canonical cross-port order. */
function assertHtmlPillarHeaders(section: string): void {
  pillarHeaderColumns.forEach((header, index) => {
    const numericColumnAttribute = index === 0 ? "" : ' class="num"';
    assert.match(section, new RegExp(`<th scope="col"${numericColumnAttribute}>${header}</th>`));
  });
  const headerOrder = [...section.matchAll(/<th[^>]*>([^<]+)<\/th>/g)].map((entry) => entry[1]);
  assert.deepEqual(headerOrder, [...pillarHeaderColumns]);
}

/** Extracts the body rows from the HTML pillar section into a typed shape so individual
 * assertions only reference field names, never regex group indices. */
function parseHtmlPillarRows(section: string): ParsedHtmlPillarRow[] {
  const rowMatches = [...section.matchAll(/<tr>(?:(?!<\/?thead).)*?<\/tr>/g)].slice(1);
  return rowMatches.map((entry) => {
    const cells = [...entry[0].matchAll(/<td[^>]*>(?:<span[^>]*>)?([^<]+)(?:<\/span>)?<\/td>/g)].map((cell) => cell[1]);
    return {
      pillar: cells[0],
      grade: cells[1],
      score: cells[2],
      findings: Number(cells[3]),
      advisory: Number(cells[4]),
      warning: Number(cells[5]),
      error: Number(cells[6]),
    };
  });
}

/** Verifies the cross-port sort contract: findings DESC, then pillar ASC. Helper exists so the
 * test body reads as a list of high-level assertions without inline loops. */
function assertHtmlPillarRowsSorted(rows: ParsedHtmlPillarRow[]): void {
  for (let i = 1; i < rows.length; i += 1) {
    const previous = rows[i - 1];
    const current = rows[i];
    assert.ok(previous && current);
    if (previous.findings === current.findings) {
      assert.ok((previous.pillar ?? "") <= (current.pillar ?? ""), `pillar sort broken at ${current.pillar}`);
    } else {
      assert.ok(previous.findings > current.findings, `findings sort broken at ${current.pillar}`);
    }
  }
}

/** Score column is rendered with two decimal places everywhere. */
function assertHtmlPillarScoresWellFormed(rows: ParsedHtmlPillarRow[]): void {
  rows.forEach((row) => {
    assert.match(row.score ?? "", /^\d+\.\d{2}$/);
  });
}

test("markdown report renders canonical 7-column Pillars table matching cross-port shape", () => {
  const rendered = renderReport(ESCAPING_FIXTURE_REPORT, "markdown");

  assert.match(rendered, /^# gruff-ts report$/m);
  assert.match(rendered, /^## Pillars$/m);
  assert.match(rendered, /^\| Pillar \| Grade \| Score \| Findings \| Advisory \| Warning \| Error \|$/m);
  assert.match(rendered, /^\| --- \| --- \| ---: \| ---: \| ---: \| ---: \| ---: \|$/m);

  // Pillars block must appear before the per-finding bullet list so CI/PR previews see it first.
  const pillarsHeadingIndex = rendered.indexOf("## Pillars");
  const firstFindingIndex = rendered.indexOf("- `");
  assert.ok(pillarsHeadingIndex > 0, "Pillars heading missing");
  assert.ok(firstFindingIndex > 0, "no findings rendered");
  assert.ok(pillarsHeadingIndex < firstFindingIndex, "Pillars block should precede the findings list");

  const parsedRows = parseMarkdownPillarRows(rendered);
  assert.ok(parsedRows.length > 0, "no pillar rows rendered");
  parsedRows.forEach((row) => {
    assert.match(row.score, /^\d+\.\d{2}$/, `score should be 2-decimal: ${row.score}`);
    assert.match(row.grade, /^[A-F]$/, `grade should be a single letter: ${row.grade}`);
  });
  assertPillarSortOrder(parsedRows);

  // Every applicable pillar surfaces, including those with zero findings (clean rows render A/100.00).
  const cleanPillarRow = parsedRows.find((row) => row.pillar === "size");
  assert.ok(cleanPillarRow, "clean pillar row missing");
  assert.equal(cleanPillarRow.grade, "A");
  assert.equal(cleanPillarRow.score, "100.00");
  assert.equal(cleanPillarRow.findings, 0);
});

// Shape of one parsed row used by the markdown table test. Kept narrow because the test only
// validates the cross-port column contract; the renderer is the source of truth for everything
// else (e.g. whitespace, decoration).
interface ParsedMarkdownPillarRow {
  pillar: string;
  grade: string;
  score: string;
  findings: number;
  advisory: number;
  warning: number;
  error: number;
}

/* Extracts every data row between the separator and the next blank line into a typed shape so the
 * markdown table test can focus on assertions instead of cell parsing. Why this lives outside the
 * test body: the per-row cell destructuring otherwise pushes the test past the cyclomatic and
 * cognitive thresholds, hiding the actual contract assertions inside parsing noise. */
function parseMarkdownPillarRows(rendered: string): ParsedMarkdownPillarRow[] {
  const tableMatch = rendered.match(/\| --- \| --- \| ---: \| ---: \| ---: \| ---: \| ---: \|\n([\s\S]*?)(?:\n\n|$)/);
  assert.ok(tableMatch, "pillar data rows not found");
  const dataRows = (tableMatch[1] ?? "").split("\n").filter((line) => line.startsWith("|"));
  return dataRows.map(parseMarkdownPillarRow);
}

/* Splits a single `| cell | cell | … |` line into the typed row contract. Defaults are conservative
 * empty/zero values because the upstream regex already verified the table has the right shape. */
function parseMarkdownPillarRow(line: string): ParsedMarkdownPillarRow {
  const cells = line.split("|").slice(1, -1).map((cell) => cell.trim());
  const [pillar = "", gradeText = "", score = "", findings = "0", advisory = "0", warning = "0", error = "0"] = cells;
  return {
    pillar,
    grade: gradeText,
    score,
    findings: Number(findings),
    advisory: Number(advisory),
    warning: Number(warning),
    error: Number(error),
  };
}

/** Validates the cross-port sort contract: findings DESC, then pillar ASC. Lifted out so the body
 * of the markdown test reads as a list of high-level assertions. */
function assertPillarSortOrder(rows: ParsedMarkdownPillarRow[]): void {
  for (let i = 1; i < rows.length; i += 1) {
    const previous = rows[i - 1];
    const current = rows[i];
    assert.ok(previous && current);
    if (previous.findings === current.findings) {
      assert.ok(previous.pillar <= current.pillar, `pillar sort broken at ${current.pillar}`);
    } else {
      assert.ok(previous.findings > current.findings, `findings sort broken at ${current.pillar}`);
    }
  }
}

test("html report rendering does not mutate json report output", () => {
  const report = analyseFixture(`export function process(value: string): string {
  return value;
}
`);
  const before = renderReport(report, "json");

  renderReport(report, "html");

  assert.equal(renderReport(report, "json"), before);
  assert.match(before, /"schemaVersion": "gruff\.analysis\.v3"/);
});

test("report command ignores default baselines", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-report-baseline-"));
  try {
    writeFileSync(
      join(projectRoot, "bad.ts"),
      `export function unsafe(input: string): unknown {
  return eval(input);
}
`,
    );
    execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "analyse", ".", "--generate-baseline", "gruff-baseline.json", "--fail-on=none", "--no-config"], { cwd: projectRoot, encoding: "utf8" });
    const output = execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "report", ".", "--format=json", "--fail-on=none", "--no-config"], { cwd: projectRoot, encoding: "utf8" });
    const report = JSON.parse(output) as AnalysisReport;
    assert.equal(report.baseline, undefined);
    assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), true);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

// Governance controls must reject misspelled values before analysis starts, not silently default.
// Spawns the CLI once per case and asserts the usage error names the accepted set.
function assertConstrainedValueRejected(label: string, args: string[]): void {
  const result = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), ...args], { encoding: "utf8" });
  assert.notEqual(result.status, 0, `${label} must fail fast`);
  assert.equal(result.stderr.includes("must be one of:"), true, `${label} must name the accepted values`);
}

test("constrained option values fail fast as usage errors naming the accepted set", () => {
  assertConstrainedValueRejected("analyse --format", ["analyse", "--format", "bogus", "--no-config", "--no-baseline"]);
  assertConstrainedValueRejected("analyse --fail-on", ["analyse", "--fail-on", "bogus", "--no-config", "--no-baseline"]);
  assertConstrainedValueRejected("analyse --changed-scope", ["analyse", "--changed-scope", "bogus", "--no-config", "--no-baseline"]);
  assertConstrainedValueRejected("report --format", ["report", "--format", "bogus", "--no-config"]);
  assertConstrainedValueRejected("report --fail-on", ["report", "--fail-on", "bogus", "--no-config"]);
  assertConstrainedValueRejected("summary --fail-on", ["summary", "--fail-on", "bogus", "--no-config"]);
});

test("deep-scan CLI override accepts paired limits or off and rejects partial values", () => {
  for (const command of ["analyse", "hook", "report", "summary"]) {
    const invalid = spawnSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), command, "--deep-scan-budget", "100", "--no-config"], { encoding: "utf8" });
    assert.notEqual(invalid.status, 0, `${command} must reject an unpaired budget`);
    assert.match(invalid.stderr, /LINES:BYTES, or off/);
  }
});

test("valid constrained values and bare directory arguments keep working", () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-valid-values-"));
  try {
    writeFileSync(join(projectRoot, "clean.ts"), "// File overview: valid-values fixture.\nexport const fine = 1;\n");
    const valid = spawnSync(
      "bash",
      [join(REPO_ROOT, "bin/gruff-ts"), "analyse", ".", "--format", "json", "--fail-on", "none", "--changed-scope", "file", "--no-config", "--no-baseline"],
      { cwd: projectRoot, encoding: "utf8" },
    );
    assert.equal(valid.status, 0);
    assert.equal(JSON.parse(valid.stdout).schemaVersion, "gruff.analysis.v3");

    // Family CLI contract: a bare directory operand means the whole subtree (dir equals dir/**).
    mkdirSync(join(projectRoot, "sub"), { recursive: true });
    writeFileSync(join(projectRoot, "sub", "nested.ts"), "// File overview: bare-directory fixture.\nexport function risky(input: string): unknown {\n  return eval(input);\n}\n");
    const bareDirRun = spawnSync(
      "bash",
      [join(REPO_ROOT, "bin/gruff-ts"), "analyse", "sub", "--format", "json", "--fail-on", "none", "--no-config", "--no-baseline"],
      { cwd: projectRoot, encoding: "utf8" },
    );
    assert.equal(bareDirRun.status, 0);
    const bareDirReport = JSON.parse(bareDirRun.stdout) as { findings: Array<{ ruleId: string; file: string }> };
    assert.equal(bareDirReport.findings.some((finding) => finding.ruleId === "security.eval-call" && finding.file === "sub/nested.ts"), true);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

/*
 * Fixture purpose: the console catalogue is hand-written and the completion script is rendered from it, so a
 * command registered on the program and forgotten in the catalogue is invisible in both.
 * Stable contract: every registered command appears in the catalogue and in every shell completion script, so a
 * user who runs `gruff-ts` or presses tab sees the whole command surface.
 * Spawns the built binary four times to read what a user would actually see; it writes nothing and needs no fixture.
 */
test("every registered command appears in the catalogue and in every completion script", () => {
  // Commander keeps its own help command out of `commands`, so the catalogue's `help` row is added back here.
  const registered = [...buildProgram().commands.map((command) => command.name()), "help"].sort();
  const catalogue = execFileSync("./bin/gruff-ts", [], { encoding: "utf8", cwd: REPO_ROOT });
  const listed = catalogue
    .split("Available commands:")[1]
    ?.split("\n")
    .map((line) => line.trim().split(/\s+/u)[0])
    .filter((name) => name !== undefined && name.length > 0)
    .sort() ?? [];

  // check-ignore was registered and absent from this list until M08 task 9, so nothing surfaced it to a user.
  assert.deepEqual(listed, registered);

  for (const shell of ["bash", "zsh", "fish"]) {
    const completion = execFileSync("./bin/gruff-ts", ["completion", shell], { encoding: "utf8", cwd: REPO_ROOT });

    // `help` is deliberately absent from completions; every other registered command must be offered.
    for (const command of registered.filter((name) => name !== "help")) {
      assert.equal(completion.includes(command), true, `${shell} completion omits ${command}`);
    }
  }
});
