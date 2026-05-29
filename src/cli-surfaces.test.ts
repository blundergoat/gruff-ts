// CLI and dashboard surface tests covering command help, render formats, SARIF, and HTML controls.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyse, renderReport, ruleDescriptors } from "./cli.ts";
import { VERSION } from "./constants.ts";
import type { AnalysisReport } from "./cli.ts";
import { analyseFixture, fetchText, REPO_ROOT, withDashboard } from "./test-fixtures.ts";

const VERSION_PATTERN = VERSION.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

test("root CLI exposes gruff console command and option parity", () => {
  const list = execFileSync("./bin/gruff-ts", [], { encoding: "utf8" });
  const help = execFileSync("./bin/gruff-ts", ["--help"], { encoding: "utf8" });
  const explicitList = execFileSync("./bin/gruff-ts", ["list"], { encoding: "utf8" });

  assert.equal(help, list);
  assert.equal(explicitList, list);
  assert.match(list, new RegExp(`^gruff-ts ${VERSION_PATTERN}\\n\\nUsage:\\n  command \\[options\\] \\[arguments\\]`));
  ["-h, --help", "--silent", "-q, --quiet", "-V, --version", "--ansi|--no-ansi", "-n, --no-interaction", "-v|vv|vvv, --verbose"].forEach((option) => {
    assert.match(list, new RegExp(option.replace(/[|]/g, "\\|")));
  });
  ["analyse", "completion", "dashboard", "help", "init", "list", "list-rules", "report", "summary"].forEach((command) => {
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
  // JSON variant for docs/integration consumers. Shape: `{ tool: {name, version}, rule: { …descriptor, configKeys: [...] } }`.
  const text = execFileSync("./bin/gruff-ts", ["list-rules", "naming.generic-parameter", "--format=json"], { encoding: "utf8" });
  const payload = JSON.parse(text);
  assert.equal(payload.tool?.name, "gruff-ts");
  assert.equal(payload.rule?.ruleId, "naming.generic-parameter");
  assert.deepEqual(payload.rule?.optionKeys, ["minCyclomatic", "minLineCount", "minParameters"]);
  assert.equal(Array.isArray(payload.rule?.configKeys), true);
  const enabledKey = payload.rule.configKeys.find((entry: { key: string }) => entry.key === "rules.naming.generic-parameter.enabled");
  assert.equal(enabledKey?.type, "bool");
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
  assert.match(text, /complexity\.npath \| complexity \| warning \| medium \| .*threshold: 20/);
  return true;
}

/** Verifies the JSON rule catalogue stays deterministic and complete enough for consumers. */
function assertRuleListJsonOutput(): boolean {
  const parsed = readDeterministicRuleListJson();
  assert.equal(parsed.schemaVersion, undefined);
  assert.equal(parsed.tool?.name, "gruff-ts");
  assert.equal(ruleListJsonHasThreshold(parsed, "design.deep-relative-import", 2), true);
  assert.equal(ruleListJsonHasOptionKey(parsed, "design.large-module-concentration", "minFiles"), true);
  return true;
}

type RuleListJsonRule = {
  ruleId?: string;
  pillar?: string;
  severity?: string;
  confidence?: string;
  description?: string;
  threshold?: number;
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

/** Checks one rule threshold without making the catalogue test branch-heavy. */
function ruleListJsonHasThreshold(payload: RuleListJsonPayload, ruleId: string, threshold: number): boolean {
  return payload.rules?.some((rule) => rule.ruleId === ruleId && rule.threshold === threshold) ?? false;
}

/** Checks one rule option key without making the catalogue test branch-heavy. */
function ruleListJsonHasOptionKey(payload: RuleListJsonPayload, ruleId: string, optionKey: string): boolean {
  return payload.rules?.some((rule) => rule.ruleId === ruleId && rule.optionKeys?.includes(optionKey)) ?? false;
}

test("console globals suppress normal output and completion emits a script", () => {
  const quietRules = execFileSync("./bin/gruff-ts", ["--quiet", "list-rules"], { encoding: "utf8" });
  assert.equal(quietRules, "");

  const completion = execFileSync("./bin/gruff-ts", ["completion"], { encoding: "utf8" });
  assert.match(completion, /complete -F _gruff_ts_completion gruff-ts/);
  assert.match(completion, /commands="analyse completion dashboard init list list-rules report summary"/);
  assert.match(completion, /text json html markdown github hotspot sarif/);

  const analyseHelp = execFileSync("./bin/gruff-ts", ["analyse", "--help"], { encoding: "utf8" });
  assert.match(analyseHelp, /sarif/);
  assert.match(analyseHelp, /--changed-ranges <ranges>/);
  assert.match(analyseHelp, /--since <ref>/);
  assert.match(analyseHelp, /--changed-scope <scope>/);
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

test("summary CLI supports json format and top limit", () => {
  const output = execFileSync(
    "./bin/gruff-ts",
    ["summary", "fixtures/sample.ts", "--format=json", "--top=1", "--fail-on=none", "--no-config", "--no-baseline"],
    { encoding: "utf8" },
  );
  const payload = JSON.parse(output) as Record<string, unknown>;
  assert.equal(payload.schemaVersion, "gruff.summary.v2");
  assert.equal((payload.topRules as unknown[] | undefined)?.length, 1);
  assert.ok(((payload.topOffenders as unknown[] | undefined)?.length ?? 0) <= 1);
  const pillars = payload.pillars as unknown[] | undefined;
  assert.ok(Array.isArray(pillars) && pillars.length > 0);
  pillars.forEach(assertPillarRowShape);
});

/** Validates one pillar row from the `gruff.summary.v2` JSON output. Accepts the raw parsed
 * value so the test does not need a typed interface mirroring the wire schema - the schema
 * contract lives in `renderSummaryJson`, this helper just confirms the row carries the
 * documented keys with the documented value types. */
function assertPillarRowShape(rawRow: unknown): void {
  assert.ok(rawRow && typeof rawRow === "object");
  const row = rawRow as Record<string, unknown>;
  assert.equal(typeof row.pillar, "string");
  assert.match(String(row.grade), /^[A-F]$/);
  assert.equal(typeof row.score, "number");
  assert.equal(typeof row.penalty, "number");
  assert.equal(row.applicable, true);
  assert.equal(typeof row.findings, "number");
  assert.equal(typeof row.advisory, "number");
  assert.equal(typeof row.warning, "number");
  assert.equal(typeof row.error, "number");
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
    assert.match(applied, /^Findings: 0 total, 0 error, 0 warning, 0 advisory$/m);
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
  assert.match(rendered, /"schemaVersion": "gruff\.analysis\.v2"/);
});

// Fixture for the SARIF render test. Hoisted out of the test body so the test reaches its first
// assertion within the setup-bloat threshold; the fixture data itself is non-trivial because it
// encodes the cross-pillar coverage SARIF must round-trip.
const SARIF_FIXTURE_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v2",
  tool: { name: "gruff-ts", version: "0.1.0-test" },
  run: { projectRoot: "/tmp/project", format: "sarif", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
  summary: { advisory: 1, warning: 1, error: 1, total: 3 },
  paths: { analysedFiles: 1, ignoredPaths: [], missingPaths: [] },
  diagnostics: [],
  findings: [
    { ruleId: "security.eval-call", message: "Avoid eval().", filePath: "./src\\bad.ts", line: 7, endLine: 10, column: 3, severity: "error", pillar: "security", secondaryPillars: ["sensitive-data"], tier: "v0.1", confidence: "high", symbol: "run", remediation: "Use a dispatch table.", metadata: { target: "eval" }, fingerprint: "abc123" },
    { ruleId: "waste.console-log", message: "Avoid console logging.", filePath: "src\\warn.ts", line: 8, severity: "warning", pillar: "maintainability", secondaryPillars: [], tier: "v0.1", confidence: "high", metadata: {}, fingerprint: "def456" },
    { ruleId: "docs.missing-public-doc", message: "Document public exports.", filePath: "./src/docs.ts", line: 9, severity: "advisory", pillar: "documentation", secondaryPillars: [], tier: "v0.1", confidence: "medium", metadata: { exported: true }, fingerprint: "ghi789" },
  ],
  score: {
    composite: 91,
    grade: "A",
    pillars: [{ pillar: "security", score: 91, penalty: 9, findings: 1 }],
    topOffenders: [{ filePath: "src/bad.ts", score: 91, findings: 1 }],
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
    assert.equal(typeof sarifResult.partialFingerprints.gruffFingerprint, "string");
    assert.equal("primary" in sarifResult.partialFingerprints, false);
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
  assert.equal(result.partialFingerprints.gruffFingerprint, "abc123");
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
  assert.equal(payload.runs[0].properties.gruffSchemaVersion, "gruff.analysis.v2");
  assert.equal(payload.runs[0].properties.generatedAt, "2026-05-15T00:00:00.000Z");
  const expectedScore = 91;
  assert.equal(payload.runs[0].properties.score, expectedScore);
  assert.equal(payload.runs[0].properties.grade, "A");
  assert.equal(JSON.parse(renderReport(report, "json")).schemaVersion, "gruff.analysis.v2");
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
  partialFingerprints: { gruffFingerprint: unknown } & Record<string, unknown>;
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
};

// Asserts a single SARIF result's invariant shape: rule-index/ruleId stable identity, fingerprint
// presence, and POSIX-style normalised URI. Factored out of the test body so the loop carries no
// inline conditional branches.
function assertSarifResultShape(rules: Array<{ id: string }>, sarifResult: SarifResult): void {
  assert.equal(typeof sarifResult.partialFingerprints.gruffFingerprint, "string");
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
  schemaVersion: "gruff.analysis.v2",
  tool: { name: "gruff-ts", version: "0.1.0-test<script>" },
  run: { projectRoot: "/tmp/project", format: "html", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
  summary: { advisory: 0, warning: 1, error: 1, total: 2 },
  paths: { analysedFiles: 1, ignoredPaths: [], missingPaths: [] },
  diagnostics: [],
  findings: [
    { ruleId: "docs.<script>", message: "Message with <script>alert(1)</script>", filePath: "src/<bad>.ts", line: 7, severity: "warning", pillar: "documentation", secondaryPillars: [], tier: "v0.1", confidence: "high", symbol: "badSymbol", metadata: {}, fingerprint: "abc123" },
    { ruleId: "complexity.cyclomatic", message: "Function has cyclomatic complexity 12.", filePath: "src/Complex.ts", line: 11, severity: "error", pillar: "complexity", secondaryPillars: [], tier: "v0.1", confidence: "high", symbol: "run", metadata: {}, fingerprint: "def456" },
  ],
  score: {
    composite: 82.5,
    grade: "B",
    pillars: [{ pillar: "documentation", score: 84, penalty: 16, findings: 1 }],
    topOffenders: [{ filePath: "src/<bad>.ts", score: 88, findings: 1 }],
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
  assert.match(before, /"schemaVersion": "gruff\.analysis\.v2"/);
});

test("dashboard root uses parity shell and escapes controls", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const rootHtml = await fetchText(`${baseUrl}/?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      ["controls-toggle", "controls-panel", "report-frame", "scan-form"].forEach((anchor) => {
        assert.match(rootHtml, new RegExp(`class="${anchor}`));
      });
      assert.match(rootHtml, /Project root/);
      assert.match(rootHtml, /Paths/);
      assert.match(rootHtml, /&lt;bad&gt;/);
      assert.match(rootHtml, /src="\/scan\?projectRoot=/);
      assert.equal(rootHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard scan returns report shell with escaped dashboard context", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const scanHtml = await fetchText(`${baseUrl}/scan?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      assert.match(scanHtml, /class="paper"/);
      assert.match(scanHtml, /class="dashboard-context"/);
      assert.match(scanHtml, /Project root/);
      assert.match(scanHtml, /sample\.ts/);
      assert.match(scanHtml, /&lt;bad&gt;/);
      assert.equal(scanHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard rejects non-loopback hosts", () => {
  const result = spawnSync("./bin/gruff-ts", ["dashboard", "--host", "0.0.0.0", "--port", "0"], { encoding: "utf8" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Dashboard host must be 127\.0\.0\.1 or localhost/);
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
