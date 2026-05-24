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
});

test("summary CLI prints compact scan digest without per-finding spam", () => {
  const output = execFileSync("./bin/gruff-ts", ["summary", "fixtures/sample.ts", "--fail-on=none", "--no-config", "--no-baseline"], { encoding: "utf8" });
  assert.match(output, new RegExp(`^gruff-ts ${VERSION_PATTERN} summary`));
  assert.equal(output.includes(`Path: ${join(process.cwd(), "fixtures/sample.ts")}\n`), true);
  assert.match(output, /^Duration: (?:\d+ms|\d+\.\d{2}s)$/m);
  assert.match(output, /Per-pillar counts:/);
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
  const payload = JSON.parse(output) as {
    schemaVersion?: string;
    topRules?: unknown[];
    topOffenders?: unknown[];
  };
  assert.equal(payload.schemaVersion, "gruff.summary.v1");
  assert.equal(payload.topRules?.length, 1);
  assert.ok((payload.topOffenders?.length ?? 0) <= 1);
});

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
    shouldSkipBaseline: true,
  });
  const rendered = renderReport(report, "json");
  assert.match(rendered, /"schemaVersion": "gruff\.analysis\.v1"/);
});

// Fixture for the SARIF render test. Hoisted out of the test body so the test reaches its first
// assertion within the setup-bloat threshold; the fixture data itself is non-trivial because it
// encodes the cross-pillar coverage SARIF must round-trip.
const SARIF_FIXTURE_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v1",
  tool: { name: "gruff-ts", version: "0.1.0-test" },
  run: { projectRoot: "/tmp/project", format: "sarif", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
  summary: { advisory: 1, warning: 1, error: 1, total: 3 },
  paths: { analysedFiles: 1, ignoredPaths: [], missingPaths: [] },
  diagnostics: [],
  findings: [
    { ruleId: "security.eval-call", message: "Avoid eval().", filePath: "./src\\bad.ts", line: 7, endLine: 10, column: 3, severity: "error", pillar: "security", secondaryPillars: ["sensitive-data"], tier: "v0.1", confidence: "high", symbol: "run", remediation: "Use a dispatch table.", metadata: { target: "eval" }, fingerprint: "abc123" },
    { ruleId: "waste.console-log", message: "Avoid console logging.", filePath: "src\\warn.ts", line: 8, severity: "warning", pillar: "waste", secondaryPillars: [], tier: "v0.1", confidence: "high", metadata: {}, fingerprint: "def456" },
    { ruleId: "docs.missing-public-doc", message: "Document public exports.", filePath: "./src/docs.ts", line: 9, severity: "advisory", pillar: "documentation", secondaryPillars: [], tier: "v0.1", confidence: "medium", metadata: { exported: true }, fingerprint: "ghi789" },
  ],
  score: {
    composite: 91,
    grade: "A",
    pillars: [{ pillar: "security", score: 91, findings: 1 }],
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
  assert.equal(payload.runs[0].properties.gruffSchemaVersion, "gruff.analysis.v1");
  assert.equal(payload.runs[0].properties.generatedAt, "2026-05-15T00:00:00.000Z");
  const expectedScore = 91;
  assert.equal(payload.runs[0].properties.score, expectedScore);
  assert.equal(payload.runs[0].properties.grade, "A");
  assert.equal(JSON.parse(renderReport(report, "json")).schemaVersion, "gruff.analysis.v1");
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
  schemaVersion: "gruff.analysis.v1",
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
    pillars: [{ pillar: "documentation", score: 84, findings: 1 }],
    topOffenders: [{ filePath: "src/<bad>.ts", score: 88, findings: 1 }],
  },
};

test("html report uses dashboard parity anchors and escapes values", () => {
  const rendered = renderReport(ESCAPING_FIXTURE_REPORT, "html");

  ["paper", "masthead", "wordmark", "verdict", "grade-stamp", "pillar-grid", "offender-list", "chart-section", "finding"].forEach((anchor) => {
    assert.match(rendered, new RegExp(`class="${anchor}`));
  });
  assert.match(rendered, /gruff-ts/);
  assert.match(rendered, /ts\/js code quality/);
  assert.match(rendered, /src\/&lt;bad&gt;\.ts/);
  assert.match(rendered, /docs\.&lt;script&gt;/);
  assert.match(rendered, /Message with &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.equal(rendered.includes("0.1.0-test<script>"), false);
  assert.equal(rendered.includes("src/<bad>.ts"), false);
  assert.equal(rendered.includes("<script>alert(1)</script>"), false);
});

test("html report rendering does not mutate json report output", () => {
  const report = analyseFixture(`export function process(value: string): string {
  return value;
}
`);
  const before = renderReport(report, "json");

  renderReport(report, "html");

  assert.equal(renderReport(report, "json"), before);
  assert.match(before, /"schemaVersion": "gruff\.analysis\.v1"/);
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
