// Focused M06 regression coverage for rule-gradient refinements that span multiple rule modules.
import assert from "node:assert/strict";
import test from "node:test";

import { renderReport } from "./cli.ts";
import { scoreReport } from "./scoring.ts";
import { analyseFixture } from "./test-fixtures.ts";
import type { AnalysisReport, Finding } from "./types.ts";

const CLUSTER_FINDINGS: Finding[] = [
  clusterFinding("complexity.cognitive"),
  clusterFinding("complexity.cyclomatic"),
  clusterFinding("design.god-function", "design"),
  clusterFinding("size.function-length", "size"),
];
const FULL_SCORE = 100;
const WARNING_PENALTY = 4;
const CLUSTERED_SINGLE_PENALTY = WARNING_PENALTY / CLUSTER_FINDINGS.length;
const CLUSTERED_COMPLEXITY_PENALTY = CLUSTERED_SINGLE_PENALTY * 2;
const EXPECTED_CLUSTER_FILE_SCORE = FULL_SCORE - WARNING_PENALTY;
const EXPECTED_CLUSTER_COMPOSITE_SCORE = (FULL_SCORE - CLUSTERED_COMPLEXITY_PENALTY + (FULL_SCORE - CLUSTERED_SINGLE_PENALTY) * 2) / 3;
const SEPARATE_COMPLEXITY_SCORE = FULL_SCORE - WARNING_PENALTY * 2;

const COMPLEXITY_CLUSTER_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v2",
  tool: { name: "gruff-ts", version: "0.3.0-test" },
  run: { projectRoot: "/tmp/project", format: "text", failOn: "none", generatedAt: "2026-05-31T00:00:00.000Z" },
  summary: { advisory: 0, warning: CLUSTER_FINDINGS.length, error: 0, total: CLUSTER_FINDINGS.length },
  paths: { analysedFiles: 1, ignoredPaths: [], skipped: [], missingPaths: [] },
  diagnostics: [],
  findings: CLUSTER_FINDINGS,
  score: {
    composite: EXPECTED_CLUSTER_FILE_SCORE,
    grade: "A",
    pillars: [
      { pillar: "complexity", score: 98, penalty: 2, findings: 2 },
      { pillar: "design", score: 99, penalty: 1, findings: 1 },
      { pillar: "size", score: 99, penalty: 1, findings: 1 },
    ],
    topOffenders: [{ filePath: "bad.ts", score: EXPECTED_CLUSTER_FILE_SCORE, findings: CLUSTER_FINDINGS.length }],
  },
};

test("M06 waste.empty-function accepts documented test double methods only in tests", () => {
  const testReport = analyseFixture(
    `class FakeTerminal {
  clear(): void {
    /* intentional no-op: interface contract for test double */
  }
}
`,
    { fileName: "test/unit/dashboard-terminal.test.ts" },
  );
  assert.equal(testReport.findings.some((entry) => entry.ruleId === "waste.empty-function" && entry.symbol === "clear"), false);

  const sourceReport = analyseFixture(`class FakeTerminal {
  clear(): void {
    /* intentional no-op: interface contract for test double */
  }
}
`);
  assert.equal(sourceReport.findings.some((entry) => entry.ruleId === "waste.empty-function" && entry.symbol === "clear"), true);
});

test("M06 modernisation.double-cast marks rationale-backed trust boundaries", () => {
  const report = analyseFixture(`interface ParsedConfig {
  ok: boolean;
}

function parseConfig(input: unknown): ParsedConfig {
  const parsed = input as unknown as ParsedConfig; // trust boundary: schema validated upstream
  const copied = input as unknown as ParsedConfig;
  return parsed.ok ? parsed : copied;
}
`);
  const findings = report.findings.filter((entry) => entry.ruleId === "modernisation.double-cast");
  assert.deepEqual(
    findings.map((entry) => ({ severity: entry.severity, rationale: entry.metadata.rationale })),
    [
      { severity: "advisory", rationale: "trust-boundary" },
      { severity: "warning", rationale: undefined },
    ],
  );
});

test("M06 text reports correlated complexity cluster contract without changing JSON score shape", () => {
  const text = renderReport(COMPLEXITY_CLUSTER_REPORT, "text");
  assert.match(text, /Correlated complexity clusters:/);
  assert.match(text, /bad\.ts#tangled: \d linked findings/);

  const json = JSON.parse(renderReport(COMPLEXITY_CLUSTER_REPORT, "json"));
  assert.deepEqual(Object.keys(json.score).sort(), ["composite", "grade", "pillars", "topOffenders"]);
  assert.equal(json.score.composite, EXPECTED_CLUSTER_FILE_SCORE);
});

test("M06 score contract clusters correlated complexity penalties by symbol", () => {
  const score = scoreReport(CLUSTER_FINDINGS);

  assert.equal(score.topOffenders[0]?.findings, CLUSTER_FINDINGS.length);
  assert.equal(score.topOffenders[0]?.score, EXPECTED_CLUSTER_FILE_SCORE);
  assert.equal(score.composite, EXPECTED_CLUSTER_COMPOSITE_SCORE);
  assert.deepEqual(
    score.pillars.map((pillar) => ({ pillar: pillar.pillar, penalty: pillar.penalty, findings: pillar.findings })).sort((left, right) => left.pillar.localeCompare(right.pillar)),
    [
      { pillar: "complexity", penalty: CLUSTERED_COMPLEXITY_PENALTY, findings: 2 },
      { pillar: "design", penalty: CLUSTERED_SINGLE_PENALTY, findings: 1 },
      { pillar: "size", penalty: CLUSTERED_SINGLE_PENALTY, findings: 1 },
    ],
  );
});

test("M06 score contract keeps different-symbol complexity penalties separate", () => {
  const score = scoreReport([
    clusterFinding("complexity.cognitive", "complexity", "first"),
    clusterFinding("complexity.cyclomatic", "complexity", "second"),
  ]);

  assert.equal(score.pillars[0]?.penalty, WARNING_PENALTY * 2);
  assert.equal(score.topOffenders[0]?.score, SEPARATE_COMPLEXITY_SCORE);
});

// Invariant: report and score fixtures share one stable clustered finding shape.
function clusterFinding(ruleId: string, pillar: Finding["pillar"] = "complexity", symbol = "tangled"): Finding {
  return {
    ruleId,
    message: `${ruleId} fired.`,
    filePath: "bad.ts",
    line: 12,
    severity: "warning",
    pillar,
    secondaryPillars: [],
    tier: "v0.1",
    confidence: "high",
    symbol,
    metadata: {},
    fingerprint: `${ruleId}:bad:${symbol}`,
  };
}
