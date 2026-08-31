// Markdown report safety tests for repository-controlled paths, symbols, and messages.
// These fixtures model what reviewers see when Markdown output is pasted into a pull request.
// They pin safe structure and ordinary readability without changing machine-report contracts.
import assert from "node:assert/strict";
import test from "node:test";
import { renderReport } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";

const MARKDOWN_SAFETY_REPORT: AnalysisReport = {
  schemaVersion: "gruff.analysis.v3",
  tool: { name: "gruff-ts", version: "0.5.0-test" },
  run: { projectRoot: "/tmp/markdown-project", format: "markdown", failOn: "none", generatedAt: "2026-07-12T00:00:00.000Z" },
  summary: { advisory: 1, warning: 2, error: 0, total: 3 },
  paths: { analysedFiles: 2, ignoredPaths: [], skipped: [], missingPaths: [] },
  diagnostics: [],
  suppressions: [],
  findings: [
    {
      ruleId: "docs.rule`label",
      message: "Read [guide](https://example.test) <img src=x> `snippet` | **bold** _italic_\n## injected heading",
      filePath: "src/[guide]|<tag>`name`.ts",
      line: 7,
      severity: "advisory",
      pillar: "documentation",
      secondaryPillars: [],
      tier: "v0.1",
      confidence: "high",
      metadata: {},
      fingerprint: "markdown-finding",
      stableIdentity: "markdown-finding-stable",
    },
    {
      ruleId: "complexity.cognitive",
      message: "Function has cognitive complexity 18.",
      filePath: "src/cluster`path.ts",
      line: 11,
      severity: "warning",
      pillar: "complexity",
      secondaryPillars: [],
      tier: "v0.1",
      confidence: "high",
      symbol: "run``unsafe|<node>[x]",
      metadata: {},
      fingerprint: "markdown-cognitive",
      stableIdentity: "markdown-cognitive-stable",
    },
    {
      ruleId: "complexity.cyclomatic",
      message: "Function has cyclomatic complexity 17.",
      filePath: "src/cluster`path.ts",
      line: 11,
      severity: "warning",
      pillar: "complexity",
      secondaryPillars: [],
      tier: "v0.1",
      confidence: "high",
      symbol: "run``unsafe|<node>[x]",
      metadata: {},
      fingerprint: "markdown-cyclomatic",
      stableIdentity: "markdown-cyclomatic-stable",
    },
  ],
  score: {
    composite: 82,
    grade: "B",
    pillars: [
      { pillar: "complexity", score: 70, penalty: 30, findings: 2 },
      { pillar: "documentation", score: 94, penalty: 6, findings: 1 },
    ],
    topOffenders: [{ filePath: "src/cluster`path.ts", score: 70, findings: 2 }],
  },
};

// A pull-request reviewer must see one finding row, not injected links, HTML, or headings.
test("markdown finding rows escape repository-controlled structure", () => {
  const markdownReport = renderReport(MARKDOWN_SAFETY_REPORT, "markdown");
  const expectedFindingRow = "- ``docs.rule`label`` ``src/[guide]|<tag>`name`.ts``:7 - Read \\[guide\\](https://example.test) &lt;img src=x&gt; \\`snippet\\` \\| \\*\\*bold\\*\\* \\_italic\\_ \\#\\# injected heading";

  assert.equal(markdownReport.includes(expectedFindingRow), true);
  assert.equal(markdownReport.includes("<img src=x>"), false);
  assert.equal(markdownReport.includes("\n## injected heading"), false);

  // A hostile finding must not change the seven columns a reviewer sees in the Pillars table.
  const markdownTableRows = markdownReport.split("\n").filter((line) => line.startsWith("| "));
  const tablePipeCounts = markdownTableRows.map((line) => [...line.matchAll(/\|/g)].length);
  assert.deepEqual([...new Set(tablePipeCounts)], [8]);
});

// A complexity label with longer backtick runs must remain one readable inline-code span.
test("markdown complexity clusters choose a safe inline-code fence", () => {
  const markdownReport = renderReport(MARKDOWN_SAFETY_REPORT, "markdown");
  const expectedClusterRow = "- ```src/cluster`path.ts#run``unsafe|<node>[x]```: 2 linked findings (`complexity.cognitive`, `complexity.cyclomatic`)";

  assert.equal(markdownReport.includes(expectedClusterRow), true);
});

// Ordinary paths stay compact for reviewers, and rendering Markdown must not mutate JSON output.
test("markdown escaping keeps ordinary finding rows readable", () => {
  // An accidentally empty safety fixture should fail clearly before building the ordinary control.
  const [repositoryControlledFinding] = MARKDOWN_SAFETY_REPORT.findings;
  assert.ok(repositoryControlledFinding);
  const ordinaryReport: AnalysisReport = {
    ...MARKDOWN_SAFETY_REPORT,
    summary: { advisory: 1, warning: 0, error: 0, total: 1 },
    findings: [
      {
        ...repositoryControlledFinding,
        ruleId: "docs.missing-internal-function-doc",
        message: "Document this function for reviewers.",
        filePath: "src/ordinary.ts",
      },
    ],
  };
  const jsonBeforeMarkdown = renderReport(ordinaryReport, "json");
  const markdownReport = renderReport(ordinaryReport, "markdown");

  assert.equal(markdownReport.includes("- `docs.missing-internal-function-doc` `src/ordinary.ts`:7 - Document this function for reviewers."), true);
  assert.equal(renderReport(ordinaryReport, "json"), jsonBeforeMarkdown);
});
