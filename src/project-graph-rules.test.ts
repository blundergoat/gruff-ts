// Regression tests for project-level architecture graph rules: deep imports, circular imports,
// SCC grouping, root graph context, and type-only cycle suppression.
import assert from "node:assert/strict";
import test from "node:test";
import type { AnalysisReport } from "./cli.ts";
import { analyseProject } from "./test-fixtures.ts";

// Fixture covers deterministic project graph findings for deep imports and cycles; the deep path
// and two-file cycle are intentional because the fingerprint contract must stay stable across
// discovery permutations.
const CROSS_FILE_GRAPH_FIXTURE = {
  "src/app/feature/controller.ts": `import { sharedValue } from "../../../shared/value";
import { startCycle } from "../cycle/a";

export function renderController(): string {
  return sharedValue + startCycle();
}
`,
  "src/app/cycle/a.ts": `import { fromB } from "./b";

export function startCycle(): string {
  return fromB();
}
`,
  "src/app/cycle/b.ts": `import { startCycle } from "./a";

export function fromB(): string {
  return startCycle();
}
`,
  "src/shared/value.ts": `export const sharedValue = "shared";
`,
  "src/large.ts": Array.from({ length: 20 }, (_, index) => `export const largeValue${index} = ${index};`).join("\n"),
};

const CROSS_FILE_GRAPH_CONFIG = {
  rules: {
    "design.large-module-concentration": { threshold: 40, severity: "advisory", options: { minFiles: 4, minLines: 8 } },
  },
};

test("project architecture index finds deterministic cross-file findings", () => {
  const first = analyseProject(CROSS_FILE_GRAPH_FIXTURE, { config: CROSS_FILE_GRAPH_CONFIG });
  const second = analyseProject(CROSS_FILE_GRAPH_FIXTURE, { config: CROSS_FILE_GRAPH_CONFIG });
  const ruleIds = new Set(first.findings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("design.deep-relative-import"), true);
  assert.equal(ruleIds.has("design.circular-import"), true);
  assert.equal(ruleIds.has("design.large-module-concentration"), true);
  assert.deepEqual(
    first.findings
      .filter((finding) => finding.ruleId.startsWith("design."))
      .map((finding) => [finding.filePath, finding.line, finding.ruleId, finding.symbol, finding.fingerprint]),
    second.findings
      .filter((finding) => finding.ruleId.startsWith("design."))
      .map((finding) => [finding.filePath, finding.line, finding.ruleId, finding.symbol, finding.fingerprint]),
  );
});

test("circular import finding is stable across source iteration order", () => {
  const first = analyseProject({
    "src/cycle/a.ts": `import { fromB } from "./b";
export function fromA(): string {
  return fromB();
}
`,
    "src/cycle/b.ts": `import { fromA } from "./a";
export function fromB(): string {
  return fromA();
}
`,
  });
  const second = analyseProject({
    "src/cycle/b.ts": `import { fromA } from "./a";
export function fromB(): string {
  return fromA();
}
`,
    "src/cycle/a.ts": `import { fromB } from "./b";
export function fromA(): string {
  return fromB();
}
`,
  });
  const firstCycle = first.findings.find((finding) => finding.ruleId === "design.circular-import");
  const secondCycle = second.findings.find((finding) => finding.ruleId === "design.circular-import");
  assert.ok(firstCycle);
  assert.ok(secondCycle);
  assert.deepEqual(
    [firstCycle.filePath, firstCycle.line, firstCycle.symbol, firstCycle.fingerprint],
    [secondCycle.filePath, secondCycle.line, secondCycle.symbol, secondCycle.fingerprint],
  );
});

const MULTI_CYCLE_SCC_FIXTURE = {
  "src/charts/index.ts": `export { AreaChart } from "./AreaChart";
export { BarChart } from "./BarChart";
`,
  "src/charts/AreaChart.ts": `import { BarChart } from "./index";
export function AreaChart(): string {
  return BarChart();
}
`,
  "src/charts/BarChart.ts": `import { AreaChart } from "./index";
export function BarChart(): string {
  return AreaChart();
}
`,
};

test("circular import groups a multi-cycle SCC into one canonical finding", () => {
  const cycles = circularImportFindings(analyseProject(MULTI_CYCLE_SCC_FIXTURE));
  assert.equal(cycles.length, 1);

  const [cycle] = cycles;
  assert.ok(cycle);
  assert.equal(cycle.filePath, "src/charts/AreaChart.ts");
  assert.equal(cycle.line, 1);
  assert.equal(cycle.symbol, "src/charts/AreaChart.ts -> src/charts/BarChart.ts -> src/charts/index.ts");
  assert.deepEqual(cycle.metadata.files, ["src/charts/AreaChart.ts", "src/charts/BarChart.ts", "src/charts/index.ts"]);
  assert.deepEqual(cycle.metadata.representativeCycle, ["src/charts/AreaChart.ts", "src/charts/index.ts", "src/charts/AreaChart.ts"]);
});

test("circular import reports independent SCCs separately", () => {
  const cycles = circularImportFindings(
    analyseProject({
      "src/alpha/a.ts": `import { fromB } from "./b";
export function fromA(): string {
  return fromB();
}
`,
      "src/alpha/b.ts": `import { fromA } from "./a";
export function fromB(): string {
  return fromA();
}
`,
      "src/beta/c.ts": `import { fromD } from "./d";
export function fromC(): string {
  return fromD();
}
`,
      "src/beta/d.ts": `import { fromC } from "./c";
export function fromD(): string {
  return fromC();
}
`,
    }),
  );

  assert.equal(cycles.length, 2);
  assert.deepEqual(cycles.map((finding) => finding.metadata.files), [
    ["src/alpha/a.ts", "src/alpha/b.ts"],
    ["src/beta/c.ts", "src/beta/d.ts"],
  ]);
});

test("narrow circular import run uses root graph context without widening analysed files", () => {
  const report = analyseProject(
    {
      "src/cycle/a.ts": `import { fromB } from "./sub/b";
export function fromA(): string {
  return fromB();
}
`,
      "src/cycle/sub/b.ts": `import { fromA } from "../a";
export function fromB(): string {
  return fromA();
}
`,
      "src/unrequested/deep.ts": `import { helper } from "../../../shared/helper";
export const value = helper;
`,
      "shared/helper.ts": `export const helper = "helper";
`,
    },
    { paths: ["src/cycle/sub/b.ts"] },
  );
  const cycles = circularImportFindings(report);

  assert.equal(report.paths.analysedFiles, 1);
  assert.equal(cycles.length, 1);
  assert.equal(cycles[0]?.filePath, "src/cycle/a.ts");
  assert.deepEqual(cycles[0]?.metadata.files, ["src/cycle/a.ts", "src/cycle/sub/b.ts"]);
  assert.equal(report.findings.some((finding) => finding.ruleId === "design.deep-relative-import" && finding.filePath === "src/unrequested/deep.ts"), false);
});

test("changed-region diff keeps a cycle through a changed member and suppresses unrelated cycles", () => {
  // Fixture covers project-relationship changed-region attribution: the diff touches only the
  // alpha cycle's non-anchor member, so that cycle must stay visible while the untouched beta
  // cycle is suppressed into `suppressedCount`.
  const report = analyseProject(
    {
      "src/alpha/a.ts": `import { fromB } from "./b";
export function fromA(): string {
  return fromB();
}
`,
      "src/alpha/b.ts": `import { fromA } from "./a";
export function fromB(): string {
  return fromA();
}
`,
      "src/beta/c.ts": `import { fromD } from "./d";
export function fromC(): string {
  return fromD();
}
`,
      "src/beta/d.ts": `import { fromC } from "./c";
export function fromD(): string {
  return fromC();
}
`,
    },
    {
      diff: "-",
      diffPatch: [
        "diff --git a/src/alpha/b.ts b/src/alpha/b.ts",
        "--- a/src/alpha/b.ts",
        "+++ b/src/alpha/b.ts",
        "@@ -2 +2 @@",
        "+export function fromB(): string {",
        "",
      ].join("\n"),
    },
  );
  const cycles = circularImportFindings(report);

  assert.equal(cycles.length, 1);
  assert.equal(cycles[0]?.filePath, "src/alpha/a.ts");
  assert.deepEqual(cycles[0]?.metadata.files, ["src/alpha/a.ts", "src/alpha/b.ts"]);
  assert.equal((report.suppressedCount ?? 0) > 0, true);
});

test("disabled circular import rule emits no cycle finding", () => {
  const report = analyseProject(
    {
      "src/cycle/a.ts": `import { fromB } from "./b";
export function fromA(): string {
  return fromB();
}
`,
      "src/cycle/b.ts": `import { fromA } from "./a";
export function fromB(): string {
  return fromA();
}
`,
    },
    { config: { rules: { "design.circular-import": { enabled: false } } } },
  );

  assert.equal(report.findings.some((finding) => finding.ruleId === "design.circular-import"), false);
});

test("project graph ignores type-only import cycles", () => {
  const report = analyseProject({
    "src/types/a.ts": `import type { B } from "./b";
export interface A {
  b: B;
}
`,
    "src/types/b.ts": `import type { A } from "./a";
export interface B {
  a: A;
}
`,
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "design.circular-import"), false);
});

/** Contract helper that returns only circular-import findings from the supplied report. */
function circularImportFindings(report: AnalysisReport): AnalysisReport["findings"] {
  return report.findings.filter((finding) => finding.ruleId === "design.circular-import");
}
