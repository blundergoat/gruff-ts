// Consumer-equivalent fixtures for the complexity values shown in findings and JSON metadata.
// Each scan exercises a source shape a CLI user can submit, including false-positive regressions
// and retained branching whose report anchors must not move during the syntax-aware migration.
import assert from "node:assert/strict";
import test from "node:test";

import { functionBlocks } from "./blocks.ts";
import { parseScript } from "./parsed-script.ts";
import { maskNonCode } from "./source-text.ts";
import { analyseFixture } from "./test-fixtures.ts";

const EMPTY_COMPLEXITY_BREAKDOWN = {
  if: 0,
  loop: 0,
  catch: 0,
  case: 0,
  ternary: 0,
  logicalAnd: 0,
  logicalOr: 0,
  maxNesting: 0,
};

// Linear defaults and safe property reads must not ask a reviewer to explain nonexistent branches.
test("nullish defaults and optional chains stay at base complexity", () => {
  const report = analyseFixture(
    `/** Builds the labels displayed in an account panel. */
function visibleAccountLabels(settings?: {
  account?: { name?: string; email?: string };
  team?: { name?: string; owner?: string };
}): string[] {
  return [
    settings?.account?.name ?? "",
    settings?.account?.email ?? "",
    settings?.team?.name ?? "",
    settings?.team?.owner ?? "",
    settings?.account?.name ?? "",
    settings?.account?.email ?? "",
    settings?.team?.name ?? "",
    settings?.team?.owner ?? "",
  ];
}
`,
    { fileName: "account-labels.ts" },
  );

  const falseComplexity = report.findings.filter((finding) => finding.ruleId.startsWith("complexity.") || finding.ruleId === "docs.missing-why-for-complex-code");
  assert.deepEqual(falseComplexity, []);
});

// Stable fixture contract: nested presentation objects and callback braces add no decision paths.
test("object literals and callback braces do not add control-flow nesting", () => {
  const source = `/** Builds cards displayed in the search results panel. */
function resultCards(items: Array<{ title: string }>): unknown[] {
  return items.map((item) => ({
    title: item.title,
    appearance: {
      border: {
        width: 1,
      },
    },
  }));
}
`;
  const report = analyseFixture(source, {
    fileName: "result-cards.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 99 },
      },
    },
  });

  const falseNesting = report.findings.filter((finding) => finding.ruleId === "docs.missing-why-for-complex-code");
  assert.deepEqual(falseNesting, []);
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "resultCards"), [1, 1, 0]);
});

// Stable fixture contract: a flat switch is one decision however many non-default choices it has.
test("a flat switch counts as one decision", () => {
  const source = `function routePanel(panel: string): string {
  switch (panel) {
    case "account":
      return "account";
    case "billing":
      return "billing";
    default:
      return "home";
  }
}
`;
  const report = analyseFixture(source, {
    fileName: "panel-router.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 1 },
      },
    },
  });

  const cyclomatic = report.findings.find((finding) => finding.ruleId === "complexity.cyclomatic");
  assert.deepEqual(
    { cyclomatic: cyclomatic?.metadata },
    {
      cyclomatic: { complexity: 2, threshold: 1, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, case: 1, maxNesting: 1 }, limitBand: "upper" },
    },
  );
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "routePanel"), [2, 3, 1]);
});

// Stable fixture contract: ternary and logical nodes count while optional and nullish nodes do not.
test("ternary and logical operators count without optional or nullish inflation", () => {
  const source = `function visibleStatus(
  account: { active?: boolean; label?: string } | undefined,
  hasBackup: boolean,
  fallback: string,
): string {
  return ((account?.active && hasBackup) || (account?.label ?? fallback)) ? "visible" : "hidden";
}
`;
  const report = analyseFixture(source, {
    fileName: "visible-status.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 3 },
      },
    },
  });

  const cyclomatic = report.findings.find((finding) => finding.ruleId === "complexity.cyclomatic");
  assert.deepEqual(
    { cyclomatic: cyclomatic?.metadata },
    {
      cyclomatic: { complexity: 4, threshold: 3, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, ternary: 1, logicalAnd: 1, logicalOr: 1, maxNesting: 1 }, limitBand: "lower" },
    },
  );
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "visibleStatus"), [4, 5, 1]);
});

// Stable fixture contract: an unenumerated callback remains owned by its nearest reported function.
test("anonymous callback decisions contribute to the named owner", () => {
  const source = `function visibleItemLabels(items: Array<{ isVisible: boolean; label?: string }>): string[] {
  return items.map((item) => {
    if (item.isVisible && item.label) {
      return item.label;
    }
    if (item.isVisible) {
      return "untitled";
    }
    return "hidden";
  });
}
`;
  const report = analyseFixture(source, {
    fileName: "item-labels.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 3 },
      },
    },
  });

  const ownerFindings = report.findings.filter((finding) => finding.symbol === "visibleItemLabels" && finding.ruleId.startsWith("complexity."));
  assert.deepEqual(
    ownerFindings.map((finding) => [finding.ruleId, finding.metadata.complexity]),
    // Both callback ifs are early-exit guards, so they add decisions but no nesting.
    [["complexity.cyclomatic", 4]],
  );
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "visibleItemLabels"), [4, 4, 0]);
});

// Stable fixture contract: genuine branching preserves its report measurements and identity tuple.
test("nested branching retains findings, documentation pressure, and identity", () => {
  const source = `/** Routes the first visible result into the report panel. */
function routeVisibleResult(results: string[], isReady: boolean): string {
  if (isReady) {
    for (const result of results) {
      if (result.length > 0) {
        return result;
      }
    }
  }
  return "empty";
}
`;
  const report = analyseFixture(source, {
    fileName: "nested-routing.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 3, severity: "advisory" },
      },
    },
  });

  const retainedFindings = report.findings
    .filter((finding) => finding.ruleId.startsWith("complexity.") || finding.ruleId === "docs.missing-why-for-complex-code")
    .map((finding) => ({
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      line: finding.line,
      symbol: finding.symbol,
      severity: finding.severity,
      complexity: finding.metadata.complexity,
      fingerprint: finding.fingerprint,
      stableIdentity: finding.stableIdentity,
    }));
  assert.deepEqual(retainedFindings, [
    {
      ruleId: "complexity.cyclomatic",
      filePath: "nested-routing.ts",
      line: 1,
      symbol: "routeVisibleResult",
      severity: "advisory",
      complexity: 4,
      fingerprint: "32407ab7e194ecfe",
      stableIdentity: "49e0f9ef064a32f0",
    },
    {
      ruleId: "docs.missing-why-for-complex-code",
      filePath: "nested-routing.ts",
      line: 1,
      symbol: "routeVisibleResult",
      severity: "advisory",
      complexity: undefined,
      fingerprint: "5337383dcb4b5b42",
      stableIdentity: "b4d40522be965aa8",
    },
  ]);
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "routeVisibleResult"), [4, 6, 2]);
});

// Stable fixture contract: branch-shaped prose and literals remain inert during a CLI scan.
test("branch tokens in comments strings and regular expressions stay inert", () => {
  const source = `function branchVocabulary(): string {
  // Words such as if, for, case, and catch explain a help screen.
  const helpText = "if (ready) { for (;;) { switch (value) { case 1: } } }";
  const helpPattern = /if|for|while|catch|case|\\?\\?|&&|\\|\\|/;
  return helpPattern.test(helpText) ? "matched" : "unmatched";
}
`;
  const report = analyseFixture(source, {
    fileName: "branch-vocabulary.ts",
    config: {
      rules: {
        "complexity.cyclomatic": { enabled: true, threshold: 2 },
      },
    },
  });

  const complexityFindings = report.findings.filter((finding) => finding.ruleId.startsWith("complexity."));
  assert.deepEqual(complexityFindings, []);
  // The cognitive metric still sets the documentation gate, so its value stays pinned on the parsed block.
  assert.deepEqual(metricTupleFor(parsedFixtureBlocks(source), "branchVocabulary"), [2, 3, 1]);
});

// Stable fixture contract: every decision counts once, including the catch recover path.
test("shared metrics expose the complete counting-policy breakdown", () => {
  const blocks = parsedFixtureBlocks(`function allDecisions(
  values: string[],
  flags: Record<string, boolean> & { mode: string; left: boolean; right?: boolean },
): boolean {
  if (flags.ready) {
    observe(flags.ready);
  }
  for (let index = 0; index < 1; index += 1) {
    observe(index);
  }
  for (const key in flags) {
    observe(key);
  }
  for (const value of values) {
    observe(value);
  }
  while (flags.waiting) {
    break;
  }
  do {
    observe(flags.retry);
  } while (flags.retry);
  try {
    observe(flags.ready);
  } catch {
    observe(flags.retry);
  }
  switch (flags.mode) {
    case "left":
      return true;
    case "right":
      return false;
    default:
      observe(flags.mode);
  }
  return flags.ready ? flags.left && flags.ready : flags.left || (flags.right ?? false);
}
`);
  const metrics = blocks.find((block) => block.name === "allDecisions")?.complexityMetrics;

  assert.deepEqual(metrics, {
    cyclomatic: 12,
    cognitive: 13,
    maximumControlFlowNesting: 1,
    breakdown: {
      if: 1,
      loop: 5,
      catch: 1,
      case: 1,
      ternary: 1,
      logicalAnd: 1,
      logicalOr: 1,
      maxNesting: 1,
    },
  });
});

// Stable fixture contract: an early-exit guard adds its decision but no nesting; any other if still nests.
test("an early-exit guard adds no nesting level", () => {
  const blocks = parsedFixtureBlocks(`function guarded(items: number[]): number {
  for (const item of items) {
    if (item < 0) continue;
    if (item === 0) {
      return 0;
    }
  }
  return 1;
}

function nested(items: number[]): number {
  for (const item of items) {
    if (item > 0) {
      record(item);
    }
  }
  return 1;
}
`);
  const guarded = blocks.find((block) => block.name === "guarded")?.complexityMetrics;
  const nested = blocks.find((block) => block.name === "nested")?.complexityMetrics;

  assert.deepEqual([guarded?.cyclomatic, guarded?.maximumControlFlowNesting, guarded?.cognitive], [4, 1, 5]);
  assert.deepEqual([nested?.cyclomatic, nested?.maximumControlFlowNesting, nested?.cognitive], [3, 2, 5]);
});

// Every callable shape receives its own node, while a nested reported child is pruned from its parent.
test("callable ownership covers every shared-parse block shape", () => {
  const blocks = parsedFixtureBlocks(`function declared(isReady: boolean): void {
  if (isReady) return;
}

class Panel {
  constructor(isReady: boolean) {
    if (isReady) observe(isReady);
  }

  render(items: string[]): void {
    while (items.length > 0) break;
  }
}

const panelActions = {
  choose(isReady: boolean): string {
    for (const option of ["open"]) {
      if (isReady) return option;
    }
    return "closed";
  },
};

const arrow = (isReady: boolean): string => isReady ? "ready" : "waiting";

const recover = function (isReady: boolean): boolean {
  try {
    return isReady;
  } catch {
    return false;
  }
};

test("shows panel", () => {
  if (panelActions) observe(panelActions);
});

interface PanelContract {
  show(isReady: boolean): void;
}

function parent(isReady: boolean): void {
  if (isReady) observe(isReady);
  function child(hasFirst: boolean, hasSecond: boolean): void {
    if (hasFirst) observe(hasFirst);
    if (hasSecond) observe(hasSecond);
  }
  child(isReady, isReady);
}
`);

  assert.deepEqual(
    Object.fromEntries([
      "declared",
      "constructor",
      "render",
      "choose",
      "arrow",
      "recover",
      "shows panel",
      "show",
      "parent",
      "child",
    ].map((blockName) => [blockName, metricTupleFor(blocks, blockName)])),
    {
      declared: [2, 2, 0],
      constructor: [2, 3, 1],
      render: [2, 3, 1],
      choose: [3, 4, 1],
      arrow: [2, 3, 1],
      recover: [2, 3, 1],
      "shows panel": [2, 3, 1],
      show: [1, 1, 0],
      parent: [2, 3, 1],
      child: [3, 4, 1],
    },
  );
});

/**
 * Parses one TypeScript fixture through the shared boundary used by a normal CLI scan.
 * @param source Fixture source; an empty string yields no callable blocks.
 * @returns Discovered blocks with syntax metrics, or an empty array when source has no callables.
 */
function parsedFixtureBlocks(source: string) {
  const parsed = parseScript({ displayPath: "complexity-fixture.ts", isScript: true }, source);
  // A `.ts` fixture must produce the shared parse; undefined would bypass the behavior under test.
  assert.ok(parsed);
  return functionBlocks(source, maskNonCode(source), parsed);
}

/**
 * Selects the three headline values a report user compares across callable shapes.
 * @param blocks Parsed fixture blocks shown by the analyser.
 * @param blockName Reported symbol to select; an empty name cannot match a stable block.
 * @returns Cyclomatic, cognitive, and max nesting, or undefined when discovery/metrics are missing.
 */
function metricTupleFor(blocks: ReturnType<typeof parsedFixtureBlocks>, blockName: string): [number, number, number] | undefined {
  const metrics = blocks.find((block) => block.name === blockName)?.complexityMetrics;
  // An absent tuple tells the assertion that callable discovery or metric ownership failed.
  if (!metrics) {
    return undefined;
  }
  return [metrics.cyclomatic, metrics.cognitive, metrics.maximumControlFlowNesting];
}
