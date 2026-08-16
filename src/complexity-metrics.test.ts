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
  const report = analyseFixture(
    `/** Builds cards displayed in the search results panel. */
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
`,
    {
      fileName: "result-cards.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 99 },
          "complexity.cognitive": { threshold: 2 },
        },
      },
    },
  );

  const falseNesting = report.findings.filter((finding) => finding.ruleId === "complexity.cognitive" || finding.ruleId === "docs.missing-why-for-complex-code");
  assert.deepEqual(falseNesting, []);
});

// Stable fixture contract: a flat switch counts only its non-default choices.
test("flat switch complexity follows the non-default case policy", () => {
  const report = analyseFixture(
    `function routePanel(panel: string): string {
  switch (panel) {
    case "account":
      return "account";
    case "billing":
      return "billing";
    default:
      return "home";
  }
}
`,
    {
      fileName: "panel-router.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 2 },
          "complexity.cognitive": { threshold: 3 },
        },
      },
    },
  );

  const cyclomatic = report.findings.find((finding) => finding.ruleId === "complexity.cyclomatic");
  const cognitive = report.findings.find((finding) => finding.ruleId === "complexity.cognitive");
  assert.deepEqual(
    { cyclomatic: cyclomatic?.metadata, cognitive: cognitive?.metadata },
    {
      cyclomatic: { complexity: 3, threshold: 2, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, case: 2, maxNesting: 1 } },
      cognitive: { complexity: 4, threshold: 3, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, case: 2, maxNesting: 1 } },
    },
  );
});

// Stable fixture contract: ternary and logical nodes count while optional and nullish nodes do not.
test("ternary and logical operators count without optional or nullish inflation", () => {
  const report = analyseFixture(
    `function visibleStatus(
  account: { active?: boolean; label?: string } | undefined,
  hasBackup: boolean,
  fallback: string,
): string {
  return ((account?.active && hasBackup) || (account?.label ?? fallback)) ? "visible" : "hidden";
}
`,
    {
      fileName: "visible-status.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 3 },
          "complexity.cognitive": { threshold: 4 },
        },
      },
    },
  );

  const cyclomatic = report.findings.find((finding) => finding.ruleId === "complexity.cyclomatic");
  const cognitive = report.findings.find((finding) => finding.ruleId === "complexity.cognitive");
  assert.deepEqual(
    { cyclomatic: cyclomatic?.metadata, cognitive: cognitive?.metadata },
    {
      cyclomatic: { complexity: 4, threshold: 3, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, ternary: 1, logicalAnd: 1, logicalOr: 1, maxNesting: 1 } },
      cognitive: { complexity: 5, threshold: 4, breakdown: { ...EMPTY_COMPLEXITY_BREAKDOWN, ternary: 1, logicalAnd: 1, logicalOr: 1, maxNesting: 1 } },
    },
  );
});

// Stable fixture contract: an unenumerated callback remains owned by its nearest reported function.
test("anonymous callback decisions contribute to the named owner", () => {
  const report = analyseFixture(
    `function visibleItemLabels(items: Array<{ isVisible: boolean; label?: string }>): string[] {
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
`,
    {
      fileName: "item-labels.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 3 },
          "complexity.cognitive": { threshold: 4 },
        },
      },
    },
  );

  const ownerFindings = report.findings.filter((finding) => finding.symbol === "visibleItemLabels" && finding.ruleId.startsWith("complexity."));
  assert.deepEqual(
    ownerFindings.map((finding) => [finding.ruleId, finding.metadata.complexity]),
    [
      ["complexity.cognitive", 5],
      ["complexity.cyclomatic", 4],
    ],
  );
});

// Stable fixture contract: genuine branching preserves its report measurements and identity tuple.
test("nested branching retains findings, documentation pressure, and identity", () => {
  const report = analyseFixture(
    `/** Routes the first visible result into the report panel. */
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
`,
    {
      fileName: "nested-routing.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 3, severity: "advisory" },
          "complexity.cognitive": { threshold: 6, severity: "error" },
        },
      },
    },
  );

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
      ruleId: "complexity.cognitive",
      filePath: "nested-routing.ts",
      line: 1,
      symbol: "routeVisibleResult",
      severity: "error",
      complexity: 7,
      fingerprint: "77bebc0d6c0c8009",
      stableIdentity: "87f4743c33d7be44",
    },
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
});

// Stable fixture contract: branch-shaped prose and literals remain inert during a CLI scan.
test("branch tokens in comments strings and regular expressions stay inert", () => {
  const report = analyseFixture(
    `function branchVocabulary(): string {
  // Words such as if, for, case, and catch explain a help screen.
  const helpText = "if (ready) { for (;;) { switch (value) { case 1: } } }";
  const helpPattern = /if|for|while|catch|case|\\?\\?|&&|\\|\\|/;
  return helpPattern.test(helpText) ? "matched" : "unmatched";
}
`,
    {
      fileName: "branch-vocabulary.ts",
      config: {
        rules: {
          "complexity.cyclomatic": { threshold: 2 },
          "complexity.cognitive": { threshold: 3 },
        },
      },
    },
  );

  const complexityFindings = report.findings.filter((finding) => finding.ruleId.startsWith("complexity."));
  assert.deepEqual(complexityFindings, []);
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
    cyclomatic: 13,
    cognitive: 14,
    maximumControlFlowNesting: 1,
    breakdown: {
      if: 1,
      loop: 5,
      catch: 1,
      case: 2,
      ternary: 1,
      logicalAnd: 1,
      logicalOr: 1,
      maxNesting: 1,
    },
  });
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
      declared: [2, 3, 1],
      constructor: [2, 3, 1],
      render: [2, 3, 1],
      choose: [3, 5, 2],
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
