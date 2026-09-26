/*
 * Pins the behaviours the ratified family scoring contract fixes.
 *
 * The cross-port scoring conformance suite proves the same properties for all five ports at once,
 * but it runs from the specification repository and needs every port built. These tests fail here,
 * in gruff-ts's own gate, the moment one of them breaks.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { makeFinding } from "./findings.ts";
import { scoreReport } from "./scoring.ts";
import type { Confidence, Finding, Pillar, Severity } from "./types.ts";

// Evaluated-file denominator every fixture scores against; ten keeps the derived numbers legible.
const EVALUATED_FILES = 10;
// The ratified severity weights, restated so an expectation reads as arithmetic rather than a constant.
const ADVISORY_WEIGHT = 1;
const WARNING_WEIGHT = 4;
// Low confidence halves a finding's weight; high leaves it whole.
const LOW_CONFIDENCE_FACTOR = 0.5;
const MEDIUM_CONFIDENCE_FACTOR = 0.75;
// A reachable pillar that reported nothing scores exactly this.
const CLEAN_PILLAR_SCORE = 100;
// The curve's half-way point: weight 1 over ten files is density 0.10, which is DENSITY_SCALE.
const HALF_WAY_SCORE = 75;

/**
 * Builds one finding with an explicit weight and symbol so a test can state what it expects.
 *
 * Invariant: the returned finding always carries the severity and confidence the caller asked for,
 * and omits `symbol` entirely rather than setting it undefined, which `exactOptionalPropertyTypes`
 * rejects.
 */
function contractFinding(
  ruleId: string,
  pillar: Pillar,
  severity: Severity,
  options: { confidence?: Confidence; filePath?: string; symbol?: string; line?: number } = {},
): Finding {
  return makeFinding({
    ruleId,
    message: `${ruleId} fired.`,
    filePath: options.filePath ?? "src/a.ts",
    line: options.line ?? 1,
    severity,
    pillar,
    confidence: options.confidence ?? "high",
    ...(options.symbol === undefined ? {} : { symbol: options.symbol }),
  });
}

// Reads one published pillar row, failing the test rather than returning undefined.
function pillarRow(score: ReturnType<typeof scoreReport>, pillar: Pillar) {
  const row = score.pillars.find((entry) => entry.pillar === pillar);
  assert.ok(row, `pillar ${pillar} absent from the published set`);
  return row;
}

// Reads one published pillar's score, failing the test when the pillar evaluated nothing.
function pillarScore(score: ReturnType<typeof scoreReport>, pillar: Pillar): number {
  const pillarValue = pillarRow(score, pillar).score;
  assert.notEqual(pillarValue, null, `pillar ${pillar} has no score`);
  return pillarValue as number;
}

// Reads the composite, failing the test when the run evaluated nothing.
function compositeScore(score: ReturnType<typeof scoreReport>): number {
  assert.notEqual(score.composite, null, "run has no composite");
  return score.composite as number;
}

test("scale is not an automatic penalty", () => {
  // Duplication doubles the findings and the evaluated files together, so the density they make is
  // unchanged and the grade must not move. The retired absolute-sum shape failed this: a fourfold
  // duplication of identical code cost gruff-ts nearly seven composite points.
  const single = [contractFinding("naming.one", "naming", "warning", { filePath: "src/a.ts" })];
  const doubled = [...single, contractFinding("naming.one", "naming", "warning", { filePath: "src/b.ts" })];
  const quadrupled = [
    ...doubled,
    contractFinding("naming.one", "naming", "warning", { filePath: "src/c.ts" }),
    contractFinding("naming.one", "naming", "warning", { filePath: "src/d.ts" }),
  ];

  const base = compositeScore(scoreReport(single, EVALUATED_FILES));

  assert.equal(compositeScore(scoreReport(doubled, EVALUATED_FILES * 2)), base);
  assert.equal(compositeScore(scoreReport(quadrupled, EVALUATED_FILES * 4)), base);
});

test("monotonicity holds at a fixed denominator", () => {
  const before = scoreReport([contractFinding("security.one", "security", "warning")], EVALUATED_FILES);
  const after = scoreReport(
    [contractFinding("security.one", "security", "warning"), contractFinding("security.two", "security", "error")],
    EVALUATED_FILES,
  );

  assert.ok(pillarScore(after, "security") < pillarScore(before, "security"));
  assert.ok(compositeScore(after) < compositeScore(before));
  // A pillar that gained no finding must not move, or the composite couples unrelated areas.
  assert.equal(pillarScore(after, "documentation"), pillarScore(before, "documentation"));
});

test("applicability keeps null apart from perfect", () => {
  const clean = scoreReport([], EVALUATED_FILES);
  for (const pillar of clean.pillars) {
    assert.equal(pillar.applicable, true, `pillar ${pillar.pillar} is not applicable`);
    assert.equal(pillar.score, CLEAN_PILLAR_SCORE, `reachable clean pillar ${pillar.pillar}`);
  }

  const nothing = scoreReport([], 0);
  assert.equal(nothing.composite, null);
  assert.equal(nothing.grade, null);
  // The denominator is still published, so a reader can see that nothing was evaluated.
  assert.equal(nothing.evaluatedFiles, 0);
  assert.ok(nothing.pillars.every((pillar) => pillar.score === null));
});

test("serialization rounds to two decimals", () => {
  // One high-confidence advisory weighs ADVISORY_WEIGHT over ten files: density 0.10, which is the
  // curve's half-way point between the floor and 100.
  const score = scoreReport([contractFinding("naming.one", "naming", "advisory")], EVALUATED_FILES);

  assert.equal(pillarScore(score, "naming"), HALF_WAY_SCORE);
  assert.equal(pillarRow(score, "naming").penalty, ADVISORY_WEIGHT);

  const composite = compositeScore(score);
  assert.equal(Math.round(composite * 100) / 100, composite, "composite carries more than two decimals");
});

test("clustering keys on symbol without line identity", () => {
  // Correlated rules disagree about which line to report, so a line in the cluster key would split
  // one root cause into two and bill it twice.
  const shared = scoreReport(
    [
      contractFinding("size.function-length", "size", "warning", { symbol: "run", line: 1 }),
      contractFinding("complexity.cyclomatic", "complexity", "warning", { symbol: "run", line: 9 }),
    ],
    EVALUATED_FILES,
  );
  // The cluster bills its single worst member once, shared across the two findings in it.
  const sharePerMember = WARNING_WEIGHT / 2;

  assert.equal(pillarRow(shared, "size").penalty, sharePerMember);
  assert.equal(pillarRow(shared, "complexity").penalty, sharePerMember);
  assert.equal(shared.clusters.length, 1);

  const cluster = shared.clusters[0];
  assert.ok(cluster, "one cluster published");
  assert.equal(cluster.findings, 2);
  assert.equal(cluster.weight, WARNING_WEIGHT);
  assert.deepEqual(cluster.ruleIds, ["complexity.cyclomatic", "size.function-length"]);

  const distinct = scoreReport(
    [
      contractFinding("size.function-length", "size", "warning", { symbol: "run", line: 1 }),
      contractFinding("complexity.cyclomatic", "complexity", "warning", { symbol: "walk", line: 9 }),
    ],
    EVALUATED_FILES,
  );
  assert.deepEqual(distinct.clusters, []);
});

test("rule attribution is keyed by native ruleId", () => {
  const score = scoreReport(
    [
      contractFinding("naming.b-rule", "naming", "advisory"),
      contractFinding("naming.a-rule", "naming", "warning", { confidence: "medium" }),
      contractFinding("naming.a-rule", "naming", "warning", { confidence: "medium", filePath: "src/b.ts" }),
    ],
    EVALUATED_FILES,
  );

  assert.deepEqual(
    score.ruleAttribution.map((row) => row.ruleId),
    ["naming.a-rule", "naming.b-rule"],
  );

  const first = score.ruleAttribution[0];
  const second = score.ruleAttribution[1];
  assert.ok(first && second, "one row per native rule");
  assert.equal(first.findings, 2);
  assert.equal(first.weight, 2 * WARNING_WEIGHT * MEDIUM_CONFIDENCE_FACTOR);
  assert.equal(second.findings, 1);
  assert.equal(second.weight, ADVISORY_WEIGHT);
});

test("confidence weights the density, which gruff-ts never did before M06", () => {
  // Before the break gruff-ts had no confidence dimension: a low-confidence heuristic weighed
  // exactly as much as a certain defect, so a noisy rule could drag a pillar as hard as a real one.
  const high = scoreReport([contractFinding("naming.one", "naming", "warning", { confidence: "high" })], EVALUATED_FILES);
  const low = scoreReport([contractFinding("naming.one", "naming", "warning", { confidence: "low" })], EVALUATED_FILES);

  assert.ok(pillarScore(low, "naming") > pillarScore(high, "naming"));
  assert.equal(pillarRow(low, "naming").penalty, WARNING_WEIGHT * LOW_CONFIDENCE_FACTOR);
  assert.equal(pillarRow(high, "naming").penalty, WARNING_WEIGHT);
});

test("the published denominator and pillar set let a reader recompute the composite", () => {
  const evaluatedFiles = 7;
  const score = scoreReport([contractFinding("naming.one", "naming", "warning")], evaluatedFiles);

  assert.equal(score.evaluatedFiles, evaluatedFiles);
  assert.equal(score.pillars.length, score.scoredPillars.length);

  const applicable = score.pillars.flatMap((pillar) => (pillar.score === null ? [] : [pillar.score]));
  const mean = applicable.reduce((sum, pillarValue) => sum + pillarValue, 0) / applicable.length;

  assert.equal(Math.round(mean * 100) / 100, compositeScore(score));
});
