// FAMILY-CONTRACT.md section 13c as a user meets it: another tool's suppression comment, and one eval call under two rules.
import assert from "node:assert/strict";
import test from "node:test";

import { DUPLICATE_SUPPRESSION_REASON, INLINE_SUPPRESSION_REASON } from "./inline-suppressions.ts";
import { renderReport } from "./report-renderers.ts";
import { analyseProject } from "./test-fixtures.ts";
import type { AnalysisReport } from "./types.ts";

// Each line exercises one comment form or control; the assertions name the lines that must still report.
const RUN_SOURCE = `export function run(request: { body: string }, code: string): unknown {
  new Function(code); // eslint-disable-line no-new-func
  // eslint-disable-next-line no-new-func -- startup banner
  new Function(code);
  new Function(code);
  new Function(code); // eslint-disable-line no-alert
  // @ts-expect-error -- this control proves Gruff never honours a type-checker comment
  new Function(code);
  // biome-ignore lint/security: fixture evaluates trusted code
  eval(code);
  const same = new Function(code); // eslint-disable-line
  return eval(request.body) ?? same;
}
`;

const WORKFLOW = `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker/login-action@v3 # zizmor: ignore[unpinned-uses]
      - uses: docker/build-push-action@v6
`;

// The two uncommented siblings, the unrelated eslint rule, the type-checker comment, and the eval reported once.
const REPORTED_SECURITY = [
  ".github/workflows/ci.yml:8 security.github-actions-unpinned-action",
  "src/run.ts:5 security.new-function",
  "src/run.ts:6 security.new-function",
  "src/run.ts:8 security.new-function",
  "src/run.ts:12 security.eval-call",
];

// Scans the fixture project with its workflow folder included.
// Invariant: every call rebuilds the same two files, so both tests read identical, deterministic reports.
function analyseSection13cProject(): AnalysisReport {
  return analyseProject({ "src/run.ts": RUN_SOURCE, ".github/workflows/ci.yml": WORKFLOW }, { shouldIncludeIgnored: true });
}

test("other tools' comments suppress only the checks they name, and an eval call reports once", () => {
  const report = analyseSection13cProject();

  const reported = report.findings
    .filter((finding) => finding.ruleId.startsWith("security."))
    .map((finding) => `${finding.filePath}:${finding.line ?? 0} ${finding.ruleId}`);
  assert.deepEqual(reported, REPORTED_SECURITY);
  assert.deepEqual(
    report.suppressions.map((row) => `${row.index} ${row.source ?? "configured"} ${row.paths[0] ?? ""} ${row.rule} ${row.suppressed}`),
    [
      "0 inline .github/workflows/ci.yml security.github-actions-unpinned-action 1",
      "1 inline src/run.ts security.eval-call 1",
      "2 inline src/run.ts security.new-function 3",
      "3 duplicate src/run.ts security.unsafe-deserialization 1",
    ],
  );
  assert.deepEqual([...new Set(report.suppressions.map((row) => row.reason))], [INLINE_SUPPRESSION_REASON, DUPLICATE_SUPPRESSION_REASON]);
});

test("text and SARIF keep every section 13c removal visible", () => {
  const report = analyseSection13cProject();

  const text = renderReport(report, "text");
  assert.ok(text.includes(`inline[src/run.ts] security.new-function: 3 (${INLINE_SUPPRESSION_REASON})`), text);
  assert.ok(text.includes(`duplicate[src/run.ts] security.unsafe-deserialization: 1 (${DUPLICATE_SUPPRESSION_REASON})`), text);

  const sarif = JSON.parse(renderReport(report, "sarif")) as { runs: { results: { suppressions?: { kind: string; justification: string }[] }[] }[] };
  const justifications = (sarif.runs[0]?.results ?? []).flatMap((result) => (result.suppressions ?? []).map((suppression) => `${suppression.kind} ${suppression.justification}`));
  assert.deepEqual(justifications, [
    ...Array.from({ length: 5 }, () => `inSource ${INLINE_SUPPRESSION_REASON}`),
    `inSource ${DUPLICATE_SUPPRESSION_REASON}`,
  ]);
});
