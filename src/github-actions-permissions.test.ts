// GitHub Actions secrets-in-pr fixtures: which event guards make a secret reference unreachable from a
// pull request, and which ones still report it.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseProject } from "./test-fixtures.ts";

// Warning ordering and fingerprints remain unchanged; only own PR-unreachable references become quiet.
const secret = "${{ secrets.DEPLOY_TOKEN }}";
const EVENT_GUARD_CASES: Array<[string, boolean]> = [
  ["github.event_name == 'issues'", false],
  ["github.event_name != 'pull_request_target'", false],
  ["${{ !(github.event_name == 'pull_request_target') }}", false],
  ["(github.event_name == 'push' || github.event_name == 'issues')", false],
  ["github.event_name == 'issues' && inputs.enabled", false],
  ["inputs.enabled && github.event_name == 'issues'", false],
  ["github.event_name == 'PULL_REQUEST_TARGET'", true],
  ["github.event_name == 'pull_request_target'", true],
  ["github.event_name != 'issues'", true],
  ["inputs.enabled", true],
  ["github.event_name == 'issues' || inputs.enabled", true],
  ["${{ github.event_name == 'issues' }} trailing", true],
  ["github.event_name == 'issues' trailing", true],
  ["github.event_name == 'issues' &&", true],
  ["github.event_name == 'issues' && contains(inputs.x, 'x')", true],
  ["github.event_name == 0", true],
  ["!github.event_name == 'issues'", true],
];
for (const [condition, reports] of EVENT_GUARD_CASES) {
  test("complete event guard: " + condition, () => {
    const report = analyseProject({
      ".github/workflows/guard.yml": `on: [pull_request_target, issues]\njobs:\n  build:\n    if: ${condition}\n    steps:\n      - run: echo "${secret}"\n`,
    });
    assert.equal(report.findings.some((finding) => finding.ruleId === "security.github-actions-secrets-in-pr"), reports);
  });
}

const GUARD_OWNERSHIP_CASES: Array<[string, number]> = [
  [`jobs:\n  build:\n    steps:\n      - run: echo ${secret}\n    if: github.event_name == 'issues'`, 0],
  [`'jobs':\n  'build':\n    'steps':\n      - 'run': echo ${secret}\n        'if': github.event_name == 'issues'`, 0],
  [`jobs:\n  build:\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ${secret}`, 0],
  [`jobs:\n  build:\n    steps:\n      - run: |\n          if: github.event_name == 'issues'\n          echo ${secret}`, 1],
  [`jobs:\n  build:\n    steps:\n      - run: |\n          echo ${secret}\n        if: github.event_name == 'issues'`, 0],
  [`env:\n  TOKEN: ${secret}\njobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ready`, 1],
  [`jobs:\n  build:\n    env:\n      TOKEN: ${secret}\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ready`, 1],
  [`jobs:\n  safe:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ready\n  build:\n    steps:\n      - run: echo ${secret}`, 1],
  [`jobs:\n  build:\n    steps:\n      - if: github.event_name == 'issues'\n        run: echo ready\n      - run: echo ${secret}`, 1],
  [`jobs:\n  build:\n    steps:\n      - run: echo ${secret}\n        with:\n          if: github.event_name == 'issues'`, 1],
  [`jobs:\n  build:\n    if: github.event_name == 'issues'\n    if: inputs.enabled\n    steps:\n      - run: echo ${secret}`, 1],
  [`jobs:\n  build:\n    if: github.event_name == 'issues'\n    steps:\n      - run: echo ${secret}\n  build:\n    steps:\n      - run: echo ready`, 1],
  [`jobs:\n  build:\n    if: github.event_name == 'issues'\n    env: &shared\n      TOKEN: ${secret}\n    steps:\n      - run: echo ready`, 1],
  [`jobs:\n  build:\n    if: github.event_name == 'issues'\n    <<: *shared\n    steps:\n      - run: echo ${secret}`, 1],
  [`jobs: {build: {if: "github.event_name == 'issues'", env: {VALUE: ${secret}}}}`, 1],
  [`jobs:\n  build:\n    if: github.event_name == 'issues'\n    env:\n      TOKEN: ${secret}\n    steps:\n      - *shared`, 1],
];
for (const [body, expected] of GUARD_OWNERSHIP_CASES) {
  test("own workflow guard: " + body, () => {
    const report = analyseProject({ ".github/workflows/guard.yml": `on:\n  pull_request_target:\n${body}\n` });
    assert.equal(report.findings.filter((finding) => finding.ruleId === "security.github-actions-secrets-in-pr").length, expected);
  });
}

test("secrets-in-pr reads the on: key and reports only pull_request_target, never GITHUB_TOKEN", () => {
  const job = "jobs:\n  build:\n    steps:\n      - run: echo \"${{ secrets.DEPLOY_TOKEN }}\"\n      - run: echo \"${{ secrets.GITHUB_TOKEN }}\"\n";
  const report = analyseProject({
    ".github/workflows/target-scalar.yml": `on: pull_request_target\n${job}`,
    ".github/workflows/target-flow.yml": `on: [push, pull_request_target]\n${job}`,
    ".github/workflows/target-mapping.yml": `"on":\n  "pull_request_target":\n    branches: [main]\n${job}`,
    ".github/workflows/plain-pr.yml": `on:\n  pull_request:\n${job}`,
    ".github/workflows/comment.yml": `on: issue_comment\n${job.replace("steps:", "if: github.event.issue.pull_request\n    steps:")}`,
  });

  assert.deepEqual(
    report.findings
      .filter((finding) => finding.ruleId === "security.github-actions-secrets-in-pr")
      .map((finding) => `${finding.filePath}:${finding.symbol}`)
      .sort(),
    [
      ".github/workflows/target-flow.yml:DEPLOY_TOKEN",
      ".github/workflows/target-mapping.yml:DEPLOY_TOKEN",
      ".github/workflows/target-scalar.yml:DEPLOY_TOKEN",
    ],
  );
});
