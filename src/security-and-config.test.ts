// Security, sensitive-data, config-health, and test-quality expansion tests with safe fixture values.
import assert from "node:assert/strict";
import test from "node:test";
import { analyseFixture, analyseProject, TS_IGNORE_DIRECTIVE } from "./test-fixtures.ts";

const EXPECTED_DYNAMIC_PROCESS_EXEC_LINE = 15;

test("extended type-safety rubric finds explicit unsafety without false positives", () => {
  const unsafeReport = analyseFixture(`export function unsafeApi(input: ${"any"}): ${"any"} {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as ${"unknown"} as { profile?: { name: string } };
  return user${"!"}.profile${"!"}.name;
}
`);
  const unsafeRuleIds = new Set(unsafeReport.findings.map((finding) => finding.ruleId));
  ["modernisation.ts-comment-without-rationale", "modernisation.non-null-assertion", "modernisation.double-cast", "waste.exported-any"].forEach((ruleId) => {
    assert.equal(unsafeRuleIds.has(ruleId), true, `expected ${ruleId}`);
  });

  const cleanReport = analyseFixture(`function acceptsString(value: string): string {
  return value;
}

export function safeApi(input: unknown): string {
  // ${"@ts-expect-error"} -- third-party overload rejects this documented regression fixture
  acceptsString(123);
  const user = input as { profile?: { name?: string } };
  return user.profile?.name ?? "anonymous";
}
`);
  ["modernisation.ts-comment-without-rationale", "modernisation.non-null-assertion", "modernisation.double-cast", "waste.exported-any"].forEach((ruleId) => {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  });
});

test("extended reliability rubric finds unsafe async patterns without false positives", () => {
  // Fixture covers unsafe async patterns across callbacks, floating promises, catch, and thrown strings.
  const unsafeReport = analyseFixture(`async function unreliable(userIds: string[]): Promise<void> {
  userIds.forEach(${"async"} (userId) => {
    await sendEmailAsync(userId);
  });
  ${"sendEmailAsync"}(userIds[0]);
  try {
    await sendEmailAsync("primary");
  } catch (error) {
    // FIXME
  }
  throw ${JSON.stringify("failed")};
}
`);
  const unsafeRuleIds = new Set(unsafeReport.findings.map((finding) => finding.ruleId));
  ["security.async-foreach", "security.floating-promise", "waste.swallowed-catch", "security.throw-non-error"].forEach((ruleId) => {
    assert.equal(unsafeRuleIds.has(ruleId), true, `expected ${ruleId}`);
  });

  // Fixture covers async safe cases that should avoid reliability findings.
  const cleanReport = analyseFixture(`async function reliable(userIds: string[]): Promise<void> {
  for (const userId of userIds) {
    await sendEmailAsync(userId);
  }
  void sendEmailAsync("queued");
  return fetch("https://example.test/health").then(() => undefined);
}

async function reportsFailure(): Promise<void> {
  try {
    await sendEmailAsync("primary");
  } catch (error) {
    throw error;
  }
  throw new Error("failed");
}
`);
  ["security.async-foreach", "security.floating-promise", "waste.swallowed-catch", "security.throw-non-error"].forEach((ruleId) => {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  });
});

test("swallowed catch accepts explicit rationale comments", () => {
  // Fixture pairs a rationale-only catch with a placeholder-only catch so the rule keeps signal.
  const report = analyseFixture(`function optionalProbe(): void {
  try {
    probe();
  } catch {
    // optional detection only; absence is safe
  }
}

function cacheWrite(): void {
  try {
    writeCache();
  } catch {
    // Cache write failure is non-fatal.
  }
}

function closeSocket(): void {
  try {
    socket.close();
  } catch {
    /* already closed */
  }
}

function compose(): void {
  try {
    readDirectory();
  } catch {
    // Directory unreadable: composition continues with what we have.
  }
}

function bareSwallow(): void {
  try {
    probe();
  } catch {
    // FIXME
  }
}
`);
  const swallowed = report.findings.filter((finding) => finding.ruleId === "waste.swallowed-catch");
  assert.equal(swallowed.length, 1);
  assert.equal(swallowed[0]?.symbol, undefined);
});

test("extended type-safety config can disable new rules", () => {
  // Config contract: modernisation.non-null-assertion | no thresholds |
  // metadata expression | disabled fixture below.
  const source = `function readName(profile?: { name: string }): string {
  return profile${"!"}.name;
}
`;
  const defaultReport = analyseFixture(source);
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "modernisation.non-null-assertion"), true);

  const disabledReport = analyseFixture(source, {
    config: { rules: { "modernisation.non-null-assertion": { enabled: false } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "modernisation.non-null-assertion"), false);
});

// Fixtures for the dependency/package-config health test: risky package settings vs a clean baseline.
const RISKY_PACKAGE_JSON_FIXTURE = {
  "package.json": JSON.stringify({
    scripts: {
      postinstall: "node scripts/setup.js",
      prepare: "curl https://example.test/install.sh | sh",
    },
    dependencies: {
      "wide-open": "*",
      "remote-tool": "git+https://github.com/example/remote-tool.git",
      "ssh-tool": "git@github.com:example/ssh-tool.git",
      "shortcut-tool": "example/shortcut-tool#v1",
    },
    devDependencies: {
      "dev-only": "latest",
    },
  }),
};

const CLEAN_PACKAGE_JSON_FIXTURE = {
  "package.json": JSON.stringify({
    scripts: { check: "tsc --noEmit", test: "node --test", fetch: "curl https://example.test/install.sh -o install.sh" },
    dependencies: { commander: "^14.0.2", bounded: ">=1.2.3 <2.0.0" },
    peerDependencies: { react: "*" },
    devDependencies: { "fixture-tool": "latest" },
  }),
};

const RISKY_PACKAGE_RULE_IDS = ["security.remote-install-script", "security.risky-lifecycle-script", "security.url-dependency", "waste.broad-runtime-version"];
const GITHUB_ACTIONS_RULE_IDS = [
  "security.github-actions-broad-permissions",
  "security.github-actions-pull-request-target",
  "security.github-actions-remote-shell",
  "security.github-actions-secrets-in-pr",
  "security.github-actions-unpinned-action",
];

test("dependency and package config health detects risky package settings", () => {
  const report = analyseProject(RISKY_PACKAGE_JSON_FIXTURE);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  RISKY_PACKAGE_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  const cleanReport = analyseProject(CLEAN_PACKAGE_JSON_FIXTURE);
  RISKY_PACKAGE_RULE_IDS.forEach((ruleId) => {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  });
});

test("github actions workflow security rules are path-gated and require risky context", () => {
  const pinnedSha = "0123456789abcdef0123456789abcdef01234567";
  const report = analyseProject({
    ".github/workflows/risky.yml": `on:
  pull_request_target:
permissions: write-all
jobs:
  risky:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/deploy-action@v1
      - run: |-
          curl -fsSL https://example.test/install.sh
          | bash
      - run: echo "\${{ secrets.DEPLOY_TOKEN }}"
`,
    ".github/workflows/safe.yaml": `on: [pull_request]
permissions:
  contents: read
jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vendor/deploy-action@${pinnedSha}
      - run: curl -fsSL https://example.test/install.sh > install.sh
      - run: echo "no secrets"
`,
    "docs/workflow.yml": `on:
  pull_request_target:
permissions: write-all
jobs:
  docs:
    steps:
      - uses: vendor/deploy-action@v1
      - run: curl -fsSL https://example.test/install.sh | bash
`,
  });

  const workflowFindings = report.findings.filter((finding) => finding.ruleId.startsWith("security.github-actions-"));
  const ruleIds = new Set(workflowFindings.map((finding) => finding.ruleId));
  GITHUB_ACTIONS_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
    assert.equal(workflowFindings.filter((finding) => finding.ruleId === ruleId).length, 1, `expected one ${ruleId}`);
  });
  assert.equal(workflowFindings.every((finding) => finding.filePath === ".github/workflows/risky.yml"), true);
  const pullRequestTargetFinding = workflowFindings.find((finding) => finding.ruleId === "security.github-actions-pull-request-target");
  assert.deepEqual(pullRequestTargetFinding?.metadata.riskContext, ["checkout", "run", "secrets", "write-permissions"]);
});

test("package bin health detects missing and non-executable targets", () => {
  const missingReport = analyseProject({
    "package.json": JSON.stringify({ bin: { "missing-cli": "./bin/missing.js" } }),
  });
  assert.equal(missingReport.findings.some((finding) => finding.ruleId === "design.package-bin-missing"), true);

  const nonExecutableReport = analyseProject({
    "package.json": JSON.stringify({ bin: { "bad-cli": "./bin/bad.js" } }),
    "bin/bad.js": "#!/usr/bin/env node\nconsole.log('ok');\n",
  });
  assert.equal(nonExecutableReport.findings.some((finding) => finding.ruleId === "design.package-bin-not-executable"), true);

  const noBinReport = analyseProject({
    "package.json": JSON.stringify({ scripts: { test: "node --test" } }),
  });
  assert.equal(noBinReport.findings.some((finding) => finding.ruleId.startsWith("design.package-bin-")), false);

  const executableReport = analyseProject(
    {
      "package.json": JSON.stringify({ bin: { "good-cli": "./bin/good.js" } }),
      "bin/good.js": "#!/usr/bin/env node\nconsole.log('ok');\n",
    },
    { executableFiles: ["bin/good.js"] },
  );
  assert.equal(executableReport.findings.some((finding) => finding.ruleId.startsWith("design.package-bin-")), false);
});

// Fixture covers executable security sinks while keeping noisy safe references nearby.
const SECURITY_RISKY_FIXTURE = `import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

function unsafe(userInput: string, userId: string): void {
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  window.setInterval("alert(1)", 10);
  execScript("alert(1)");
  spawn(userInput, []);
  Math.random();
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const insecureAgent = { rejectUnauthorized: false, minVersion: "TLSv1" };
  location.href = "javascript:alert(1)";
  element.dangerouslySetInnerHTML = { __html: userInput };
  element.__proto__ = {};
  element["__proto__"] = {};
  db.query("SELECT * FROM users WHERE id = " + userId);
  createHash("sha1").update(userInput);
  void insecureAgent;
}

function safe(userId: string): void {
  const docs = "new Function(userInput)";
  const urlText = "xjavascript:alert(1)";
  const urlDocs = "javascript: URL literal can execute script.";
  const protoText = "__proto__";
  const secureAgent = { rejectUnauthorized: true, minVersion: "TLSv1.2" };
  timer.setTimeout("not global code", 10);
  setTimeout(() => alert("ok"), 10);
  crypto.getRandomValues(new Uint32Array(1));
  db.query("SELECT * FROM users WHERE id = ?", [userId]);
  createHash("sha256").update(userId);
  void urlText;
  void urlDocs;
  void protoText;
  void secureAgent;
}
`;

const SECURITY_RISKY_RULE_IDS = [
  "security.new-function",
  "security.string-timer",
  "security.process-exec",
  "security.insecure-random",
  "security.disabled-tls-verification",
  "security.javascript-url",
  "security.inner-html",
  "security.proto-access",
  "security.sql-concatenation",
  "security.weak-crypto",
];

test("risk expansion finds security rules with safe non-candidates", () => {
  const report = analyseFixture(SECURITY_RISKY_FIXTURE);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  SECURITY_RISKY_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });

  const newFunctionFindings = report.findings.filter((finding) => finding.ruleId === "security.new-function");
  const expectedStringTimerFindings = 3;
  const expectedProtoAccessFindings = 2;
  assert.equal(newFunctionFindings.length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.string-timer").length, expectedStringTimerFindings);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.javascript-url").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.proto-access").length, expectedProtoAccessFindings);
});

test("process exec exempts fixed local test harnesses but reports dynamic commands", () => {
  const report = analyseProject({
    "src/harness.test.ts": `import { spawn } from "node:child_process";

const child = spawn("./bin/gruff-ts", ["summary"]);
void child;
`,
    "src/harness-shell.test.ts": `import { spawn } from "node:child_process";

const child = spawn("./bin/gruff-ts", ["summary"], { shell: true });
void child;
`,
    "src/test-fixtures.ts": `import { spawn } from "node:child_process";

export function withHarness(): void {
  const child = spawn("./bin/gruff-ts", ["dashboard"]);
  void child;
}
`,
    "src/runner.ts": `import { spawn, execFile, execSync, execFileSync, spawnSync, fork } from "node:child_process";

function run(userCommand: string): void {
  spawn(userCommand, []);
  execFile(userCommand, []);
  execSync(userCommand);
  execFileSync(userCommand, []);
  spawnSync(userCommand, []);
  fork(userCommand);
  const match = /unsafe/.exec(userCommand);
  const globalPattern = /unsafe/g;
  globalPattern["exec"](userCommand);
  void match;
}
`,
  });

  const processExecFindings = report.findings.filter((finding) => finding.ruleId === "security.process-exec");
  const expectedRunnerExecFindings = 6;
  assert.equal(processExecFindings.some((finding) => finding.filePath === "src/harness.test.ts"), false);
  assert.equal(processExecFindings.some((finding) => finding.filePath === "src/test-fixtures.ts"), false);
  assert.equal(processExecFindings.filter((finding) => finding.filePath === "src/harness-shell.test.ts").length, 1);
  assert.equal(processExecFindings.filter((finding) => finding.filePath === "src/runner.ts").length, expectedRunnerExecFindings);
});

test("process exec exempts fixed command vectors", () => {
  const report = analyseProject({
    "src/fixed-git.ts": `import { execFileSync } from "node:child_process";

function changedFiles(mode: string): void {
  const args = ["diff", "--name-only"];
  if (mode === "staged") {
    args.push("--cached");
  }
  execFileSync("git", args, { encoding: "utf8" });
}
`,
  });

  assert.equal(report.findings.some((finding) => finding.ruleId === "security.process-exec"), false);
});

test("process exec exempts multi-line fixed command vectors but keeps dynamic calls", () => {
  const expectedDynamicFindings = 1;
  const report = analyseProject({
    "src/fixed-npm.ts": `import { execFileSync, spawn } from "node:child_process";
const args = [
  "pack",
  "--dry-run",
  "--json",
  "--ignore-scripts",
];
execFileSync(
  "npm",
  args,
  {
    encoding: "utf8",
  },
);
spawn(userCommand, ["status"]);
`,
  });
  const processExecFindings = report.findings.filter((finding) => finding.ruleId === "security.process-exec");
  assert.equal(processExecFindings.length, expectedDynamicFindings);
  assert.equal(processExecFindings[0]?.line, EXPECTED_DYNAMIC_PROCESS_EXEC_LINE);
});

const SOURCE_TO_SINK_RULE_IDS = [
  "security.path-traversal-candidate",
  "security.ssrf-candidate",
  "security.open-redirect-candidate",
  "security.dynamic-regexp",
];

test("source-to-sink security rubrics require visible external input in risky sinks", () => {
  // Fixture covers every same-line source-to-sink rule plus safe literal non-candidates.
  const report = analyseFixture(`import { readFileSync } from "node:fs";

function unsafe(req: any, res: any): void {
  readFileSync(req.query.file, "utf8");
  fetch(req.body.url);
  res.redirect(req.query.next);
  new RegExp(process.argv[2]);
}

function safe(req: any, res: any): void {
  const localPath = "config.json";
  readFileSync(localPath, "utf8");
  fetch("https://example.test/health");
  res.redirect("/dashboard");
  new RegExp("^[a-z]+$");
  const docs = "fetch(req.query.url); res.redirect(req.query.next);";
  void docs;
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  SOURCE_TO_SINK_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  SOURCE_TO_SINK_RULE_IDS.forEach((ruleId) => {
    assert.equal(report.findings.filter((finding) => finding.ruleId === ruleId).length, 1, `expected one ${ruleId}`);
  });
  const pathFinding = report.findings.find((finding) => finding.ruleId === "security.path-traversal-candidate");
  assert.equal(pathFinding?.confidence, "medium");
  assert.equal(pathFinding?.metadata.sourceKind, "request");
  assert.equal(pathFinding?.metadata.sinkKind, "filesystem-path");
});

test("risk expansion finds direct modernisation and waste rules with safe non-candidates", () => {
  // Fixture covers modernization and waste detections with adjacent safe alternatives.
  const report = analyseFixture(`function risky(value: unknown, source: Record<string, string>): number {
  if (!!source.ready) {
    observe(source);
  }
  if (Boolean(source.ready)) {
    observe(source);
  }
  if (value == "1") {
    observe(source);
  }
  const timestamp = new Date().getTime();
  const copy = Object.assign({}, source);
  try {
    return timestamp + Object.keys(copy).length;
  } catch (error) {
    throw error;
  }
}

function safe(value: unknown, source: Record<string, string>): void {
  if (source.ready) {
    observe(source);
  }
  if (value == null) {
    observe(source);
  }
  const timestamp = Date.now();
  const copy = { ...source };
  void timestamp;
  void copy;
}

function finish(): void {
  doWork();
  return;
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  ["modernisation.loose-equality", "modernisation.date-now-candidate", "modernisation.object-spread-candidate", "waste.redundant-boolean-cast", "waste.useless-catch", "waste.useless-return"].forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  const expectedBooleanCastFindings = 2;
  assert.equal(report.findings.filter((finding) => finding.ruleId === "modernisation.loose-equality").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "waste.redundant-boolean-cast").length, expectedBooleanCastFindings);
});

test("risk expansion finds scoped test-quality rules", () => {
  // Fixture covers test-quality detections across assertions, mocks, global mutation, and setup bloat.
  const report = analyseFixture(`import assert from "node:assert/strict";
import test from "node:test";

test("magic assertion", () => {
  const total = calculateTotal();
  expect(total).toBe(42);
});

test("mock only", () => {
  const serviceMock = vi.fn();
  serviceMock();
  expect(serviceMock).toHaveBeenCalled();
});

test("unused mock", () => {
  const unusedMock = jest.fn();
  assert.ok(true);
});

test("exception type only", () => {
  expect(() => fail()).toThrow(Error);
});

test("global mutation", () => {
  process.env.NODE_ENV = "test";
  assert.equal(process.env.NODE_ENV, "test");
});

test("snapshot only", () => {
  expect(routeOrder("new", false)).toMatchSnapshot();
});

test("no throw only", () => {
  assert.doesNotThrow(() => routeOrder("new", false));
});

test("setup bloat", () => {
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  const four = buildFour();
  const five = buildFive();
  const six = buildSix();
  const seven = buildSeven();
  const eight = buildEight();
  const nine = buildNine();
  const ten = buildTen();
  const eleven = buildEleven();
  const twelve = buildTwelve();
  const thirteen = buildThirteen();
  expect(one).toBeDefined();
});

test("playwright expectation", async () => {
  await expect(page.locator("h1")).toHaveText("Home");
});

test("rejects expectation", async () => {
  await assert.rejects(() => fail(), Error);
});

function testBuildsLibraryValue(): void {
  expect(1).toBe(1);
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  ["test-quality.magic-number-assertion", "test-quality.mock-only-test", "test-quality.unused-mock", "test-quality.exception-type-only", "test-quality.global-state-mutation", "test-quality.setup-bloat"].forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "test-quality.no-assertions"), false);
  assert.deepEqual(report.findings.filter((finding) => finding.pillar === "test-quality" && finding.symbol === "testBuildsLibraryValue"), []);
});

test("risk expansion respects test-quality config", () => {
  // Config contract: test-quality.setup-bloat | threshold maxSetupLines |
  // default 12 | metadata setupLines,maxSetupLines | disabled and override fixtures below.
  const source = `test("compact setup", () => {
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  const four = buildFour();
  expect(one).toBeDefined();
});
`;
  const defaultReport = analyseFixture(source);
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "test-quality.setup-bloat"), false);

  const tightReport = analyseFixture(source, {
    config: { rules: { "test-quality.setup-bloat": { threshold: 3, severity: "advisory" } } },
  });
  assert.equal(tightReport.findings.some((finding) => finding.ruleId === "test-quality.setup-bloat"), true);

  const disabledReport = analyseFixture(source, {
    config: { rules: { "test-quality.setup-bloat": { enabled: false, threshold: 3, severity: "advisory" } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "test-quality.setup-bloat"), false);
});
