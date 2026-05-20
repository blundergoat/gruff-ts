import assert from "node:assert/strict";
import test from "node:test";
import { renderReport } from "./cli.ts";
import {
  analyseFixture,
  analyseProject,
  API_TOKEN_FIXTURE_VALUE,
  DATABASE_URL_FIXTURE_VALUE,
  OPENAI_KEY_FIXTURE_VALUE,
  SSN_FIXTURE_VALUE,
  TS_IGNORE_DIRECTIVE,
} from "./test-fixtures.ts";

test("extended type-safety rubric finds explicit unsafety without false positives", () => {
  const unsafeReport = analyseFixture(`export function unsafeApi(input: ${"any"}): ${"any"} {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as ${"unknown"} as { profile?: { name: string } };
  return user${"!"}.profile${"!"}.name;
}
`);
  const unsafeRuleIds = new Set(unsafeReport.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "modernisation.ts-comment-without-rationale",
    "modernisation.non-null-assertion",
    "modernisation.double-cast",
    "waste.exported-any",
  ]) {
    assert.equal(unsafeRuleIds.has(ruleId), true, `expected ${ruleId}`);
  }

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
  for (const ruleId of [
    "modernisation.ts-comment-without-rationale",
    "modernisation.non-null-assertion",
    "modernisation.double-cast",
    "waste.exported-any",
  ]) {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  }
});

test("extended reliability rubric finds unsafe async patterns without false positives", () => {
  const unsafeReport = analyseFixture(`async function unreliable(userIds: string[]): Promise<void> {
  userIds.forEach(${"async"} (userId) => {
    await sendEmailAsync(userId);
  });
  ${"sendEmailAsync"}(userIds[0]);
  try {
    await sendEmailAsync("primary");
  } catch (error) {
    // ignored
  }
  throw ${JSON.stringify("failed")};
}
`);
  const unsafeRuleIds = new Set(unsafeReport.findings.map((finding) => finding.ruleId));
  for (const ruleId of ["security.async-foreach", "security.floating-promise", "waste.swallowed-catch", "security.throw-non-error"]) {
    assert.equal(unsafeRuleIds.has(ruleId), true, `expected ${ruleId}`);
  }

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
  for (const ruleId of ["security.async-foreach", "security.floating-promise", "waste.swallowed-catch", "security.throw-non-error"]) {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  }
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

test("dependency and package config health detects risky package settings", () => {
  const report = analyseProject({
    "package.json": JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js",
        prepare: "curl https://example.test/install.sh | sh",
      },
      dependencies: {
        "wide-open": "*",
        "remote-tool": "git+https://github.com/example/remote-tool.git",
      },
      devDependencies: {
        "dev-only": "latest",
      },
    }),
  });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of ["security.remote-install-script", "security.risky-lifecycle-script", "security.url-dependency", "waste.broad-runtime-version"]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  const cleanReport = analyseProject({
    "package.json": JSON.stringify({
      scripts: { check: "tsc --noEmit", test: "node --test" },
      dependencies: { commander: "^14.0.2" },
      devDependencies: { "fixture-tool": "latest" },
    }),
  });
  for (const ruleId of ["security.remote-install-script", "security.risky-lifecycle-script", "security.url-dependency", "waste.broad-runtime-version"]) {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  }
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

test("tsconfig health detects disabled strictness without changing diagnostics", () => {
  const report = analyseProject({
    "tsconfig.json": JSON.stringify({
      compilerOptions: {
        strict: false,
        noUncheckedIndexedAccess: false,
        exactOptionalPropertyTypes: false,
      },
    }),
  });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "modernisation.tsconfig-strict-disabled",
    "modernisation.tsconfig-index-safety-disabled",
    "modernisation.tsconfig-exact-optional-disabled",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  const cleanReport = analyseProject({
    "tsconfig.json": JSON.stringify({
      compilerOptions: {
        strict: true,
        noUncheckedIndexedAccess: true,
        exactOptionalPropertyTypes: true,
      },
    }),
  });
  for (const ruleId of [
    "modernisation.tsconfig-strict-disabled",
    "modernisation.tsconfig-index-safety-disabled",
    "modernisation.tsconfig-exact-optional-disabled",
  ]) {
    assert.equal(cleanReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  }

  const malformedReport = analyseProject({ "package.json": "{ not json" });
  assert.deepEqual(malformedReport.diagnostics, []);
});

test("risk expansion redacts sensitive data in all render formats", () => {
  const apiToken = API_TOKEN_FIXTURE_VALUE;
  const databaseUrl = DATABASE_URL_FIXTURE_VALUE;
  const openAiKey = OPENAI_KEY_FIXTURE_VALUE;
  const ssn = SSN_FIXTURE_VALUE;
  const report = analyseFixture(
    `API_TOKEN=${apiToken}
DATABASE_URL=${databaseUrl}
OPENAI_API_KEY=${openAiKey}
PATIENT_SSN=${ssn}
`,
    { fileName: ".env" },
  );

  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "sensitive-data.hardcoded-env-value",
    "sensitive-data.api-key-pattern",
    "sensitive-data.database-url-password",
    "sensitive-data.pii-pattern",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  for (const format of ["text", "json", "markdown", "github", "html", "sarif"] as const) {
    const rendered = renderReport(report, format);
    for (const secret of [apiToken, databaseUrl, openAiKey, ssn]) {
      assert.equal(rendered.includes(secret), false, `${format} leaked ${secret}`);
    }
    assert.match(rendered, /redacted/);
  }
});

test("risk expansion respects sensitive-data config", () => {
  // Config contract: sensitive-data.hardcoded-env-value | threshold minLength |
  // default 16 | metadata keyName,preview,length | disabled and override fixtures below.
  const source = `API_TOKEN=qR8vT3mK6pL9xS2nD4eG
`;
  const defaultReport = analyseFixture(source, { fileName: ".env" });
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), true);

  const disabledReport = analyseFixture(source, {
    fileName: ".env",
    config: { rules: { "sensitive-data.hardcoded-env-value": { enabled: false } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), false);

  const thresholdReport = analyseFixture(source, {
    fileName: ".env",
    config: { rules: { "sensitive-data.hardcoded-env-value": { threshold: 40, severity: "error" } } },
  });
  assert.equal(thresholdReport.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), false);
});

test("risk expansion ignores package integrity hashes", () => {
  const report = analyseFixture(
    `{
  "packages": {
    "": {
      "integrity": "sha512-Zx7pQ9vLm3N8sT2rY6wK1dF4gH5jC0bR2mN5pQ8sR1tV4xY7zA0bC3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW3xY6zA9bC2dE5fG8h=="
    }
  }
}
`,
    { fileName: "package-lock.json" },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string"), false);
});

test("risk expansion finds security rules with safe non-candidates", () => {
  const report = analyseFixture(`import { createHash } from "node:crypto";
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
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
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
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  const newFunctionFindings = report.findings.filter((finding) => finding.ruleId === "security.new-function");
  assert.equal(newFunctionFindings.length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.string-timer").length, 3);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.javascript-url").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "security.proto-access").length, 2);
});

test("process exec exempts fixed local test harnesses but reports dynamic commands", () => {
  const report = analyseProject({
    "src/harness.test.ts": `import { spawn } from "node:child_process";

const child = spawn("./bin/gruff-ts", ["summary"]);
void child;
`,
    "src/runner.ts": `import { spawn, execFile } from "node:child_process";

function run(userCommand: string): void {
  spawn(userCommand, []);
  execFile(userCommand, []);
}
`,
  });

  const processExecFindings = report.findings.filter((finding) => finding.ruleId === "security.process-exec");
  assert.equal(processExecFindings.some((finding) => finding.filePath === "src/harness.test.ts"), false);
  assert.equal(processExecFindings.filter((finding) => finding.filePath === "src/runner.ts").length, 2);
});

test("risk expansion finds direct modernisation and waste rules with safe non-candidates", () => {
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
  for (const ruleId of [
    "modernisation.loose-equality",
    "modernisation.date-now-candidate",
    "modernisation.object-spread-candidate",
    "waste.redundant-boolean-cast",
    "waste.useless-catch",
    "waste.useless-return",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
  assert.equal(report.findings.filter((finding) => finding.ruleId === "modernisation.loose-equality").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "waste.redundant-boolean-cast").length, 2);
});

test("risk expansion finds scoped test-quality rules", () => {
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
  for (const ruleId of [
    "test-quality.magic-number-assertion",
    "test-quality.mock-only-test",
    "test-quality.unused-mock",
    "test-quality.exception-type-only",
    "test-quality.global-state-mutation",
    "test-quality.setup-bloat",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
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
