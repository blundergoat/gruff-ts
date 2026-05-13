import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse, renderReport } from "./cli.ts";

const expandedRuleIds = new Set([
  "complexity.npath",
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.stale-param-tag",
  "docs.useless-docblock",
  "modernisation.nullish-coalescing-candidate",
  "modernisation.optional-chaining-candidate",
  "modernisation.readonly-property-candidate",
  "naming.boolean-prefix",
  "naming.class-file-mismatch",
  "naming.hungarian-notation",
  "naming.identifier-quality",
  "security.disabled-tls-verification",
  "security.insecure-random",
  "security.new-function",
  "security.sql-concatenation",
  "security.string-timer",
  "security.weak-crypto",
  "sensitive-data.api-key-pattern",
  "sensitive-data.hardcoded-env-value",
  "sensitive-data.high-entropy-string",
  "sensitive-data.pii-pattern",
  "test-quality.exception-type-only",
  "test-quality.global-state-mutation",
  "test-quality.magic-number-assertion",
  "test-quality.mock-only-test",
  "test-quality.setup-bloat",
  "test-quality.trivial-assertion",
  "test-quality.unused-mock",
  "waste.commented-out-code",
  "waste.empty-function",
  "waste.redundant-variable",
  "waste.unused-import",
  "waste.unused-parameter",
]);

test("analysis finds core TypeScript smells", () => {
  const report = analyseFixture(`export class Bad {
  public name = "demo";
  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string): void {
    if (a) {
      eval(c);
    }
    console.log(b, d, e, f);
  }
}

test("sleeps without assertion", async () => {
  await new Promise((resolve) => setTimeout(resolve, 1));
});
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("security.eval-call"), true);
  assert.equal(ruleIds.has("size.parameter-count"), true);
  assert.equal(ruleIds.has("test-quality.no-assertions"), true);
  assert.equal(ruleIds.has("modernisation.public-property"), true);
});

test("existing core fixture fingerprints stay stable", () => {
  const report = analyseFixture(`export class Bad {
  public name = "demo";
  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string): void {
    if (a) {
      eval(c);
    }
    console.log(b, d, e, f);
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

test("analysis finds first-slice portable TypeScript rules", () => {
  const secret = "Zx7pQ9vLm3N8sT2rY6wK1dF4gH5jC0bR2";
  // M01 portable rubric map: port-now rules use source-text, line, function-block,
  // test-block, and sensitive-data seams with standalone TypeScript fixtures.
  const report = analyseFixture(`import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const data1 = "placeholder";
const embeddedToken = "${secret}";

// const legacyPassword = loadSecret();
function hashPassword(password: string): string {
  return createHash("md5").update(password).digest("hex");
}

test("trivial assertion", () => {
  assert.equal(1, 1);
});

function testBuildsValue(): void {
  assert.equal("not a test", "not a test");
}
`);
  const firstSliceRuleIds = new Set([
    "waste.commented-out-code",
    "naming.identifier-quality",
    "test-quality.trivial-assertion",
    "security.weak-crypto",
    "sensitive-data.high-entropy-string",
  ]);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of firstSliceRuleIds) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  const firstSliceFindings = report.findings.filter((finding) => firstSliceRuleIds.has(finding.ruleId));
  assert.equal(new Set(firstSliceFindings.map((finding) => finding.fingerprint)).size, firstSliceFindings.length);

  const helperTestFindings = report.findings.filter((finding) => finding.pillar === "test-quality" && finding.symbol === "testBuildsValue");
  assert.deepEqual(helperTestFindings, []);

  const secretFinding = report.findings.find((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
  assert.notEqual(secretFinding, undefined);
  assert.equal(secretFinding?.message.includes(secret), false);
  assert.equal(JSON.stringify(secretFinding?.metadata).includes(secret), false);
  assert.match(JSON.stringify(secretFinding?.metadata), /redacted/);
  assert.equal(renderReport(report, "json").includes(secret), false);
});

test("core expansion clean fixture avoids new M02 findings", () => {
  const report = analyseFixture(
    `/** UserProfile stores profile state. */
export class UserProfile {
  public readonly displayName: string;

  public constructor(displayName: string) {
    this.displayName = displayName;
  }

  public getName(account?: { profile?: { name?: string } }, fallbackName?: string): string {
    return account?.profile?.name ?? fallbackName ?? this.displayName;
  }
}

/**
 * Formats a display name.
 * @param displayName Name to format.
 * @returns The formatted display name.
 */
export function formatDisplayName(displayName: string): string {
  return displayName.trim();
}

function combineNames(primaryName: string, secondaryName: string): string {
  return primaryName + secondaryName;
}

function normalizeStatus(status: string): string {
  try {
    if (status.length > 10) {
      return "long";
    }
    switch (status) {
      case "ready":
        return "ready";
      default:
        return status.trim();
    }
  } catch (error) {
    return String(error);
  }
}
`,
    { fileName: "UserProfile.ts" },
  );
  const m02RuleIds = new Set([
    "complexity.npath",
    "waste.commented-out-code",
    "waste.empty-function",
    "waste.redundant-variable",
    "waste.unused-import",
    "waste.unused-parameter",
    "naming.identifier-quality",
    "naming.boolean-prefix",
    "naming.hungarian-notation",
    "naming.class-file-mismatch",
    "docs.stale-param-tag",
    "docs.missing-param-tag",
    "docs.missing-return-tag",
    "docs.useless-docblock",
    "modernisation.readonly-property-candidate",
    "modernisation.optional-chaining-candidate",
    "modernisation.nullish-coalescing-candidate",
  ]);
  const unexpected = report.findings.filter((finding) => m02RuleIds.has(finding.ruleId));
  assert.deepEqual(unexpected, []);
});

test("core expansion finds complexity and waste rules", () => {
  const report = analyseFixture(`import { readFileSync, writeFileSync } from "node:fs";

const loadedText = readFileSync("input.txt", "utf8");

function routeOrder(state: string, unusedFlag: boolean): string {
  if (state === "new") {
    return "new";
  }
  if (state === "paid") {
    return "paid";
  }
  if (state === "sent") {
    return "sent";
  }
  if (state === "closed") {
    return "closed";
  }
  if (loadedText.length > 0) {
    return loadedText;
  }
  return "unknown";
}

// const disabledCache = loadCache();
function emptyWork(): void {}

function redundantResult(): string {
  const calculatedResult = routeOrder("new", true);
  return calculatedResult;
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "complexity.npath",
    "waste.commented-out-code",
    "waste.empty-function",
    "waste.redundant-variable",
    "waste.unused-import",
    "waste.unused-parameter",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
  const npathFinding = report.findings.find((finding) => finding.ruleId === "complexity.npath");
  assert.match(npathFinding?.message ?? "", /capped at/);
  assert.equal(typeof npathFinding?.metadata.npath, "number");
});

test("core expansion respects npath config", () => {
  // Config contract: complexity.npath | thresholds warn/error | defaults 20/80 |
  // metadata npath,capped,cap | disabled and override fixtures below.
  const source = `function branchLightly(input: string): string {
  if (input === "a") {
    return "a";
  }
  if (input === "b") {
    return "b";
  }
  return "c";
}
`;
  const defaultReport = analyseFixture(source);
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "complexity.npath"), false);

  const tightReport = analyseFixture(source, {
    config: { rules: { "complexity.npath": { thresholds: { warn: 3, error: 6 } } } },
  });
  assert.equal(tightReport.findings.some((finding) => finding.ruleId === "complexity.npath"), true);

  const disabledReport = analyseFixture(source, {
    config: { rules: { "complexity.npath": { enabled: false, thresholds: { warn: 1, error: 2 } } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "complexity.npath"), false);
});

test("loads default gruff yaml config", () => {
  const report = analyseProject(
    {
      "bad.ts": `function branchLightly(input: string): string {
  if (input === "a") {
    return "a";
  }
  if (input === "b") {
    return "b";
  }
  return "c";
}
`,
      ".gruff.yaml": `
rules:
  "complexity.npath":
    thresholds:
      warn: 3
      error: 6
`,
    },
    { noConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "complexity.npath"), true);
});

test("loads default gruff yml config", () => {
  const report = analyseProject(
    {
      "bad.ts": `const xy = 1;
console.log(xy);
`,
      ".gruff.yml": `
allowlists:
  acceptedAbbreviations: [xy]
`,
    },
    { noConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "naming.short-variable"), false);
});

test("loads explicit yaml config path", () => {
  const report = analyseProject(
    {
      "bad.ts": `eval("console.log(1)");
`,
      "custom-gruff.yaml": `
rules:
  security.eval-call:
    enabled: false
`,
    },
    { configPath: "custom-gruff.yaml" },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
});

test("prefers default gruff json config over yaml", () => {
  const report = analyseProject(
    {
      "bad.ts": `eval("console.log(1)");
`,
      ".gruff.json": JSON.stringify({ rules: { "security.eval-call": { enabled: false } } }),
      ".gruff.yaml": `
rules:
  security.eval-call:
    enabled: true
`,
    },
    { noConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
});

test("core expansion finds naming and documentation rules", () => {
  const report = analyseFixture(
    `/** CustomerProfile stores customer data. */
export class CustomerRecord {
  public active = true;
}

const strName = "Ada";
const objUser = { name: strName };

/**
 * Calculates score.
 * @param amount Amount to score.
 * @param stale Removed parameter.
 */
export function calculateScore(amount: number, label: string): number {
  return amount + label.length + objUser.name.length;
}

/** updateName */
export function updateName(name: string): string {
  return name;
}
`,
    { fileName: "CustomerProfile.ts" },
  );
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "naming.boolean-prefix",
    "naming.hungarian-notation",
    "naming.class-file-mismatch",
    "docs.stale-param-tag",
    "docs.missing-param-tag",
    "docs.missing-return-tag",
    "docs.useless-docblock",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
});

test("core expansion finds modernisation rules", () => {
  const report = analyseFixture(`class AccountReader {
  public displayName: string;

  public constructor(displayName: string) {
    this.displayName = displayName;
  }

  public read(profile?: { name?: string }, fallbackName?: string): string {
    const displayName = fallbackName || "anonymous";
    if (profile && profile.name) {
      return profile.name;
    }
    return displayName;
  }
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "modernisation.readonly-property-candidate",
    "modernisation.optional-chaining-candidate",
    "modernisation.nullish-coalescing-candidate",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
});

test("parse diagnostics ignore delimiter-looking text in literals", () => {
  const report = analyseFixture(`const closer = "}";
const opener = "{";
const pattern = /[})]/;
/*
}
(
*/
function ok(value: string): string {
  return pattern.test(value) ? closer : opener;
}
`);
  assert.deepEqual(report.diagnostics, []);
});

test("risk expansion redacts sensitive data in all render formats", () => {
  const apiToken = "rN7pQ4sV9xY2zA5bC8dG9hK2mN5pQ8sR1";
  const databaseUrl = "postgres://app:superSecretPassword@db.internal/app";
  const openAiKey = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890";
  const ssn = "123-45-6789";
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

  for (const format of ["text", "json", "markdown", "github", "html"] as const) {
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
    config: { rules: { "sensitive-data.hardcoded-env-value": { thresholds: { minLength: 40 } } } },
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

function unsafe(userInput: string, userId: string): void {
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  Math.random();
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  db.query("SELECT * FROM users WHERE id = " + userId);
  createHash("sha1").update(userInput);
}

function safe(userId: string): void {
  const docs = "new Function(userInput)";
  setTimeout(() => alert("ok"), 10);
  crypto.getRandomValues(new Uint32Array(1));
  db.query("SELECT * FROM users WHERE id = ?", [userId]);
  createHash("sha256").update(userId);
}
`);
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of [
    "security.new-function",
    "security.string-timer",
    "security.insecure-random",
    "security.disabled-tls-verification",
    "security.sql-concatenation",
    "security.weak-crypto",
  ]) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }

  const newFunctionFindings = report.findings.filter((finding) => finding.ruleId === "security.new-function");
  assert.equal(newFunctionFindings.length, 1);
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
  // default 8 | metadata setupLines,maxSetupLines | disabled and override fixtures below.
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
    config: { rules: { "test-quality.setup-bloat": { thresholds: { maxSetupLines: 3 } } } },
  });
  assert.equal(tightReport.findings.some((finding) => finding.ruleId === "test-quality.setup-bloat"), true);

  const disabledReport = analyseFixture(source, {
    config: { rules: { "test-quality.setup-bloat": { enabled: false, thresholds: { maxSetupLines: 3 } } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "test-quality.setup-bloat"), false);
});

test("expanded scanner keeps pre-expansion fingerprints stable", () => {
  const report = analyseFixture(`export class Bad {
  public name = "demo";
  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string): void {
    if (a) {
      eval(c);
    }
    console.log(b, d, e, f);
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
    writeFileSync(
      join(projectDir, "bad.ts"),
      `const embeddedToken = "Zx7pQ9vLm3N8sT2rY6wK1dF4gH5jC0bR2";

function unsafe(userInput: string): void {
  eval(userInput);
  new Function(userInput)();
}
`,
    );
    chdir(projectDir);
    const baseOptions = {
      paths: ["."],
      noConfig: true,
      format: "json" as const,
      failOn: "none" as const,
      includeIgnored: false,
      noBaseline: true,
    };
    const report = analyse(baseOptions);
    const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
    assert.equal(ruleIds.has("security.eval-call"), true);
    assert.equal(ruleIds.has("security.new-function"), true);
    assert.equal(ruleIds.has("sensitive-data.high-entropy-string"), true);

    const baselinePath = join(baselineDir, "baseline.json");
    analyse({ ...baseOptions, generateBaseline: baselinePath });
    const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as {
      schemaVersion?: string;
      entries?: Array<{ fingerprint: string; ruleId: string; filePath: string; line?: number; symbol?: string; message?: string }>;
    };
    const entries = baseline.entries ?? [];
    const [target] = entries;
    assert.equal(baseline.schemaVersion, "gruff.baseline.v1");
    assert.ok(target);
    assert.equal(typeof target.fingerprint, "string");
    assert.equal(typeof target.ruleId, "string");
    assert.equal(typeof target.filePath, "string");
    assert.equal(typeof target.message, "string");

    const suppressed = analyse({ ...baseOptions, noBaseline: false, baseline: baselinePath });
    assert.equal(suppressed.baseline?.suppressed, report.findings.length);
    assert.equal(suppressed.findings.length, 0);

    const wrongRulePath = join(baselineDir, "wrong-rule.json");
    writeFileSync(wrongRulePath, JSON.stringify({ ...baseline, entries: entries.map((entry, index) => (index === 0 ? { ...entry, ruleId: "security.wrong-rule" } : entry)) }));
    const wrongRuleReport = analyse({ ...baseOptions, noBaseline: false, baseline: wrongRulePath });
    assert.equal(wrongRuleReport.findings.some((finding) => finding.fingerprint === target.fingerprint && finding.ruleId === target.ruleId && finding.filePath === target.filePath), true);

    const wrongFilePath = join(baselineDir, "wrong-file.json");
    writeFileSync(wrongFilePath, JSON.stringify({ ...baseline, entries: entries.map((entry, index) => (index === 0 ? { ...entry, filePath: "other.ts" } : entry)) }));
    const wrongFileReport = analyse({ ...baseOptions, noBaseline: false, baseline: wrongFilePath });
    assert.equal(wrongFileReport.findings.some((finding) => finding.fingerprint === target.fingerprint && finding.ruleId === target.ruleId && finding.filePath === target.filePath), true);
  } finally {
    chdir(previous);
    rmSync(projectDir, { recursive: true, force: true });
    rmSync(baselineDir, { recursive: true, force: true });
  }
});

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
        "complexity.npath": { thresholds: { warn: 3, error: 6 } },
      },
    },
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "complexity.npath"), true);
});

test("cumulative expanded fixture covers every new rule with unique fingerprints", () => {
  const report = analyseProject({
    "Widget.ts": `import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

export class WidgetRecord {
  public active = true;
  public name: string;

  public constructor(name: string) {
    this.name = name;
  }

  public read(profile?: { name?: string }, fallbackName?: string): string {
    const displayName = fallbackName || "anonymous";
    if (profile && profile.name) {
      return profile.name;
    }
    return displayName;
  }
}

const data1 = "placeholder";
const strName = "Ada";
const objUser = { name: strName };
const loadedText = readFileSync("input.txt", "utf8");
const embeddedToken = "Zx7pQ9vLm3N8sT2rY6wK1dF4gH5jC0bR2";

// const legacyPassword = loadSecret();

function routeOrder(state: string, unusedFlag: boolean): string {
  if (state === "new") return "new";
  if (state === "paid") return "paid";
  if (state === "sent") return "sent";
  if (state === "closed") return "closed";
  if (loadedText.length > 0) return loadedText;
  return "unknown";
}

function emptyWork(): void {}

function redundantResult(): string {
  const calculatedResult = routeOrder("new", true);
  return calculatedResult;
}

function unsafe(userInput: string, userId: string): void {
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  Math.random();
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  db.query("SELECT * FROM users WHERE id = " + userId);
  createHash("md5").update(userInput);
}

/**
 * Scores amount.
 * @param stale Removed parameter.
 */
export function scoreAmount(amount: number): number {
  return amount + objUser.name.length;
}

/** updateName */
export function updateName(name: string): string {
  return name;
}

test("trivial assertion", () => {
  assert.equal(1, 1);
});

test("magic assertion", () => {
  const total = routeOrder("new", false).length;
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
  expect(one).toBeDefined();
});
`,
    ".env": `API_TOKEN=rN7pQ4sV9xY2zA5bC8dG9hK2mN5pQ8sR1
OPENAI_API_KEY=sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz1234567890
PATIENT_SSN=123-45-6789
`,
  });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of expandedRuleIds) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
  assert.equal(new Set(report.findings.map((finding) => finding.fingerprint)).size, report.findings.length);

  const sampleMessages = new Map(report.findings.filter((finding) => expandedRuleIds.has(finding.ruleId)).map((finding) => [finding.ruleId, finding.message]));
  assert.match(sampleMessages.get("security.new-function") ?? "", /dynamic code/);
  assert.match(sampleMessages.get("test-quality.setup-bloat") ?? "", /setup lines/);
  assert.match(sampleMessages.get("sensitive-data.hardcoded-env-value") ?? "", /Redacted preview/);
});

test("json report uses schema version", () => {
  const report = analyse({
    paths: [],
    noConfig: true,
    format: "json",
    failOn: "none",
    includeIgnored: false,
    noBaseline: true,
  });
  const rendered = renderReport(report, "json");
  assert.match(rendered, /"schemaVersion": "gruff\.analysis\.v1"/);
});

interface AnalyseProjectOptions {
  config?: Record<string, unknown>;
  configPath?: string;
  noConfig?: boolean;
}

interface AnalyseFixtureOptions extends AnalyseProjectOptions {
  fileName?: string;
}

function analyseFixture(source: string, options: AnalyseFixtureOptions = {}) {
  return analyseProject(
    { [options.fileName ?? "bad.ts"]: source },
    {
      ...(options.config ? { config: options.config } : {}),
      ...(typeof options.configPath === "string" ? { configPath: options.configPath } : {}),
      ...(typeof options.noConfig === "boolean" ? { noConfig: options.noConfig } : {}),
    },
  );
}

function analyseProject(files: Record<string, string>, options: AnalyseProjectOptions = {}) {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-"));
  const previous = cwd();
  try {
    for (const [fileName, source] of Object.entries(files)) {
      writeFileSync(join(dir, fileName), source);
    }
    if (options.config) {
      writeFileSync(join(dir, ".gruff.json"), JSON.stringify(options.config));
    }
    chdir(dir);
    return analyse({
      paths: ["."],
      ...(typeof options.configPath === "string" ? { config: options.configPath } : {}),
      noConfig: options.noConfig ?? !(options.config || options.configPath),
      format: "json",
      failOn: "none",
      includeIgnored: false,
      noBaseline: true,
    });
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
}
