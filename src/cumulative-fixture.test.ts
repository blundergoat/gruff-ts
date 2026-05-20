import assert from "node:assert/strict";
import test from "node:test";
import { ruleDescriptors } from "./cli.ts";
import {
  analyseProject,
  API_TOKEN_FIXTURE_VALUE,
  COMMENTED_OUT_SECRET_LOAD,
  HIGH_ENTROPY_FIXTURE_VALUE,
  largeFixtureSourceLines,
  OPENAI_KEY_FIXTURE_VALUE,
  SSN_FIXTURE_VALUE,
  TS_IGNORE_DIRECTIVE,
} from "./test-fixtures.ts";

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
