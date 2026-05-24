// Core scanner, parser, discovery, gitignore, and config-loading tests. Other test
// groups live in companion files (naming-rules.test.ts, docs-comment-rules.test.ts,
// security-and-config.test.ts, baseline-and-project.test.ts, cli-surfaces.test.ts,
// cumulative-fixture.test.ts, rule-catalogue.test.ts).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cwd } from "node:process";
import test from "node:test";
import { renderReport } from "./cli.ts";
import type { AnalysisReport } from "./cli.ts";
import {
  analyseFixture,
  analyseProject,
  COMMENTED_OUT_CACHE_LOAD,
  COMMENTED_OUT_SECRET_LOAD,
  evalFindingFiles,
  HIGH_ENTROPY_FIXTURE_VALUE,
  gitAvailable,
  isGitIgnoredByGit,
  writeFixtureFiles,
} from "./test-fixtures.ts";

test("analysis finds core TypeScript smells", () => {
  // Fixture covers core scanner findings across class, eval, parameter-count, and no-assertions paths.
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
  // Fixture covers stable fingerprint anchors for the original core scanner findings.
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

const FIRST_SLICE_RULE_IDS = new Set([
  "waste.commented-out-code",
  "naming.identifier-quality",
  "test-quality.trivial-assertion",
  "security.weak-crypto",
  "sensitive-data.high-entropy-string",
]);

test("analysis finds first-slice portable TypeScript rules", () => {
  const secret = HIGH_ENTROPY_FIXTURE_VALUE;
  // Fixture covers portable source-text, line, function-block, test-block, and sensitive-data seams.
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
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  FIRST_SLICE_RULE_IDS.forEach((ruleId: string) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });

  const firstSliceFindings = report.findings.filter((finding) => FIRST_SLICE_RULE_IDS.has(finding.ruleId));
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

// Fixture covers clean-path expansion rules so false positives stay visible.
const CLEAN_USER_PROFILE_FIXTURE = `/** UserProfile stores profile state. */
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
`;

const M02_EXPANSION_RULE_IDS = new Set([
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

test("core expansion clean fixture stays finding-free", () => {
  const report = analyseFixture(CLEAN_USER_PROFILE_FIXTURE, { fileName: "UserProfile.ts" });
  const unexpected = report.findings.filter((finding) => M02_EXPANSION_RULE_IDS.has(finding.ruleId));
  assert.deepEqual(unexpected, []);
});

// Fixture covers noisy complexity and waste signals with threshold override metadata.
const COMPLEXITY_WASTE_FIXTURE = `import { readFileSync, writeFileSync } from "node:fs";

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
`;

test("core expansion finds complexity and waste rules", () => {
  const report = analyseFixture(COMPLEXITY_WASTE_FIXTURE, { config: { rules: { "complexity.npath": { threshold: 20, severity: "warning" } } } });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  ["complexity.npath", "waste.commented-out-code", "waste.empty-function", "waste.redundant-variable", "waste.unused-import", "waste.unused-parameter"].forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
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
    { shouldSkipConfig: false },
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
    { shouldSkipConfig: false },
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

// Fixture files for the nested-gitignore discovery test.
const NESTED_GITIGNORE_FIXTURE = {
  ".gitignore": "ignored.ts\nignored-dir/\n*.ignored.ts\n!keep.ignored.ts\n",
  "tracked.ts": `eval("tracked");\n`,
  "ignored.ts": `eval("ignored");\n`,
  "skip.ignored.ts": `eval("skip");\n`,
  "keep.ignored.ts": `eval("keep");\n`,
  "ignored-dir/bad.ts": `eval("dir");\n`,
  "nested/.gitignore": "*.ts\n!allowed.ts\n",
  "nested/blocked.ts": `eval("blocked");\n`,
  "nested/allowed.ts": `eval("allowed");\n`,
};

test("directory discovery respects root and nested gitignore rules", () => {
  const report = analyseProject(NESTED_GITIGNORE_FIXTURE, { shouldSkipConfig: true });
  const expectedTrackedFiles = ["keep.ignored.ts", "nested/allowed.ts", "tracked.ts"];
  assert.deepEqual([...evalFindingFiles(report)].sort(), expectedTrackedFiles); assert.equal(report.paths.analysedFiles, expectedTrackedFiles.length);
  assert.deepEqual(
    report.paths.ignoredPaths.filter((path) => ["ignored-dir", "ignored.ts", "nested/blocked.ts", "skip.ignored.ts"].includes(path)).sort(),
    ["ignored-dir", "ignored.ts", "nested/blocked.ts", "skip.ignored.ts"],
  );
});

// Fixture covers gitignore parity against git check-ignore for ignored and tracked path cases; spawns git and writes a temporary filesystem tree.
test("gitignore fixture expectations match git check-ignore when git is available", { skip: !gitAvailable() }, () => {
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

// Fixture files for the include-ignored test; policy/** stays ignored regardless of include-ignored.
const INCLUDE_IGNORED_FIXTURE = {
  ".gitignore": "ignored.ts\n",
  ".gruff-ts.yaml": `\npaths:\n  ignore:\n    - "policy/**"\n`,
  "visible.ts": `eval("visible");\n`,
  "ignored.ts": `eval("ignored");\n`,
  "node_modules/pkg/index.ts": `eval("dependency");\n`,
  "policy/bad.ts": `eval("policy");\n`,
};

test("include ignored scans default and Git ignored paths but keeps config policy ignores", () => {
  const normalReport = analyseProject(INCLUDE_IGNORED_FIXTURE, { shouldSkipConfig: false });
  assert.deepEqual([...evalFindingFiles(normalReport)].sort(), ["visible.ts"]);
  assert.deepEqual(
    normalReport.paths.ignoredPaths.filter((path) => ["ignored.ts", "node_modules", "policy"].includes(path)).sort(),
    ["ignored.ts", "node_modules", "policy"],
  );

  const includeReport = analyseProject(INCLUDE_IGNORED_FIXTURE, { shouldIncludeIgnored: true, shouldSkipConfig: false });
  assert.deepEqual([...evalFindingFiles(includeReport)].sort(), ["ignored.ts", "node_modules/pkg/index.ts", "visible.ts"]);
  assert.deepEqual(includeReport.paths.ignoredPaths.filter((path) => ["ignored.ts", "node_modules", "policy"].includes(path)).sort(), ["policy"]);
});

// Fixture for the non-gitignored-config-surfaces test.
const NON_GITIGNORED_CONFIG_FIXTURE = {
  ".gitignore": ".claude/settings.local.json\n.codex/local.json\n",
  ".agents/config.json": "{}\n",
  ".claude/settings.json": "{}\n",
  ".claude/settings.local.json": "{}\n",
  ".codex/config.toml": "sandbox_mode = \"danger-full-access\"\n",
  ".codex/local.json": "{}\n",
  ".github/workflows/ci.yaml": "name: ci\n",
  ".goat-flow/config.yaml": "version: 1\n",
};

test("directory discovery includes non-gitignored repository config surfaces", () => {
  const report = analyseProject(NON_GITIGNORED_CONFIG_FIXTURE, { shouldSkipConfig: true });
  const expectedAnalysedFileCount = 5;
  assert.equal(report.paths.analysedFiles, expectedAnalysedFileCount); assert.deepEqual(report.paths.ignoredPaths.sort(), [".claude/settings.local.json", ".codex/local.json"]);
});

test("explicit file inputs are scanned even when gitignored", () => {
  const report = analyseProject(
    {
      ".gitignore": "ignored.ts\n",
      "ignored.ts": `eval("ignored");
`,
    },
    { shouldSkipConfig: true, paths: ["ignored.ts"] },
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
    { shouldSkipConfig: false },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "security.eval-call"), false);
});

// Fixture covers naming and documentation rule emissions in one source sample.
const NAMING_DOC_FIXTURE = `/** CustomerProfile stores customer data. */
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
`;

test("core expansion finds naming and documentation rules", () => {
  const report = analyseFixture(NAMING_DOC_FIXTURE, { fileName: "CustomerProfile.ts" });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  ["naming.boolean-prefix", "naming.hungarian-notation", "naming.class-file-mismatch", "docs.stale-param-tag", "docs.missing-param-tag", "docs.missing-return-tag", "docs.useless-docblock"].forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
});

test("core expansion finds modernisation rules", () => {
  // Fixture covers modernization detections for readonly, optional chaining, and nullish coalescing.
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
  ["modernisation.readonly-property-candidate", "modernisation.optional-chaining-candidate", "modernisation.nullish-coalescing-candidate"].forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
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

// Fixture for the scanner guardrail noisy-valid test: commented/templated/regex shapes that must
// stay quiet across the noisy-valid rule set.
const SCANNER_GUARDRAIL_NOISY_VALID_FIXTURE = {
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
};

test("scanner guardrail fixtures keep noisy-valid comments strings regex templates inert", () => {
  const report = analyseProject(SCANNER_GUARDRAIL_NOISY_VALID_FIXTURE);
  const noisyRules = new Set([
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
      .map((finding) => [finding.ruleId, finding.filePath, finding.line ?? 0, finding.fingerprint].join(":"))
      .sort();
  assert.deepEqual(identity(noisy), identity(base));
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
  // Fixture covers multiline arrow parsing without treating expression bodies as empty blocks.
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
