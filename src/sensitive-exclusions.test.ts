// Acceptance and rejection coverage for the ratified `sensitiveExclusions:` config section.
//
// The cases mirror `gruff-spec/fixtures/sensitive-exclusions/cases.v1.json` so this port's native
// suite fails for the same reasons the cross-port conformance suite would. Every secret-shaped value
// below is a synthetic fixture constant from `test-fixtures.ts`; none is a live credential.
import assert from "node:assert/strict";
import test from "node:test";
import { ConfigLoadError } from "./config-load-error.ts";
import { renderReport, renderSummary } from "./report-renderers.ts";
import { AWS_ACCESS_KEY_FIXTURE_VALUE, analyseProject, JWT_FIXTURE_VALUE } from "./test-fixtures.ts";
import type { AnalysisReport } from "./types.ts";

const AWS_RULE_ID = "sensitive-data.aws-access-key";
const JWT_RULE_ID = "sensitive-data.jwt-token";
const NON_SENSITIVE_RULE_ID = "waste.console-log";
const AWS_FIXTURE_PATH = "secrets/aws.env";
const AWS_SIBLING_FIXTURE_PATH = "secrets/aws-sibling.env";
const JWT_FIXTURE_PATH = "secrets/jwt.env";

// The synthetic corpus every case scans: one AWS key, a sibling file with the same rule, and a JWT
// in a third file. Three files are the minimum that can prove a scope suppresses one file's finding
// while the same rule elsewhere and a different rule in the same file both keep reporting.
const SENSITIVE_CORPUS: Record<string, string> = {
  [AWS_FIXTURE_PATH]: `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_FIXTURE_VALUE}\n`,
  [AWS_SIBLING_FIXTURE_PATH]: `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_FIXTURE_VALUE}\n`,
  [JWT_FIXTURE_PATH]: `SESSION_TOKEN=${JWT_FIXTURE_VALUE}\n`,
};

// Renders one `sensitiveExclusions:` YAML document. Written as text rather than through the fixture
// object serializer because that serializer emits inline `[...]` arrays and cannot express the
// ratified sequence-of-mappings shape.
function sensitiveExclusionConfig(entries: string[]): string {
  return ["schemaVersion: gruff-ts.config.v0.1", "sensitiveExclusions:", ...entries].join("\n") + "\n";
}

// Scans the synthetic corpus under one exclusion config and returns the stable report contract.
// `shouldSkipConfig: false` is explicit because the fixture helper otherwise skips config loading
// when no config object was passed.
function analyseWithExclusions(entries: string[]): AnalysisReport {
  return analyseProject({ ...SENSITIVE_CORPUS, ".gruff-ts.yaml": sensitiveExclusionConfig(entries) }, { shouldSkipConfig: false });
}

// Collects the config error one rejection case produces, so each assertion can name the key the
// diagnostic must mention. Throws an assertion failure when the config loaded instead of being
// rejected, or when it failed with something other than a ConfigLoadError.
function exclusionConfigError(entries: string[]): ConfigLoadError {
  try {
    analyseWithExclusions(entries);
  } catch (error) {
    assert.ok(error instanceof ConfigLoadError, `expected a config error, got ${String(error)}`);
    return error;
  }
  throw new assert.AssertionError({ message: "expected the config to be rejected" });
}

// Counts findings for one rule in one file, which is what an acceptance case asserts survived. The
// rule-plus-path pair is the same scope contract an exclusion entry declares.
function findingCount(report: AnalysisReport, ruleId: string, filePath: string): number {
  return report.findings.filter((finding) => finding.ruleId === ruleId && finding.filePath === filePath).length;
}

// Pulls the single `Suppressed findings:` row out of a rendered text surface so two surfaces can be
// compared as text rather than as recomputed totals. Fails the case when the surface published no
// row at all, which is the silent-filtering failure the audit rule exists to catch.
function suppressionLine(rendered: string): string {
  const line = rendered.split("\n").find((candidate) => candidate.startsWith("Suppressed findings:"));
  assert.ok(line !== undefined, "the surface applied an exclusion without publishing a suppression row");
  return line;
}

test("an exact rule and path suppresses that scope, counts it, and leaves siblings reporting", () => {
  const baseline = analyseProject(SENSITIVE_CORPUS, { shouldSkipConfig: true });
  assert.ok(findingCount(baseline, AWS_RULE_ID, AWS_FIXTURE_PATH) >= 1, "fixture must produce the AWS finding it excludes");

  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: Synthetic AWS key used by the redaction corpus; not a live credential.",
  ]);

  assert.equal(findingCount(report, AWS_RULE_ID, AWS_FIXTURE_PATH), 0, "the declared scope must be suppressed");
  assert.ok(findingCount(report, AWS_RULE_ID, AWS_SIBLING_FIXTURE_PATH) >= 1, "the same rule in another file must keep reporting");
  assert.ok(findingCount(report, JWT_RULE_ID, JWT_FIXTURE_PATH) >= 1, "another sensitive rule must keep reporting");
  assert.equal(report.suppressions.length, 1);
  assert.deepEqual(
    { index: report.suppressions[0]?.index, rule: report.suppressions[0]?.rule, paths: report.suppressions[0]?.paths, symbol: report.suppressions[0]?.symbol },
    { index: 0, rule: AWS_RULE_ID, paths: [AWS_FIXTURE_PATH], symbol: null },
  );
  assert.ok((report.suppressions[0]?.suppressed ?? 0) >= 1, "the audit row must count what it suppressed");
});

test("an exclusion whose scope matches no finding reports zero instead of failing", () => {
  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    "    path: secrets/absent-from-corpus.env",
    "    reason: Retained while the fixture is being removed.",
  ]);

  assert.equal(report.suppressions[0]?.suppressed, 0, "a scope matching nothing must report zero, not break the build");
  assert.ok(findingCount(report, AWS_RULE_ID, AWS_FIXTURE_PATH) >= 1, "an unmatched entry must suppress nothing");
});

test("a symbol narrows the scope, so it matches nothing on a pillar whose findings carry no symbol", () => {
  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    symbol: Fixtures::awsSample",
    "    reason: Narrowed to one symbol while the fixture is refactored.",
  ]);

  assert.equal(report.suppressions[0]?.symbol, "Fixtures::awsSample", "the symbol must be accepted and published");
  assert.equal(report.suppressions[0]?.suppressed, 0);
  assert.ok(findingCount(report, AWS_RULE_ID, AWS_FIXTURE_PATH) >= 1, "the symbol did not match, so the finding survives");
});

test("two entries with different scopes are independent and each reports its own count", () => {
  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: Synthetic AWS key used by the redaction corpus.",
    `  - rule: ${JWT_RULE_ID}`,
    `    path: ${JWT_FIXTURE_PATH}`,
    "    reason: Synthetic JWT used by the redaction corpus.",
  ]);

  assert.equal(report.suppressions.length, 2);
  assert.ok((report.suppressions[0]?.suppressed ?? 0) >= 1);
  assert.ok((report.suppressions[1]?.suppressed ?? 0) >= 1);
  assert.equal(findingCount(report, AWS_RULE_ID, AWS_FIXTURE_PATH), 0);
  assert.equal(findingCount(report, JWT_RULE_ID, JWT_FIXTURE_PATH), 0);
  assert.ok(findingCount(report, AWS_RULE_ID, AWS_SIBLING_FIXTURE_PATH) >= 1, "excluding one file must leave the sibling reporting");
});

test("a suppressed finding leaves the score and the text total, not the finding list", () => {
  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: Synthetic AWS key used by the redaction corpus.",
  ]);
  const text = renderReport(report, "text");

  assert.match(text, /Suppressed findings: \d+ via sensitiveExclusions\[0\] sensitive-data\.aws-access-key: \d+ \(Synthetic AWS key used by the redaction corpus\.\)/);
  assert.equal(report.summary.total, report.findings.length, "the summary counts only surviving findings");
  assert.equal(text.includes(AWS_ACCESS_KEY_FIXTURE_VALUE), false, "no suppression surface may carry matched value material");
});

test("summary text publishes the same suppression count analyse publishes for one tree", () => {
  const report = analyseWithExclusions([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: Synthetic AWS key used by the redaction corpus.",
  ]);
  const summaryText = renderSummary(report);
  const summaryRow = suppressionLine(summaryText);

  assert.match(summaryRow, /^Suppressed findings: [1-9][0-9]* via sensitiveExclusions\[0\] sensitive-data\.aws-access-key: [1-9][0-9]* \(Synthetic AWS key used by the redaction corpus\.\)$/);
  assert.equal(summaryRow, suppressionLine(renderReport(report, "text")), "both surfaces filter the same tree, so both must report one identical count");
  assert.equal(findingCount(report, AWS_RULE_ID, AWS_FIXTURE_PATH), 0, "summary still applies the exclusion it reports");
  assert.ok(summaryText.indexOf("Suppressed findings:") > summaryText.indexOf("Findings:"), "the audit row is an extension line below the canonical block");
  assert.equal(summaryText.includes(AWS_ACCESS_KEY_FIXTURE_VALUE), false, "no suppression surface may carry matched value material");
});

test("a missing reason is rejected because an unexplained suppression is unreviewable", () => {
  const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, `    path: ${AWS_FIXTURE_PATH}`]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.reason/);
});

test("a whitespace-only reason is rejected because whitespace is not a rationale", () => {
  const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, `    path: ${AWS_FIXTURE_PATH}`, '    reason: "   "']);

  assert.match(error.message, /sensitiveExclusions\[0\]\.reason/);
});

test("a wildcard rule is rejected because a blanket suppression hides findings nobody reviewed", () => {
  const error = exclusionConfigError(['  - rule: "*"', `    path: ${AWS_FIXTURE_PATH}`, "    reason: Everything here is synthetic."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.rule/);
});

test("a pillar name is rejected because it is a blanket suppression wearing a rule id", () => {
  const error = exclusionConfigError(["  - rule: sensitive-data", `    path: ${AWS_FIXTURE_PATH}`, "    reason: Everything here is synthetic."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.rule/);
  assert.match(error.message, /pillar/);
});

test("a glob over rule ids is rejected as blanket suppression", () => {
  const error = exclusionConfigError(['  - rule: "sensitive-data.*"', `    path: ${AWS_FIXTURE_PATH}`, "    reason: Everything here is synthetic."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.rule/);
});

test("an unknown rule id fails loudly instead of silently suppressing nothing", () => {
  const error = exclusionConfigError(["  - rule: sensitive-data.not-a-real-rule", `    path: ${AWS_FIXTURE_PATH}`, "    reason: Synthetic fixture."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.rule/);
  assert.match(error.message, /unknown rule id/);
});

test("a known rule outside the sensitive-data pillar is rejected", () => {
  const error = exclusionConfigError([`  - rule: ${NON_SENSITIVE_RULE_ID}`, `    path: ${AWS_FIXTURE_PATH}`, "    reason: Synthetic fixture."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.rule/);
  assert.match(error.message, /sensitive-data pillar/);
});

test("an absolute path is rejected because it escapes the analysed project", () => {
  const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, "    path: /etc/secrets/aws.env", "    reason: Synthetic fixture."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.path/);
  assert.match(error.message, /absolute/);
});

test("a parent-escape path is rejected because a traversal leaves the project", () => {
  const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, "    path: ../secrets/aws.env", "    reason: Synthetic fixture."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.path/);
});

test("a path glob is rejected because it suppresses files nobody enumerated", () => {
  const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, '    path: "secrets/*.env"', "    reason: Synthetic fixture."]);

  assert.match(error.message, /sensitiveExclusions\[0\]\.path/);
  assert.match(error.message, /glob/);
});

test("message, value, and preview keys are rejected so value matching cannot return", () => {
  for (const [key, value] of [["message_contains", "AKIA"], ["messageContains", "AKIA"], ["value", "AKIA"], ["preview", "[redacted:aws-access-key]"]]) {
    const error = exclusionConfigError([`  - rule: ${AWS_RULE_ID}`, `    path: ${AWS_FIXTURE_PATH}`, `    ${String(key)}: ${JSON.stringify(String(value))}`, "    reason: Synthetic fixture."]);

    assert.match(error.message, new RegExp(`sensitiveExclusions\\[0\\]\\.${String(key)}`), `expected the diagnostic to name ${String(key)}`);
  }
});

test("a second entry claiming one scope is rejected so the audit count cannot split", () => {
  const error = exclusionConfigError([
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: First rationale.",
    `  - rule: ${AWS_RULE_ID}`,
    `    path: ${AWS_FIXTURE_PATH}`,
    "    reason: Second rationale.",
  ]);

  assert.match(error.message, /sensitiveExclusions\[1\]/);
  assert.match(error.message, /duplicate/);
});
