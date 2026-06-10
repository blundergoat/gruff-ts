// Sensitive-data detector tests keep raw synthetic secrets out of source and rendered output.
import assert from "node:assert/strict";
import test from "node:test";
import { renderReport } from "./cli.ts";
import {
  analyseFixture,
  analyseProject,
  API_TOKEN_FIXTURE_VALUE,
  AWS_ACCESS_KEY_FIXTURE_VALUE,
  CREDIT_CARD_FIXTURE_VALUE,
  DATABASE_URL_FIXTURE_VALUE,
  DISCORD_WEBHOOK_FIXTURE_VALUE,
  GCP_PRIVATE_KEY_ID_FIXTURE_VALUE,
  GOOGLE_API_KEY_FIXTURE_VALUE,
  HIGH_ENTROPY_FIXTURE_VALUE,
  INVALID_CREDIT_CARD_FIXTURE_VALUE,
  JWT_FIXTURE_VALUE,
  MBI_FIXTURE_VALUE,
  MRN_FIXTURE_VALUE,
  NPM_AUTH_TOKEN_FIXTURE_VALUE,
  OPENAI_KEY_FIXTURE_VALUE,
  PRIVATE_KEY_HEADER_FIXTURE_VALUE,
  SLACK_WEBHOOK_FIXTURE_VALUE,
  SSN_FIXTURE_VALUE,
  URL_CREDENTIAL_FIXTURE_VALUE,
} from "./test-fixtures.ts";

const SENSITIVE_DATA_RULE_IDS = ["sensitive-data.hardcoded-env-value", "sensitive-data.api-key-pattern", "sensitive-data.database-url-password", "sensitive-data.pii-pattern"];
const ALL_RENDER_FORMATS = ["text", "json", "markdown", "github", "html", "sarif", "hotspot"] as const;
const PREVIEW_RENDER_FORMATS = ["text", "json", "markdown", "github", "html", "sarif"] as const;
const RAW_SECRET_FIXTURE_VALUES = [
  API_TOKEN_FIXTURE_VALUE,
  DATABASE_URL_FIXTURE_VALUE,
  URL_CREDENTIAL_FIXTURE_VALUE,
  OPENAI_KEY_FIXTURE_VALUE,
  GOOGLE_API_KEY_FIXTURE_VALUE,
  SLACK_WEBHOOK_FIXTURE_VALUE,
  DISCORD_WEBHOOK_FIXTURE_VALUE,
  SSN_FIXTURE_VALUE,
  CREDIT_CARD_FIXTURE_VALUE,
];
const EXPECTED_SECRET_DOTFILE_ANALYSED_FILES = 2;
const EXPECTED_NEW_DETECTOR_PREVIEWS = 2;

// Fixture covers the redaction contract across every report renderer using safe synthetic values.
function redactedSecretsFixtureSource(): string {
  return `API_TOKEN=${API_TOKEN_FIXTURE_VALUE}
DATABASE_URL=${DATABASE_URL_FIXTURE_VALUE}
REMOTE_CONTROL_URL=${URL_CREDENTIAL_FIXTURE_VALUE}
OPENAI_API_KEY=${OPENAI_KEY_FIXTURE_VALUE}
GOOGLE_API_KEY=${GOOGLE_API_KEY_FIXTURE_VALUE}
SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_FIXTURE_VALUE}
DISCORD_WEBHOOK_URL=${DISCORD_WEBHOOK_FIXTURE_VALUE}
PATIENT_SSN=${SSN_FIXTURE_VALUE}
PAYMENT_CARD=${CREDIT_CARD_FIXTURE_VALUE}
`;
}

// Fixture purpose: proves every report renderer avoids raw secret output while preview renderers
// still show deterministic redaction markers for reviewer triage.
test("risk expansion redacts sensitive data in all render formats", () => {
  const report = analyseFixture(redactedSecretsFixtureSource(), { fileName: ".env" });
  const ruleIds = new Set(report.findings.map((finding) => finding.ruleId));
  SENSITIVE_DATA_RULE_IDS.forEach((ruleId) => {
    assert.equal(ruleIds.has(ruleId), true, `expected ${ruleId}`);
  });
  ALL_RENDER_FORMATS.forEach((format) => {
    const rendered = renderReport(report, format);
    RAW_SECRET_FIXTURE_VALUES.forEach((secret) => {
      assert.equal(rendered.includes(secret), false, `${format} leaked ${secret}`);
    });
  });
  PREVIEW_RENDER_FORMATS.forEach((format) => {
    assert.match(renderReport(report, format), /redacted/);
  });
});

test("M26 URL credentials and payment-card PII fire with deterministic redaction", () => {
  const report = analyseFixture(
    `REMOTE_CONTROL_URL=${URL_CREDENTIAL_FIXTURE_VALUE}
PAYMENT_CARD=${CREDIT_CARD_FIXTURE_VALUE}
INVALID_CARD=${INVALID_CREDIT_CARD_FIXTURE_VALUE}
`,
    { fileName: ".env" },
  );

  const urlFinding = report.findings.find((finding) => finding.ruleId === "sensitive-data.database-url-password");
  assert.match(urlFinding?.message ?? "", /embedded credentials/);
  assert.equal(urlFinding?.message.includes(URL_CREDENTIAL_FIXTURE_VALUE), false);
  assert.equal(JSON.stringify(urlFinding?.metadata).includes(URL_CREDENTIAL_FIXTURE_VALUE), false);
  assert.match(String(urlFinding?.metadata.preview), /redacted/);

  const cardFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.pii-pattern");
  assert.equal(cardFindings.length, 1);
  assert.match(cardFindings[0]?.message ?? "", /Credit card/);
  assert.equal(cardFindings[0]?.message.includes(CREDIT_CARD_FIXTURE_VALUE), false);
  assert.equal(JSON.stringify(cardFindings[0]?.metadata).includes(CREDIT_CARD_FIXTURE_VALUE), false);
  assert.equal(JSON.stringify(report).includes(INVALID_CREDIT_CARD_FIXTURE_VALUE), false);
});

test("M26 sensitive-data allowlists match redacted previews for new detector coverage", () => {
  const source = `REMOTE_CONTROL_URL=${URL_CREDENTIAL_FIXTURE_VALUE}
PAYMENT_CARD=${CREDIT_CARD_FIXTURE_VALUE}
`;
  const defaultReport = analyseFixture(source, { fileName: ".env" });
  const previews = defaultReport.findings
    .filter((finding) => ["sensitive-data.database-url-password", "sensitive-data.pii-pattern"].includes(finding.ruleId))
    .map((finding) => finding.metadata.preview);
  assert.equal(previews.length, EXPECTED_NEW_DETECTOR_PREVIEWS);

  const allowlistedReport = analyseFixture(source, {
    fileName: ".env",
    config: { allowlists: { secretPreviews: previews } },
  });

  assert.equal(allowlistedReport.findings.some((finding) => finding.ruleId === "sensitive-data.database-url-password"), false);
  assert.equal(allowlistedReport.findings.some((finding) => finding.ruleId === "sensitive-data.pii-pattern"), false);
});

test("M26 PHI (MBI/MRN) and GCP service-account detectors fire and redact across every renderer", () => {
  const phiReport = analyseFixture(`PATIENT_MBI=${MBI_FIXTURE_VALUE}\nMRN: ${MRN_FIXTURE_VALUE}\n`, { fileName: ".env" });
  const gcpReport = analyseFixture(
    JSON.stringify({
      type: "service_account",
      private_key_id: GCP_PRIVATE_KEY_ID_FIXTURE_VALUE,
      private_key: `${PRIVATE_KEY_HEADER_FIXTURE_VALUE}\nx\n-----END PRIVATE KEY-----\n`,
    }),
    { fileName: "service-account.json" },
  );
  const phiRuleIds = new Set(phiReport.findings.map((finding) => finding.ruleId));
  const gcpRuleIds = new Set(gcpReport.findings.map((finding) => finding.ruleId));
  assert.equal(phiRuleIds.has("sensitive-data.phi-pattern"), true, "expected phi-pattern");
  assert.equal(gcpRuleIds.has("sensitive-data.gcp-service-account-key"), true, "expected gcp-service-account-key");

  ALL_RENDER_FORMATS.forEach((format) => {
    const phiRendered = renderReport(phiReport, format);
    [MBI_FIXTURE_VALUE, MRN_FIXTURE_VALUE].forEach((secret) => {
      assert.equal(phiRendered.includes(secret), false, `${format} leaked PHI ${secret}`);
    });
    const gcpRendered = renderReport(gcpReport, format);
    assert.equal(gcpRendered.includes(GCP_PRIVATE_KEY_ID_FIXTURE_VALUE), false, `${format} leaked GCP key id`);
  });
});

test("GCP service-account metadata without private_key stays quiet", () => {
  const report = analyseFixture(
    JSON.stringify({
      type: "service_account",
      private_key_id: GCP_PRIVATE_KEY_ID_FIXTURE_VALUE,
      client_email: "fixture@example.test",
    }),
    { fileName: "service-account.json" },
  );

  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.gcp-service-account-key"), false);
});

test("risk expansion respects sensitive-data config", () => {
  // Config contract: sensitive-data.hardcoded-env-value | threshold minLength |
  // default 16 | metadata keyName,preview,length | disabled and override fixtures below.
  const source = `API_TOKEN=${API_TOKEN_FIXTURE_VALUE}
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

// Real-secret counter-fixtures for the high-entropy word-segment exemption. Each value is a
// credential shape the exemption must never suppress; all four flagged before the exemption
// landed and the assertions lock that in. Assembled from sub-24-char halves so this test file's
// own source does not trip the detector during self-scans.
const BASE64_PADDED_TOKEN_FIXTURE_VALUE = ["dGhpc0lzQVRva2VuV2l0", "aDFEaWdpdEFuZE1peGVkQ2FzZQ=="].join("");
const BASE64URL_TOKEN_FIXTURE_VALUE = ["Xk9pQ2vLmN8sT4rY6wK1dF5g", "H7jC0bR3eW9qT2uV4xZ6aPmQ"].join("");

test("high-entropy counter-fixtures: base64 padding, JWT, base64url, and coverage value all flag", () => {
  const source = `const padded = "${BASE64_PADDED_TOKEN_FIXTURE_VALUE}";
const webToken = "${JWT_FIXTURE_VALUE}";
const urlSafe = "${BASE64URL_TOKEN_FIXTURE_VALUE}";
const coverage = "${HIGH_ENTROPY_FIXTURE_VALUE}";
void padded; void webToken; void urlSafe; void coverage;
`;
  const report = analyseFixture(source);
  const entropyLines = report.findings
    .filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string")
    .map((finding) => finding.line)
    .sort();
  assert.deepEqual(entropyLines, [1, 2, 3, 4]);
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.jwt-token" && finding.line === 2), true);
});

test("hardcoded-env requires a quoted value in script files but not in config files", () => {
  // A quoted literal in TS keeps flagging; unquoted right-hand sides in TS are code expressions
  // (secret-provider plumbing, schema builders) and stay quiet. The same unquoted value in a
  // .env file is a literal and keeps flagging.
  const scriptReport = analyseFixture(`const settings = {
  ACCESS_TOKEN: "${API_TOKEN_FIXTURE_VALUE}",
};
STORAGE_SECRET_ACCESS_KEY: SECRET.R2SecretKey.value;
const table = { access_token: text().$type<OAuth2Token>() };
void settings; void table;
`, { fileName: "config.ts" });
  const scriptFindings = scriptReport.findings.filter((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value");
  assert.equal(scriptFindings.length, 1);
  assert.equal(scriptFindings[0]?.line, 2);

  const envReport = analyseFixture(`API_TOKEN=${API_TOKEN_FIXTURE_VALUE}\n`, { fileName: ".env" });
  assert.equal(envReport.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value"), true);
});

test("payment-card detection requires card context for bare digit runs", () => {
  // GDP/population statistics can pass the Luhn check by coincidence; without card vocabulary on
  // the line a bare digit run stays quiet. Card-context lines and separator-grouped numbers keep
  // flagging - the formatted shape is card evidence on its own.
  const bareCardDigits = CREDIT_CARD_FIXTURE_VALUE.replaceAll(" ", "");
  const report = analyseFixture(`const gdpByCountry = [4300000000000];
const cardNumber = "${bareCardDigits}";
const formatted = "${CREDIT_CARD_FIXTURE_VALUE}";
void gdpByCountry; void cardNumber; void formatted;
`);
  const cardFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.pii-pattern" && /Credit card/.test(finding.message));
  assert.deepEqual(cardFindings.map((finding) => finding.line).sort(), [2, 3]);
});

test("explicitly example-marked credentials stay quiet while production-shaped ones flag", () => {
  // D6 policy: the fake marker must sit inside the matched value (AWS doc keys end in EXAMPLE,
  // redaction fixtures use REDACTED). Path or test location alone never suppresses.
  const awsDocExampleKey = ["AKIAIOSFODNN7", "EXAMPLE"].join("");
  const redactedUrl = "postgres://app:REDACTED@db.internal/app";
  const report = analyseFixture(`AWS_KEY_ONE=${awsDocExampleKey}
AWS_KEY_TWO=${AWS_ACCESS_KEY_FIXTURE_VALUE}
URL_ONE=${redactedUrl}
URL_TWO=${URL_CREDENTIAL_FIXTURE_VALUE}
`, { fileName: ".env" });
  const awsFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");
  assert.deepEqual(awsFindings.map((finding) => finding.line), [2]);
  const urlFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.database-url-password");
  assert.deepEqual(urlFindings.map((finding) => finding.line), [4]);
});

test("sensitive-data expansion scans secret dotfiles", () => {
  const report = analyseProject({
    ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_AUTH_TOKEN_FIXTURE_VALUE}
`,
    ".pypirc": `[pypi]
password = ${["pY7sK2mN8qR4", "vT6xW9zA1bC3"].join("")}
`,
  });

  const apiKeyFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.api-key-pattern");
  assert.equal(report.paths.analysedFiles, EXPECTED_SECRET_DOTFILE_ANALYSED_FILES);
  assert.equal(apiKeyFindings.some((finding) => finding.filePath === ".npmrc"), true);
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value" && finding.filePath === ".pypirc"), true);
  assert.equal(renderReport(report, "json").includes(NPM_AUTH_TOKEN_FIXTURE_VALUE), false);
});
