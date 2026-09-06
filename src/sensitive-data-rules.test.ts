// Sensitive-data detector tests cover the findings users receive for synthetic secret-like input.
//
// Fixtures prove fixed markers and retained occurrence counts across every renderer.
// All examples are synthetic and assembled safely so the repository never stores real credentials.
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
const MARKER_RENDER_FORMATS = ["text", "json", "markdown", "github", "html", "sarif"] as const;
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
const EXPECTED_NEW_DETECTOR_FINDINGS = 2;
const RETIRED_EDGE_PREVIEW_FRAGMENT_LENGTH = 4;
const SHORT_HASH_PREFIX = "a1B2";
const HASH_SECRET_SUFFIX = "c3D4e5F6g7H8";
const QUOTED_HASH_SECRET_FIXTURE_VALUE = [SHORT_HASH_PREFIX, "#", HASH_SECRET_SUFFIX].join("");
const EXPECTED_QUOTED_HASH_SECRET_LENGTH = 17;
const FIXED_MARKER_CASES = [
  { keyName: "SHORT_TOKEN_NINE", secretValue: ["a1B2", "c3D4e"].join("") },
  { keyName: "SHORT_TOKEN_TWELVE", secretValue: ["f5G6h7", "J8k9L0"].join("") },
  { keyName: "SHORT_TOKEN_SIXTEEN", secretValue: ["m1N2p3Q4", "r5S6t7U8"].join("") },
  { keyName: "LONG_TOKEN_TWENTY_FOUR", secretValue: ["v1W2x3Y4z5A6", "b7C8d9E0f1G2"].join("") },
  { keyName: "LONG_TOKEN_FORTY", secretValue: ["h3J4k5L6m7N8p9Q0r1S2", "t3U4v5W6x7Y8z9A0b1C2"].join("") },
] as const;

// Build one user-like config file that exercises generic, provider, connection, and identifier markers together.
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

// Fixture purpose: every renderer must hide source values while still showing fixed categories reviewers can act on.
test("risk expansion emits fixed sensitive markers in all render formats", () => {
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
  MARKER_RENDER_FORMATS.forEach((format) => {
    assert.match(renderReport(report, format), /\[redacted(?::[^\]]+)?\]/);
  });
  const displayedMarkers = new Set(report.findings.map((finding) => finding.metadata.preview));
  [
    "[redacted]",
    "[redacted:connection-string:https]",
    "[redacted:connection-string:postgres]",
    "[redacted:google-api-key]",
    "[redacted:payment-card]",
    "[redacted:slack-token]",
    "[redacted:ssn]",
  ].forEach((expectedMarker) => assert.equal(displayedMarkers.has(expectedMarker), true, expectedMarker));
  assert.equal(JSON.stringify(report).includes("(redacted,"), false);
  assert.equal(JSON.stringify(report).includes(" chars)"), false);
});

test("provider-shaped API keys use the fixed family marker vocabulary", () => {
  const providerTokenCases = [
    { keyName: "GITHUB_TOKEN", matchedValue: `ghp_${"A".repeat(20)}`, marker: "[redacted:github-token]" },
    { keyName: "NPM_TOKEN", matchedValue: `npm_${"B".repeat(20)}`, marker: "[redacted:npm-token]" },
    { keyName: "STRIPE_TOKEN", matchedValue: `sk_live_${"C".repeat(12)}`, marker: "[redacted:stripe-live-key]" },
    { keyName: "ANTHROPIC_TOKEN", matchedValue: `sk-ant-${"D".repeat(16)}`, marker: "[redacted:anthropic-api-key]" },
    { keyName: "GITLAB_TOKEN", matchedValue: `glpat-${"E".repeat(20)}`, marker: "[redacted:gitlab-token]" },
  ];
  const source = providerTokenCases.map(({ keyName, matchedValue }) => `${keyName}=${matchedValue}`).join("\n");
  const report = analyseFixture(source, { fileName: ".env" });
  const apiKeyMarkers = report.findings
    .filter((finding) => finding.ruleId === "sensitive-data.api-key-pattern")
    .map((finding) => finding.metadata.preview);

  assert.deepEqual(apiKeyMarkers, providerTokenCases.map(({ marker }) => marker));
  providerTokenCases.forEach(({ matchedValue }) => assert.equal(JSON.stringify(report).includes(matchedValue), false));
});

// Fixture purpose: values on both sides of the retired length boundary must now produce the same zero-payload marker.
test("generic sensitive findings reveal no matched characters or length", () => {
  const source = FIXED_MARKER_CASES.map(({ keyName, secretValue }) => `${keyName}=${secretValue}`).join("\n");
  const report = analyseFixture(source, {
    fileName: ".env",
    config: { rules: { "sensitive-data.hardcoded-env-value": { threshold: 1 } } },
  });
  const sensitiveFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value");
  assert.equal(sensitiveFindings.length, FIXED_MARKER_CASES.length);
  assert.equal(sensitiveFindings.every((finding) => finding.metadata.preview === "[redacted]"), true);
  assert.equal(sensitiveFindings.every((finding) => !("length" in finding.metadata)), true);

  const serializedReport = JSON.stringify(report);
  FIXED_MARKER_CASES.forEach(({ secretValue }) => {
    assert.equal(serializedReport.includes(secretValue), false);
    assert.equal(serializedReport.includes(secretValue.slice(0, RETIRED_EDGE_PREVIEW_FRAGMENT_LENGTH)), false);
    assert.equal(serializedReport.includes(secretValue.slice(-RETIRED_EDGE_PREVIEW_FRAGMENT_LENGTH)), false);
  });
  assert.equal(serializedReport.includes("chars"), false);
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
  assert.equal(urlFinding?.metadata.preview, "[redacted:connection-string:https]");

  const cardFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.pii-pattern");
  assert.equal(cardFindings.length, 1);
  assert.match(cardFindings[0]?.message ?? "", /Credit card/);
  assert.equal(cardFindings[0]?.message.includes(CREDIT_CARD_FIXTURE_VALUE), false);
  assert.equal(JSON.stringify(cardFindings[0]?.metadata).includes(CREDIT_CARD_FIXTURE_VALUE), false);
  assert.equal(cardFindings[0]?.metadata.preview, "[redacted:payment-card]");
  assert.equal("digits" in (cardFindings[0]?.metadata ?? {}), false);
  assert.equal(JSON.stringify(report).includes(INVALID_CREDIT_CARD_FIXTURE_VALUE), false);
});

// Fixture purpose: every category marker is produced without configuration, and the key that claimed to govern them is gone.
// Stable contract: markers are unconditional, so no configuration can widen, narrow, or silence them.
test("category markers stand on their own and any configured preview key is refused", () => {
  const source = `REMOTE_CONTROL_URL=${URL_CREDENTIAL_FIXTURE_VALUE}
PAYMENT_CARD=${CREDIT_CARD_FIXTURE_VALUE}
`;
  const report = analyseFixture(source, { fileName: ".env" });
  const findings = report.findings
    .filter((finding) => ["sensitive-data.database-url-password", "sensitive-data.pii-pattern"].includes(finding.ruleId))
    .map((finding) => [finding.ruleId, finding.metadata.preview]);

  assert.equal(findings.length, EXPECTED_NEW_DETECTOR_FINDINGS);
  // An empty list reads as configured redaction just as a populated one does, so presence alone is the rejection.
  assert.throws(
    () => analyseFixture(source, { fileName: ".env", config: { allowlists: { secretPreviews: [] } } }),
    /section 5/,
  );
});

test("same-category occurrences stay separate without any preview configuration", () => {
  const firstShortSecret = ["a1B2c3D4", "e5F6g7H8"].join("");
  const secondShortSecret = ["j9K0m1N2", "p3Q4r5S6"].join("");
  assert.equal(firstShortSecret.length, secondShortSecret.length);

  const report = analyseFixture(`FIRST_TOKEN=${firstShortSecret}\nSECOND_TOKEN=${secondShortSecret}\n`, { fileName: ".env" });
  const findings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value");

  assert.deepEqual(findings.map((finding) => finding.metadata.keyName), ["FIRST_TOKEN", "SECOND_TOKEN"]);
  assert.equal(findings.every((finding) => finding.metadata.preview === "[redacted]"), true);
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
  assert.deepEqual(
    phiReport.findings
      .filter((finding) => finding.ruleId === "sensitive-data.phi-pattern")
      .map((finding) => finding.metadata.preview),
    ["[redacted:medicare]", "[redacted:mrn]"],
  );
  assert.equal(
    gcpReport.findings.find((finding) => finding.ruleId === "sensitive-data.gcp-service-account-key")?.metadata.preview,
    "[redacted:gcp-service-account]",
  );
  assert.equal(
    gcpReport.findings.find((finding) => finding.ruleId === "sensitive-data.private-key")?.metadata.preview,
    "[redacted:private-key]",
  );

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
  // Users can still disable the rule or raise its minimum length; findings retain only safe key, threshold, and marker metadata.
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

// Each fragment stays below the 24-character candidate floor while the joined values retain complete
// package integrity shapes. This is the stable fixture contract for repository self-scans.
const SHA1_INTEGRITY_FIXTURE_VALUE = ["sha1-p3SS9LEdzHxEaj", "Sz4ochr9M8ZCo="].join("");
const SHA512_INTEGRITY_FIXTURE_VALUE = [
  "sha512-Zx7pQ9vLm3N8sT2",
  "rY6wK1dF4gH5jC0bR2",
  "mN5pQ8sR1tV4xY7zA0",
  "bC3dE6fG9hI2jK5lM8",
  "nO1pQ4rS7tU0vW3xY6",
  "zA9bC2dE5fG8h==",
].join("");

test("package-manager lockfiles drop entropy digests but keep credential findings", () => {
  const report = analyseProject({
    "package-lock.json": JSON.stringify({ integrity: SHA1_INTEGRITY_FIXTURE_VALUE, token: HIGH_ENTROPY_FIXTURE_VALUE }),
    "npm-shrinkwrap.json": JSON.stringify({ integrity: SHA512_INTEGRITY_FIXTURE_VALUE, token: HIGH_ENTROPY_FIXTURE_VALUE }),
    "pnpm-lock.yaml": `integrity: ${SHA512_INTEGRITY_FIXTURE_VALUE}\ntoken: ${HIGH_ENTROPY_FIXTURE_VALUE}\n`,
    "source.ts": `const embeddedToken = "${HIGH_ENTROPY_FIXTURE_VALUE}";\nvoid embeddedToken;\n`,
  });
  const sensitiveDataFindings = report.findings.filter((finding) => finding.pillar === "sensitive-data");
  const lockfilePaths = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml"];

  // A lockfile's integrity digests are published metadata, so no lockfile may raise entropy.
  assert.equal(
    sensitiveDataFindings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string" && lockfilePaths.includes(finding.filePath)),
    false,
  );
  // The identical value in authored source stays an error-severity finding.
  assert.equal(
    sensitiveDataFindings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string" && finding.filePath === "source.ts" && finding.severity === "error"),
    true,
  );
  // Key-name inference also misreads lockfiles: a package named `gtoken` makes its version
  // spec look like a credential assignment, so that detector is suppressed here too.
  assert.equal(
    sensitiveDataFindings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value" && lockfilePaths.includes(finding.filePath)),
    false,
  );
});

// A 0.5.0 corpus scan treated Angular's `gtoken` dependency line as a hardcoded credential.
// Generated dependency names containing `token` must remain quiet for users.
test("a lockfile dependency whose name contains token is not a credential", () => {
  const report = analyseProject({
    "pnpm-lock.yaml": "      gtoken: 8.0.0(supports-color@11.0.0)\n      gtoken: 7.1.0(encoding@0.1.13)(supports-color@11.0.0)\n",
  });

  assert.deepEqual(report.findings.filter((finding) => finding.pillar === "sensitive-data"), []);
});

// Lockfiles may exclude public digest shapes, but a credential pasted into a resolved URL must still reach the user's report and CI gate.
test("a credential inside a lockfile is still reported", () => {
  const resolvedUrl = `  "resolved": "${DATABASE_URL_FIXTURE_VALUE}/pkg.tgz"\n`;
  const report = analyseProject({
    "package-lock.json": `{\n${resolvedUrl}}\n`,
    "pnpm-lock.yaml": `resolved: ${DATABASE_URL_FIXTURE_VALUE}/pkg.tgz\n`,
  });
  const credentialFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.database-url-password");

  assert.deepEqual(
    [...new Set(credentialFindings.map((finding) => finding.filePath))].sort(),
    ["package-lock.json", "pnpm-lock.yaml"],
  );
});

test("integrity hashes outside lockfiles do not become high-entropy findings", () => {
  const report = analyseFixture(
    JSON.stringify({ legacyIntegrity: SHA1_INTEGRITY_FIXTURE_VALUE, integrity: SHA512_INTEGRITY_FIXTURE_VALUE }),
    { fileName: "registry-metadata.json" },
  );
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.high-entropy-string"), false);
});

// Counter-fixtures protect credential shapes from the readable-word exemption.
//
// Each value is assembled from safe fragments so repository self-scans stay quiet while runtime analysis must report all four.
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
  const jwtFinding = report.findings.find((finding) => finding.ruleId === "sensitive-data.jwt-token" && finding.line === 2);
  assert.equal(jwtFinding?.metadata.preview, "[redacted:jwt]");
});

test("hardcoded-env requires a quoted value in script files but not in config files", () => {
  // Quoted TypeScript literals remain findings, while unquoted right-hand sides are code expressions such as secret-provider plumbing.
  // The same unquoted value in a config file is literal user input and remains reportable.
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

// Fixture purpose: quoted assignment values exercise every quote style accepted by the scanner.
// Stable contract: matching quotes preserve an embedded hash as secret data.
test("hardcoded-env preserves hash characters inside matching quotes", () => {
  assert.equal(QUOTED_HASH_SECRET_FIXTURE_VALUE.length, EXPECTED_QUOTED_HASH_SECRET_LENGTH);
  const source = [
    `DOUBLE_TOKEN="${QUOTED_HASH_SECRET_FIXTURE_VALUE}"`,
    `SINGLE_TOKEN='${QUOTED_HASH_SECRET_FIXTURE_VALUE}'`,
    `BACKTICK_TOKEN=\`${QUOTED_HASH_SECRET_FIXTURE_VALUE}\``,
  ].join("\n");
  const report = analyseFixture(source, { fileName: ".env" });
  const findings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value");

  assert.deepEqual(findings.map((finding) => finding.metadata.keyName), ["DOUBLE_TOKEN", "SINGLE_TOKEN", "BACKTICK_TOKEN"]);
  assert.equal(findings.every((finding) => finding.metadata.preview === "[redacted]"), true);
  assert.equal(findings.every((finding) => !("length" in finding.metadata)), true);
});

// Fixture purpose: unquoted hashes exercise .env, YAML, INI, and npmrc assignment handling.
// Stable contract: comment text never inflates an unquoted value into a secret finding.
test("hardcoded-env does not inflate unquoted values with hash comments across config dialects", () => {
  const report = analyseProject({
    ".env": `TOKEN=${QUOTED_HASH_SECRET_FIXTURE_VALUE}\nPASSWORD=${SHORT_HASH_PREFIX} #${HASH_SECRET_SUFFIX}\n`,
    "config.yaml": `API_KEY: ${QUOTED_HASH_SECRET_FIXTURE_VALUE}\n`,
    "settings.ini": `SECRET=${QUOTED_HASH_SECRET_FIXTURE_VALUE}\n`,
    ".npmrc": `CREDENTIAL=${QUOTED_HASH_SECRET_FIXTURE_VALUE}\n`,
  });
  const findings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value");

  assert.deepEqual(findings, []);
});

test("payment-card detection requires card context for bare digit runs", () => {
  // Statistics can pass Luhn by coincidence, so bare or irregular digit runs need card vocabulary on the user's source line.
  // Card-context lines and canonical grouping remain reportable because their presentation provides stronger evidence.
  const bareCardDigits = CREDIT_CARD_FIXTURE_VALUE.replaceAll(" ", "");
  const irregularStatistic = `${bareCardDigits.slice(0, 8)}-${bareCardDigits.slice(8)}`;
  const report = analyseFixture(`const gdpByCountry = [4300000000000];
const cardNumber = "${bareCardDigits}";
const formatted = "${CREDIT_CARD_FIXTURE_VALUE}";
const irregularStatistic = "${irregularStatistic}";
void gdpByCountry; void cardNumber; void formatted; void irregularStatistic;
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
  assert.equal(awsFindings[0]?.metadata.preview, "[redacted:aws-access-key]");
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
  assert.equal(apiKeyFindings.find((finding) => finding.filePath === ".npmrc")?.metadata.preview, "[redacted:npm-token]");
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.hardcoded-env-value" && finding.filePath === ".pypirc"), true);
  assert.equal(renderReport(report, "json").includes(NPM_AUTH_TOKEN_FIXTURE_VALUE), false);
});

test("two distinct same-line secrets keep two findings with distinct columns", () => {
  const report = analyseFixture(`// File overview: same-line secret fixture.
const firstToken = "${HIGH_ENTROPY_FIXTURE_VALUE}"; const secondToken = "${API_TOKEN_FIXTURE_VALUE}";
`);
  const secrets = report.findings.filter((finding) => finding.ruleId === "sensitive-data.high-entropy-string");
  // Two distinct secrets on one line share a fingerprint (line-keyed) but must both survive as
  // findings; the column discriminator keeps dedupe from dropping the second occurrence (ADR-017).
  assert.equal(secrets.length, 2);
  assert.equal(secrets[0]?.line, secrets[1]?.line);
  assert.equal(typeof secrets[0]?.column, "number");
  assert.notEqual(secrets[0]?.column, secrets[1]?.column);
  assert.equal(secrets[0]?.fingerprint, secrets[1]?.fingerprint);
  assert.notEqual(secrets[0]?.stableIdentity, secrets[1]?.stableIdentity);
  const previews = secrets.map((finding) => String(finding.metadata.preview));
  assert.deepEqual(previews, ["[redacted]", "[redacted]"]);
});

test("different-rule secrets on one line stay distinct findings", () => {
  const report = analyseFixture(`// File overview: mixed same-line secret fixture.
const mixed = "${AWS_ACCESS_KEY_FIXTURE_VALUE}"; const other = "${HIGH_ENTROPY_FIXTURE_VALUE}";
`);
  const sameLineFindings = report.findings.filter((finding) => finding.pillar === "sensitive-data" && finding.line === 2);
  const ruleIds = new Set(sameLineFindings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("sensitive-data.aws-access-key"), true);
  assert.equal(ruleIds.has("sensitive-data.high-entropy-string"), true);
});
