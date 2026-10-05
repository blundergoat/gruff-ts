// Sensitive-data detector tests cover the findings users receive for synthetic secret-like input.
//
// Fixtures prove fixed markers and retained occurrence counts across every renderer.
// All examples are synthetic and assembled safely so the repository never stores real credentials.
import assert from "node:assert/strict";
import test from "node:test";
import { renderReport, ruleDescriptors } from "./cli.ts";
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

const SENSITIVE_DATA_RULE_IDS = ["sensitive-data.api-key-pattern", "sensitive-data.database-url-password", "sensitive-data.pii-pattern"];
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
  // Users can still disable a sensitive-data rule or raise its severity; findings keep only the fixed marker.
  const ruleId = "sensitive-data.api-key-pattern";
  const source = `GOOGLE_API_KEY=${GOOGLE_API_KEY_FIXTURE_VALUE}
`;
  const defaultReport = analyseFixture(source, { fileName: ".env" });
  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === ruleId), true);

  const disabledReport = analyseFixture(source, { fileName: ".env", config: { rules: { [ruleId]: { enabled: false } } } });
  assert.equal(disabledReport.findings.some((finding) => finding.ruleId === ruleId), false);

  const raisedReport = analyseFixture(source, { fileName: ".env", config: { rules: { [ruleId]: { severity: "error" } } } });
  assert.equal(raisedReport.findings.find((finding) => finding.ruleId === ruleId)?.severity, "error");
});

// A 0.5.0 corpus scan treated Angular's `gtoken` dependency line as a hardcoded credential.
// Generated dependency names containing `token` must remain quiet for users.
test("a lockfile dependency whose name contains token is not a credential", () => {
  const report = analyseProject({
    "pnpm-lock.yaml": "      gtoken: 8.0.0(supports-color@11.0.0)\n      gtoken: 7.1.0(encoding@0.1.13)(supports-color@11.0.0)\n",
  });

  assert.deepEqual(report.findings.filter((finding) => finding.pillar === "sensitive-data"), []);
});

// A credential pasted into a lockfile's resolved URL must still reach the user's report and CI gate.
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

// JWT ships off by default (ADR-021).
// Stable contract: a default run stays silent, and a project that enables it gets the fixed marker.
test("jwt-token stays silent by default and reports its fixed marker once enabled", () => {
  const source = `const webToken = "${JWT_FIXTURE_VALUE}";\nvoid webToken;\n`;
  assert.equal(analyseFixture(source).findings.some((finding) => finding.ruleId === "sensitive-data.jwt-token"), false);
  const enabledReport = analyseFixture(source, { config: { rules: { "sensitive-data.jwt-token": { enabled: true } } } });
  const jwtFinding = enabledReport.findings.find((finding) => finding.ruleId === "sensitive-data.jwt-token");
  assert.equal(jwtFinding?.line, 1);
  assert.equal(jwtFinding?.severity, "warning");
  assert.equal(jwtFinding?.metadata.preview, "[redacted:jwt]");
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

test("a marker word silences a URL password but not a fixed-shape key, and a masked key stays quiet", () => {
  // Family decision of 2026-09-20, amended 2026-09-26 (M10 D33): a marker word inside a fixed-shape key begins no
  // token, so it silences nothing, but AWS's documented example key is a vendor-documented sample and never reports.
  // Redaction fixtures still use REDACTED, and a masked key names no credential.
  const awsDocExampleKey = ["AKIAIOSFODNN7", "EXAMPLE"].join("");
  const redactedUrl = "postgres://app:REDACTED@db.internal/app";
  const maskedKey = ["AKIA", "X".repeat(16)].join("");
  const report = analyseFixture(`AWS_KEY_ONE=${awsDocExampleKey}
AWS_KEY_TWO=${AWS_ACCESS_KEY_FIXTURE_VALUE}
URL_ONE=${redactedUrl}
URL_TWO=${URL_CREDENTIAL_FIXTURE_VALUE}
AWS_KEY_THREE=${maskedKey}
`, { fileName: ".env" });
  const awsFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");
  assert.deepEqual(awsFindings.map((finding) => finding.line), [2]);
  assert.equal(awsFindings[0]?.metadata.preview, "[redacted:aws-access-key]");
  const urlFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.database-url-password");
  assert.deepEqual(urlFindings.map((finding) => finding.line), [4]);
});

test("an ASIA session token reports as an AWS access key, and a masked one stays quiet", () => {
  // AWS issues temporary session credentials under the ASIA prefix over the same fixed body, so a rule that
  // named only AKIA left a live credential unreported. gruff-php and gruff-py already named both shapes.
  const sessionToken = ["ASIA", "IOSFODNN7", "EXAMPLE"].join("");
  const maskedSession = ["ASIA", "X".repeat(16)].join("");
  const report = analyseFixture(`AWS_SESSION_ONE=${sessionToken}
AWS_SESSION_TWO=${maskedSession}
`, { fileName: ".env" });
  const awsFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");

  assert.deepEqual(awsFindings.map((finding) => finding.line), [1]);
  assert.equal(awsFindings[0]?.metadata.preview, "[redacted:aws-access-key]");
});

test("an AWS key reads as masked only when its whole body is X", () => {
  // FAMILY-CONTRACT.md section 5 reads a body that is entirely X as naming no credential, while a real key that
  // merely contains a run of X still reports, because hiding it would hide a live credential.
  const masked = ["AKIA", "X".repeat(16)].join("");
  const partlyMasked = ["AKIA", "IOSFODNN", "X".repeat(8)].join("");
  const report = analyseFixture(`AWS_KEY_ONE=${masked}
AWS_KEY_TWO=${partlyMasked}
`, { fileName: ".env" });
  const awsFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");

  assert.deepEqual(awsFindings.map((finding) => finding.line), [2]);
});

test("sensitive-data expansion scans secret dotfiles", () => {
  const report = analyseProject({
    ".npmrc": `//registry.npmjs.org/:_authToken=${NPM_AUTH_TOKEN_FIXTURE_VALUE}
`,
    ".pypirc": `[pypi]
repository = ${URL_CREDENTIAL_FIXTURE_VALUE}
`,
  });

  const apiKeyFindings = report.findings.filter((finding) => finding.ruleId === "sensitive-data.api-key-pattern");
  assert.equal(report.paths.analysedFiles, EXPECTED_SECRET_DOTFILE_ANALYSED_FILES);
  assert.equal(apiKeyFindings.some((finding) => finding.filePath === ".npmrc"), true);
  assert.equal(apiKeyFindings.find((finding) => finding.filePath === ".npmrc")?.metadata.preview, "[redacted:npm-token]");
  assert.equal(report.findings.some((finding) => finding.ruleId === "sensitive-data.database-url-password" && finding.filePath === ".pypirc"), true);
  assert.equal(renderReport(report, "json").includes(NPM_AUTH_TOKEN_FIXTURE_VALUE), false);
});

test("two distinct same-line secrets keep two findings with distinct columns", () => {
  const report = analyseFixture(`// File overview: same-line secret fixture.
const firstKey = "${AWS_ACCESS_KEY_FIXTURE_VALUE}"; const secondKey = "${["AKIA", "QWERTYUIOPASDFGH"].join("")}";
`);
  const secrets = report.findings.filter((finding) => finding.ruleId === "sensitive-data.aws-access-key");
  // Two distinct secrets on one line share a fingerprint (line-keyed) but must both survive as
  // findings; the column discriminator keeps dedupe from dropping the second occurrence (ADR-017).
  assert.equal(secrets.length, 2);
  assert.equal(secrets[0]?.line, secrets[1]?.line);
  assert.equal(typeof secrets[0]?.column, "number");
  assert.notEqual(secrets[0]?.column, secrets[1]?.column);
  assert.equal(secrets[0]?.fingerprint, secrets[1]?.fingerprint);
  assert.notEqual(secrets[0]?.stableIdentity, secrets[1]?.stableIdentity);
  const previews = secrets.map((finding) => String(finding.metadata.preview));
  assert.deepEqual(previews, ["[redacted:aws-access-key]", "[redacted:aws-access-key]"]);
});

test("different-rule secrets on one line stay distinct findings", () => {
  const report = analyseFixture(`// File overview: mixed same-line secret fixture.
const mixed = "${AWS_ACCESS_KEY_FIXTURE_VALUE}"; const other = "${GOOGLE_API_KEY_FIXTURE_VALUE}";
`);
  const sameLineFindings = report.findings.filter((finding) => finding.pillar === "sensitive-data" && finding.line === 2);
  const ruleIds = new Set(sameLineFindings.map((finding) => finding.ruleId));
  assert.equal(ruleIds.has("sensitive-data.aws-access-key"), true);
  assert.equal(ruleIds.has("sensitive-data.api-key-pattern"), true);
});

// M22 hunt shape (zod `template-literal.test.ts`): a URL written as a template literal type describes a shape. A
// runtime template, the family redaction corpus's connection string at `db.example.invalid`, the sample fixture and a
// JSDoc documentation-host URL all still report at error: the documentation-host half waits for ratified host semantics.
test("M22 database-url-password skips template literal types and keeps every runtime credential", () => {
  // Assembled from parts so this test file never holds a credential-shaped literal of its own.
  const credential = (scheme: string, user: string, secret: string, rest: string): string => [scheme, "://", user, ":", secret, "@", rest].join("");
  const report = analyseFixture([
    "export type MongoUrl =",
    "  | `" + credential("mongodb", "${string}", "${string}", "${string}:${number}") + "`",
    "  | `" + credential("mongodb", "admin", "${string}", "${string}/${string}") + "`;",
    "export function connect(user: string, password: string): string {",
    "  return `" + credential("postgres", "${user}", "${password}", "db.internal:5432/app") + "`;",
    "}",
    "export const databaseUrl = \"" + credential("postgres", "gruffuser", "Zq81Kx03Vt55Rm", "db.example.invalid:5432/appdb") + "\";",
    "export const secretUrl = \"" + credential("mysql", "demo", "password123", "example.test/app") + "\";",
    "/**",
    " * given URL " + credential("http", "user", "password", "example.com:8080/#/some/path"),
    " */",
    "export const documented = true;",
    "",
  ].join("\n"));
  const urlFindings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.database-url-password");

  assert.deepEqual(urlFindings.map((entry) => entry.line), [5, 7, 8, 10]);
  assert.equal(urlFindings.every((entry) => entry.severity === "warning"), true);
});

// The family unified sensitive-data severity at warning for 0.6.0: a detector that hard-fails a build on a match it
// cannot confirm teaches users to add blanket ignores. Every sensitive-data descriptor must say warning, and an
// unconfigured finding must carry the severity its descriptor publishes, not a detector-local fallback.
test("sensitive-data findings default to the warning their descriptors publish", () => {
  const sensitiveDescriptors = ruleDescriptors().filter((descriptor) => descriptor.pillar === "sensitive-data");
  assert.deepEqual(sensitiveDescriptors.filter((descriptor) => descriptor.severity !== "warning").map((descriptor) => descriptor.ruleId), []);

  // Assembled from parts so this test file never holds a credential-shaped literal of its own.
  const report = analyseFixture([
    "export const key = \"" + ["AKIA", "QWERTYUIOPASDFGH"].join("") + "\";",
    "export const token = \"" + GOOGLE_API_KEY_FIXTURE_VALUE + "\";",
    "",
  ].join("\n"));
  const sensitive = report.findings.filter((entry) => entry.pillar === "sensitive-data");

  assert.deepEqual([...new Set(sensitive.map((entry) => entry.ruleId))].sort(), ["sensitive-data.api-key-pattern", "sensitive-data.aws-access-key"]);
  assert.equal(sensitive.every((entry) => entry.severity === "warning"), true);
});

// M22 code review fixture: a template literal type is skipped only when its password is wholly a type interpolation
// straight after the user. A literal password written beside a `${string}` user, or before a `:${string}` suffix,
// still reports, because the type shapes the rest of the URL, not the secret.
test("M22 database-url-password still reports a literal password beside a type-level user", () => {
  // Assembled from parts so this test file never holds a credential-shaped literal of its own.
  const credential = (user: string, secret: string): string => ["postgres://", user, ":", secret, "@db.internal/app"].join("");
  const report = analyseFixture([
    "export type Shaped = `" + credential("${string}", "${number}") + "`;",
    "export type Leaked = `" + credential("${string}", ["Pr0d", "Passw0rd"].join("")) + "`;",
    "export type Suffixed = `" + credential("admin", ["Pr0d", "Passw0rd", ":${string}"].join("")) + "`;",
    "",
  ].join("\n"));
  const urlFindings = report.findings.filter((entry) => entry.ruleId === "sensitive-data.database-url-password");

  assert.deepEqual(urlFindings.map((entry) => entry.line), [2, 3]);
});
