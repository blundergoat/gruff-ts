// Sensitive-data analysis turns reportable secret-like source occurrences into safe findings.
//
// It runs each detector in a stable order so repeated scans remain comparable.
// Users receive fixed category markers, actionable locations, and one report entry per occurrence without matched characters or lengths.
import { createHash } from "node:crypto";
import { makeFinding } from "./findings.ts";
import { byteColumn, byteLine } from "./text-scans.ts";
import type { Finding } from "./types.ts";

// Describes the safe file context needed to locate a sensitive finding for the user.
//
// The report-facing path is sufficient for navigation, and findings carry nothing else.
interface SensitiveSourceFile {
  displayPath: string;
}

// Runs every sensitive-data detector for one user file in deterministic report order.
// Keeping pattern order stable prevents baseline churn when no source behavior changed.
function analyseSensitiveData(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    // ASIA is AWS's prefix for temporary session credentials, over the same fixed body; missing it left a live
    // credential unnamed.
    ["sensitive-data.aws-access-key", /(?:AKIA|ASIA)[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /\b(?:https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql):\/\/[^\/\s:@]+:[^\/\s@]+@/g, "URL appears to include embedded credentials."],
    [
      "sensitive-data.api-key-pattern",
      /\b(?:sk_live_[A-Za-z0-9_-]{12,}|sk_test_[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gh[ousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+|https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+)\b/g,
      "API key pattern detected.",
    ],
    ["sensitive-data.pii-pattern", /\b\d{3}-\d{2}-\d{4}\b/g, "PII-like identifier pattern detected."],
    ["sensitive-data.phi-pattern", /\b[1-9][ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY0-9]\d[ACDEFGHJKMNPQRTUVWXY][ACDEFGHJKMNPQRTUVWXY]\d\d\b/g, "Medicare Beneficiary Identifier (PHI) pattern detected."],
  ];

  // Each detector family contributes findings in this documented order so users do not see unexplained report churn.
  for (const [ruleId, pattern, message] of patterns) {
    // Every matched occurrence remains independently visible, including multiple findings on the same source line.
    for (const match of source.matchAll(pattern)) {
      // A missing regex capture is treated as empty source evidence and will be ignored by the explicit-example guard.
      const matchedSensitiveText = match[0] ?? "";
      // Explicit placeholders are teaching material rather than credentials the user needs to rotate. An AWS key
      // is one fixed-shape alphanumeric run, where a marker word can only sit inside the value and never begin a
      // token, so only a mask silences it and AWS's documented example key reports, as it does in every port.
      const isPlaceholder = ruleId === "sensitive-data.aws-access-key" ? isMaskedAwsAccessKey(matchedSensitiveText) : isExplicitExampleCredential(matchedSensitiveText);
      if (isPlaceholder) {
        continue;
      }
      // A URL shape written as a template literal type names no credential at all.
      if (ruleId === "sensitive-data.database-url-password" && isTypeLevelUrlCredential(matchedSensitiveText)) {
        continue;
      }
      pushSensitiveFinding({
        findings,
        file,
        ruleId,
        message,
        line: byteLine(source, match.index ?? 0),
        column: byteColumn(source, match.index ?? 0),
        matchedSensitiveText,
        confidence: "high",
      });
    }
  }

  analyseNpmAuthTokens(file, source, findings);
  analysePhiLabelledIdentifiers(file, source, findings);
  analysePaymentCardNumbers(file, source, findings);
  analyseGcpServiceAccountKeys(file, source, findings);
}

// Recognizes a URL credential written in type position: a template literal type such as
// `mongodb://${string}:${string}@${string}` interpolates the type keywords `string` or `number`, which a runtime
// template would mean only through a variable of that name, so its userinfo describes a shape rather than holding a
// password. Only a password that is wholly one such interpolation, straight after the user, qualifies: a literal
// password beside a `${string}` user, or one written before a `:${string}` suffix, still reports. A runtime template
// that interpolates user and password variables into the userinfo still reports, and the pattern still stops at `@`:
// extending it to the host
// would let the substring example markers below silence any host containing "example", which waits for ratified
// host semantics (M22 activation bundle, decision 4).
function isTypeLevelUrlCredential(matchedSensitiveText: string): boolean {
  return /:\/\/[^\/\s:@]+:\$\{\s*(?:string|number)\s*\}@$/.test(matchedSensitiveText);
}

// Recognizes explicit example markers inside the matched value, such as a URL password written as `REDACTED`.
// File paths never make production-shaped credentials disappear from the user's report.
function isExplicitExampleCredential(matchedSensitiveText: string): boolean {
  return /EXAMPLE|REDACTED|PLACEHOLDER|CHANGEME/i.test(matchedSensitiveText) || isMaskedCredential(matchedSensitiveText);
}

// Recognizes an AWS key whose whole body is a run of X, written to show where a key goes (FAMILY-CONTRACT.md
// section 5). Only the whole body counts: a real key may contain a run of X, and hiding it would hide a live credential.
function isMaskedAwsAccessKey(matchedSensitiveText: string): boolean {
  return /^(?:AKIA|ASIA)X{16}$/.test(matchedSensitiveText);
}

// Recognizes a value whose body was masked out with a run of `*` or `X`, which names no credential at all.
function isMaskedCredential(matchedSensitiveText: string): boolean {
  return /\*{4}|X{4}/.test(matchedSensitiveText);
}

// Finds medical-record numbers only when an MRN label gives users reliable health-data context.
// Stable contract: bare numbers remain quiet, while each labelled identifier receives its own fixed-marker finding.
function analysePhiLabelledIdentifiers(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  // Each source line may represent a separate record the user accidentally embedded in code or a fixture.
  for (const [index, line] of lines.entries()) {
    const match = line.match(/\b(?:MRN|medical[\s_-]?record(?:[\s_-]?number)?)\b\s*[:=#]?\s*([0-9]{6,12})\b/i);
    const medicalRecordNumber = match?.[1];
    // No labelled value means this line cannot produce an MRN finding for the user.
    if (!medicalRecordNumber) {
      continue;
    }
    pushSensitiveFinding({
      findings,
      file,
      ruleId: "sensitive-data.phi-pattern",
      message: "Medical record number (PHI) detected.",
      line: index + 1,
      column: (match.index ?? 0) + 1,
      matchedSensitiveText: medicalRecordNumber,
      confidence: "high",
    });
  }
}

// Finds a GCP service-account document only when its type and private-key evidence appear together.
// Stable contract: users receive one marker at the type field, while matched identifiers and key material stay hidden.
function analyseGcpServiceAccountKeys(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const typeMatch = source.match(/"type"\s*:\s*"service_account"/);
  // Users see a finding only when the document contains both the service-account type and private-key evidence.
  if (!typeMatch || !/"private_key"\s*:\s*"|BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY/.test(source)) {
    return;
  }
  pushSensitiveFinding({
    findings,
    file,
    ruleId: "sensitive-data.gcp-service-account-key",
    message: "GCP service-account key file detected.",
    line: byteLine(source, typeMatch.index ?? 0),
    column: byteColumn(source, typeMatch.index ?? 0),
    matchedSensitiveText: "service_account",
    confidence: "high",
  });
}

// Finds payment-card values only after network shape, length, checksum, and context checks pass.
// Stable contract: canonical grouping supplies context; bare digit runs need card vocabulary before users see a finding.
function analysePaymentCardNumbers(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  // Each digit run is checked independently because a user can paste more than one card-like value into a line or file.
  for (const match of source.matchAll(/\b(?:\d[ -]?){12,18}\d\b/g)) {
    // A missing regex capture becomes an empty candidate, which cannot pass the network and checksum gates.
    const matchedDigitRun = match[0] ?? "";
    const normalizedCardNumber = normalizedPaymentCardNumber(matchedDigitRun);
    const line = byteLine(source, match.index ?? 0);
    // The helper owns the shape/checksum/vocabulary gates; anything failing them is not a card.
    if (!isReportablePaymentCardCandidate(matchedDigitRun, normalizedCardNumber, lines[line - 1] ?? "")) {
      continue;
    }
    pushSensitiveFinding({
      findings,
      file,
      ruleId: "sensitive-data.pii-pattern",
      message: "Credit card number (PII) pattern detected.",
      line,
      column: byteColumn(source, match.index ?? 0),
      matchedSensitiveText: matchedDigitRun,
      confidence: "high",
      metadata: { piiKind: "credit-card" },
    });
  }
}

// Decides whether one digit run is credible card data for the user's report.
// Valid cards need canonical grouping or explicit card vocabulary because ordinary statistics can pass Luhn.
function isReportablePaymentCardCandidate(matchedDigitRun: string, normalizedCardNumber: string, contextLine: string): boolean {
  // Invalid network shape, length, or checksum means the user entered an ordinary number rather than reportable card data.
  if (!isPaymentCardNumber(normalizedCardNumber)) {
    return false;
  }
  return hasCanonicalPaymentCardGrouping(matchedDigitRun, normalizedCardNumber) || hasPaymentCardContext(contextLine);
}

// Accept one consistent separator and the display grouping used by the detected card network.
// Arbitrary chunks such as 8-8 remain statistics unless their source line supplies card context.
function hasCanonicalPaymentCardGrouping(matchedDigitRun: string, normalizedCardNumber: string): boolean {
  // Missing separators mean a bare number needs explicit card vocabulary elsewhere on the line.
  const separators = matchedDigitRun.match(/[ -]/g) ?? [];
  // Mixed or absent separators do not provide the canonical grouping users expect for a card number.
  if (separators.length === 0 || new Set(separators).size !== 1) {
    return false;
  }
  const groupSizes = matchedDigitRun.split(separators[0] ?? " ").map((group) => group.length);
  const expectedGroupSizes = isAmericanExpressPaymentCard(normalizedCardNumber)
    ? [4, 6, 5]
    : isDinersPaymentCard(normalizedCardNumber)
      ? [4, 6, 4]
      : Array.from({ length: Math.ceil(normalizedCardNumber.length / 4) }, (_, index) => Math.min(4, normalizedCardNumber.length - index * 4));
  return groupSizes.length === expectedGroupSizes.length && groupSizes.every((size, index) => size === expectedGroupSizes[index]);
}

// Recognizes card vocabulary around an otherwise ambiguous digit run.
// Identifier forms such as `cardNumber` count, while `pan` stays word-bounded to avoid unrelated UI text.
function hasPaymentCardContext(lineText: string): boolean {
  return /(?:\bpan\b|card|payment|credit|debit|visa|master|amex|discover|jcb|diners)/i.test(lineText);
}

// Finds npm auth values in user configuration even when the token lacks an `npm_` prefix.
// Stable contract: scoped and registry `_authToken` lines remain reportable when the general provider pattern cannot classify their prefix.
function analyseNpmAuthTokens(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  // Each config line can contain a separate registry credential the user needs to rotate.
  for (const [index, line] of lines.entries()) {
    const token = npmAuthTokenValue(line);
    // No supported `_authToken` value means this line contributes no npm credential finding.
    if (!token) {
      continue;
    }
    pushSensitiveFinding({
      findings,
      file,
      ruleId: "sensitive-data.api-key-pattern",
      message: "npm auth token pattern detected.",
      line: index + 1,
      matchedSensitiveText: token,
      confidence: "high",
      metadata: { keyName: "_authToken" },
    });
  }
}

// Returns the token portion of a scoped or registry-prefixed npm auth line.
// Missing output means the user's line has no supported literal token for this detector.
function npmAuthTokenValue(line: string): string | undefined {
  const match = line.match(/(?:^|:)_authToken\s*=\s*([A-Za-z0-9_-]{20,})\b/);
  return match?.[1];
}

// Describes one reportable sensitive occurrence before the finding is built.
//
// Optional column and metadata enrich the user's report when available.
// Contract: matched text is used only to choose a fixed public category and never reaches report output or identity.
interface SensitiveFindingArgs {
  findings: Finding[];
  file: SensitiveSourceFile;
  ruleId: string;
  message: string;
  line: number;
  column?: number;
  matchedSensitiveText: string;
  confidence: Finding["confidence"];
  metadata?: Record<string, unknown>;
}

// SHA-256 digests of the 20 values vendors publish as documentation samples, so code that pastes one never reports.
//
// They cover AWS and jwt.io examples, fourteen published test cards and Google's reCAPTCHA v2 test site key.
// Digests keep the literals out of this source (FAMILY-CONTRACT.md section 5).
const DOCUMENTED_SAMPLE_DIGESTS = new Set([
  "03b970ed8171d73b58bbc9a5c72e3e4eec28503b56b3bb400a0801857dd45614",
  "19ff47cc8024c133d5845d3f8938caca289929031e7d508c3adf7adff177f0c2",
  "1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3",
  "1c9d38ed26cd808fa3b02b9b3b988a7caf474e2e42d95789c0fe07e267c80d8f",
  "2f725bbd1f405a1ed0336abaf85ddfeb6902a9984a76fd877c3b5cc3b5085a82",
  "304945e91de3deff52a61d08733141d72dd42ec9d47972f1060534d54c0c7f90",
  "3a134ef77d4e2e4cdad2d2945ff1f76c1a23296c93c851f6244220a8cedea130",
  "477bba133c182267fe5f086924abdc5db71f77bfc27f01f2843f2cdc69d89f05",
  "51a4ae4c6ae999146474a67cbcb3b05fbcf4c17ab683043a066459da95513ea8",
  "53a8fc816e63b7a5ccd17aaff93f28bcf13abbf418209dcd93947722d7c326ba",
  "576c15a8072461c216efb9bd7306a6fc6039b43a6763c4c1a05930a2dd7b788f",
  "78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598",
  "7f75367e7881255134e1375e723d1dea8ad5f6a4fdb79d938df1f1754a830606",
  "9bbef19476623ca56c17da75fd57734dbf82530686043a6e491c6d71befe8f6e",
  "c6ea27c534f993d31f0aef882e3d200e7b87470c379ae79c8f9b19d3bd363dc9",
  "d79449f462cec9af0d857c3e1af888d4fa8bbdaa511b9eaaafcd2805c4ea6471",
  "d8086d483c15c711ebba19f966b97d3c2adcba74025ff8d7e07c3698c9531deb",
  "dd13cdf9af9dd3baf46ce96aecd7163cabf381ccb21e63f15f0fa10b1c663fa9",
  "e21b597ba6b9cafa59d9ebc4d65c0385f5eb3fa56abab2607fa76589ad849a33",
  "f41e7ca4a3d71c4f047581f2ae2d6a8dbb8c58e51a020fa227edc724474aab6e",
]);

// Reports whether a matched value is, exactly and whole, a vendor-documented sample such as AWS's example key.
// A card is compared as digits, so its spaced and dashed spellings match the number its network publishes.
function isDocumentedSample(matchedSensitiveText: string, metadata: Record<string, unknown> | undefined): boolean {
  const comparedText = metadata?.["piiKind"] === "credit-card" ? matchedSensitiveText.replace(/\D/g, "") : matchedSensitiveText;
  return DOCUMENTED_SAMPLE_DIGESTS.has(createHash("sha256").update(comparedText, "utf8").digest("hex"));
}

// Reports one user-visible finding with a detector-owned marker and an optional match column.
// The matched value only selects a public category and recognises a vendor-documented sample; every other occurrence reaches the report.
function pushSensitiveFinding(args: SensitiveFindingArgs): void {
  // A pasted documentation sample, e.g. AWS's example key id from its docs, is not a credential, so the user sees nothing.
  if (isDocumentedSample(args.matchedSensitiveText, args.metadata)) {
    return;
  }
  const displayMarker = fixedMarkerForSensitiveFinding(args);
  // Missing location and metadata fields remain absent or empty so report consumers can distinguish unavailable user context.
  args.findings.push(
    makeFinding({
      ruleId: args.ruleId,
      message: `${args.message} Redacted preview: ${displayMarker}.`,
      filePath: args.file.displayPath,
      line: args.line,
      ...(args.column === undefined ? {} : { column: args.column }),
      severity: "warning",
      pillar: "sensitive-data",
      confidence: args.confidence,
      remediation: "Remove the sensitive value and load it from a secure runtime source.",
      metadata: { ...(args.metadata ?? {}), preview: displayMarker },
    }),
  );
}

// Selects the fixed category marker users see for one sensitive finding.
// Detector-owned rule and metadata categories may classify the match, but no matched characters or lengths are returned.
function fixedMarkerForSensitiveFinding(args: SensitiveFindingArgs): string {
  switch (args.ruleId) {
    case "sensitive-data.aws-access-key":
      return "[redacted:aws-access-key]";
    case "sensitive-data.private-key":
      return "[redacted:private-key]";
    case "sensitive-data.jwt-token":
      return "[redacted:jwt]";
    case "sensitive-data.database-url-password":
      return fixedConnectionStringMarker(args.matchedSensitiveText);
    case "sensitive-data.api-key-pattern":
      return fixedApiKeyMarker(args.matchedSensitiveText, args.metadata);
    case "sensitive-data.pii-pattern":
      return args.metadata?.piiKind === "credit-card" ? "[redacted:payment-card]" : "[redacted:ssn]";
    case "sensitive-data.phi-pattern":
      return /^\d+$/.test(args.matchedSensitiveText) ? "[redacted:mrn]" : "[redacted:medicare]";
    case "sensitive-data.gcp-service-account-key":
      return "[redacted:gcp-service-account]";
    default:
      return "[redacted]";
  }
}

// Builds the fixed connection-string marker users see, retaining only the detector-approved public scheme.
// Missing classification returns the generic marker and never echoes any URL characters.
function fixedConnectionStringMarker(matchedUrl: string): string {
  const acceptedScheme = matchedUrl.match(/^(https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql):\/\//i)?.[1]?.toLowerCase();
  // A missing detector-approved scheme gives users a generic marker rather than echoing any URL text.
  if (!acceptedScheme) {
    return "[redacted]";
  }
  return `[redacted:connection-string:${acceptedScheme}]`;
}

// Builds the fixed provider marker users see for recognizable API-key families.
// Unknown or shared prefixes use the generic marker so no matched token characters are exposed.
function fixedApiKeyMarker(matchedToken: string, metadata: Record<string, unknown> | undefined): string {
  // An npm auth line may omit the public `npm_` prefix, but its detector-owned key name still identifies the category.
  if (metadata?.keyName === "_authToken" || matchedToken.startsWith("npm_")) {
    return "[redacted:npm-token]";
  }
  // A GitHub public prefix gives users the provider category without disclosing any token payload.
  if (/^(?:ghp_|github_pat_|gh[ousr]_)/.test(matchedToken)) {
    return "[redacted:github-token]";
  }
  // Slack tokens and webhook URLs share one fixed provider marker in user reports.
  if (/^(?:xox[baprs]-|https:\/\/hooks\.slack\.com\/services\/)/.test(matchedToken)) {
    return "[redacted:slack-token]";
  }
  // The public live-key prefix distinguishes Stripe production credentials for rotation guidance.
  if (matchedToken.startsWith("sk_live_")) {
    return "[redacted:stripe-live-key]";
  }
  // The public Google prefix selects a provider marker without revealing the remaining key.
  if (matchedToken.startsWith("AIza")) {
    return "[redacted:google-api-key]";
  }
  // The public Anthropic prefix selects a provider marker without revealing the remaining key.
  if (matchedToken.startsWith("sk-ant-")) {
    return "[redacted:anthropic-api-key]";
  }
  // The public GitLab prefix selects a provider marker without revealing the remaining token.
  if (matchedToken.startsWith("glpat-")) {
    return "[redacted:gitlab-token]";
  }
  return "[redacted]";
}

// Removes spaces and hyphens before validating a payment-card value the user may have pasted.
// The normalized digits are used only for network and checksum checks, never report output.
function normalizedPaymentCardNumber(candidateText: string): string {
  return candidateText.replace(/[ -]/g, "");
}

// Checks issuer shape, supported length, and Luhn checksum before showing a payment-card finding.
// Ordinary long numbers stay out of the user's report when any gate fails.
function isPaymentCardNumber(cardNumber: string): boolean {
  return /^[0-9]+$/.test(cardNumber) && cardNumber.length >= 13 && cardNumber.length <= 19 && hasKnownPaymentCardPrefix(cardNumber) && passesLuhnCheck(cardNumber);
}

// Checks a normalized card value against the supported issuer prefixes.
// Network-specific helpers keep user-facing false-positive tuning isolated and readable.
function hasKnownPaymentCardPrefix(cardNumber: string): boolean {
  return isVisaPaymentCard(cardNumber)
    || isMastercardPaymentCard(cardNumber)
    || isAmericanExpressPaymentCard(cardNumber)
    || isDiscoverPaymentCard(cardNumber)
    || isDinersPaymentCard(cardNumber)
    || isJcbPaymentCard(cardNumber);
}

// Visa cards start with 4 and commonly use 13, 16, or 19 digits.
function isVisaPaymentCard(cardNumber: string): boolean {
  return cardNumber.startsWith("4") && isPaymentCardLength(cardNumber, [13, 16, 19]);
}

// Mastercard cards use 51-55 and 2221-2720 IIN ranges with 16 digits.
function isMastercardPaymentCard(cardNumber: string): boolean {
  const firstTwoDigits = Number(cardNumber.slice(0, 2));
  const firstFourDigits = Number(cardNumber.slice(0, 4));
  return (isInRange(firstTwoDigits, 51, 55) || isInRange(firstFourDigits, 2221, 2720)) && isPaymentCardLength(cardNumber, [16]);
}

// American Express cards use 34/37 prefixes with 15 digits.
function isAmericanExpressPaymentCard(cardNumber: string): boolean {
  return (cardNumber.startsWith("34") || cardNumber.startsWith("37")) && isPaymentCardLength(cardNumber, [15]);
}

// Discover cards use 6011, 65, or 644-649 prefixes with 16 or 19 digits.
function isDiscoverPaymentCard(cardNumber: string): boolean {
  const firstThreeDigits = Number(cardNumber.slice(0, 3));
  return (cardNumber.startsWith("6011") || cardNumber.startsWith("65") || isInRange(firstThreeDigits, 644, 649)) && isPaymentCardLength(cardNumber, [16, 19]);
}

// Diners Club cards use 300-305, 36, 38, or 39 prefixes with 14 digits.
function isDinersPaymentCard(cardNumber: string): boolean {
  const firstThreeDigits = Number(cardNumber.slice(0, 3));
  return (isInRange(firstThreeDigits, 300, 305) || cardNumber.startsWith("36") || cardNumber.startsWith("38") || cardNumber.startsWith("39")) && isPaymentCardLength(cardNumber, [14]);
}

// JCB cards use 3528-3589 prefixes with 16-19 digits.
function isJcbPaymentCard(cardNumber: string): boolean {
  const firstFourDigits = Number(cardNumber.slice(0, 4));
  return isInRange(firstFourDigits, 3528, 3589) && isPaymentCardLength(cardNumber, [16, 17, 18, 19]);
}

// Checks whether a normalized card uses a length supported by its detected network.
// Keeping the length table explicit makes the user-facing classification easier to audit.
function isPaymentCardLength(cardNumber: string, allowedLengths: number[]): boolean {
  return allowedLengths.includes(cardNumber.length);
}

// Checks an issuer identification number against an inclusive network range.
// Card-prefix helpers use it to decide whether the user should receive a payment-data finding.
function isInRange(candidateNumber: number, minimum: number, maximum: number): boolean {
  return candidateNumber >= minimum && candidateNumber <= maximum;
}

// Runs the standard Luhn checksum over normalized digits before a card finding reaches the user.
// Invalid checksums keep ordinary long numeric identifiers quiet.
function passesLuhnCheck(cardNumber: string): boolean {
  const digits = [...cardNumber].reverse().map((digit) => Number(digit));
  const sum = digits.reduce((total, digit, index) => total + luhnDigitContribution(digit, index), 0);
  return sum % 10 === 0;
}

// Calculates one digit's Luhn contribution while validating a possible payment-card value.
// Even-positioned digits from the right remain unchanged; alternating digits are doubled and folded.
function luhnDigitContribution(digit: number, indexFromRight: number): number {
  // Even positions from the right contribute their original digit to the user's card-validity decision.
  if (indexFromRight % 2 === 0) {
    return digit;
  }
  const doubled = digit * 2;
  return doubled > 9 ? doubled - 9 : doubled;
}

export { analyseSensitiveData };
