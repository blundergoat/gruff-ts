// Sensitive-data analysis turns reportable secret-like source occurrences into safe findings.
//
// It runs each detector in a stable order so repeated scans remain comparable.
// Users receive fixed category markers, actionable locations, and one report entry per occurrence without matched characters or lengths.
import { ruleSeverity, threshold } from "./config.ts";
import { makeFinding } from "./findings.ts";
import { byteColumn, byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

// Describes the safe file context needed to locate a sensitive finding for the user.
//
// The report-facing path is sufficient for navigation.
// Absolute filesystem details and source content stay outside this boundary.
interface SensitiveSourceFile {
  displayPath: string;
}

// Runs every sensitive-data detector for one user file in deterministic report order.
// Keeping pattern order stable prevents baseline churn when no source behavior changed.
function analyseSensitiveData(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
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
      // Explicit placeholders are teaching material rather than credentials the user needs to rotate.
      if (isExplicitExampleCredential(matchedSensitiveText)) {
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

  analyseHardcodedEnvironmentValues(file, source, config, findings);
  analyseNpmAuthTokens(file, source, findings);
  analyseHighEntropyStrings(file, source, config, findings);
  analysePhiLabelledIdentifiers(file, source, findings);
  analysePaymentCardNumbers(file, source, findings);
  analyseGcpServiceAccountKeys(file, source, findings);
}

// Recognizes explicit example markers inside the matched value, such as an AWS key ending in `EXAMPLE`.
// File paths never make production-shaped credentials disappear from the user's report.
function isExplicitExampleCredential(matchedSensitiveText: string): boolean {
  return /EXAMPLE|REDACTED|PLACEHOLDER|CHANGEME/i.test(matchedSensitiveText) || /\*{4}|X{4}/.test(matchedSensitiveText);
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

// Finds literal assignments whose key tells users the value is secret-like, such as `API_KEY` or `PASSWORD`.
// Stable contract: the configured minimum length keeps short examples out of reports without suppressing credible values.
function analyseHardcodedEnvironmentValues(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const minLength = threshold(config, "sensitive-data.hardcoded-env-value", 16);
  const requiresQuotedValue = isScriptSourcePath(file.displayPath);
  const lines = source.split(/\r?\n/);
  // Each assignment is evaluated independently so users receive a location for every embedded value.
  for (const [index, line] of lines.entries()) {
    const hardcodedValue = hardcodedEnvValue(line, minLength, requiresQuotedValue);
    // A missing result means the line is empty, non-literal, placeholder-shaped, or below the user's threshold.
    if (!hardcodedValue) {
      continue;
    }
    pushSensitiveFinding({
      findings,
      file,
      ruleId: "sensitive-data.hardcoded-env-value",
      message: `Environment-style value \`${hardcodedValue.keyName}\` appears to be hardcoded with secret-like content.`,
      line: index + 1,
      matchedSensitiveText: hardcodedValue.value,
      confidence: "medium",
      metadata: { keyName: hardcodedValue.keyName, threshold: minLength },
      severity: ruleSeverity(config, "sensitive-data.hardcoded-env-value", "error"),
    });
  }
}

// Finds generated-looking string literals after length, character-class, and distinct-character checks.
// Stable contract: known integrity and public identifier shapes stay quiet so users can focus on credible secret material.
function analyseHighEntropyStrings(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const minLength = threshold(config, "sensitive-data.high-entropy-string", 32);
  // Every long literal is checked separately so same-line secrets remain independently actionable in the report.
  for (const match of source.matchAll(/(["'`])([A-Za-z0-9_+=./-]{24,})\1/g)) {
    // A missing capture becomes empty text, which safely fails the configured length gate.
    const candidateText = match[2] ?? "";
    // Known public shapes or insufficient entropy mean the user does not need a secret finding for this literal.
    if (!isHighEntropySecretCandidate(candidateText, minLength)) {
      continue;
    }
    pushSensitiveFinding({
      findings,
      file,
      ruleId: "sensitive-data.high-entropy-string",
      message: "High-entropy string literal may be an embedded secret.",
      line: byteLine(source, match.index ?? 0),
      column: byteColumn(source, match.index ?? 0),
      matchedSensitiveText: candidateText,
      confidence: "medium",
      metadata: { detector: "high-entropy-string", threshold: minLength },
      severity: ruleSeverity(config, "sensitive-data.high-entropy-string", "error"),
    });
  }
}

// Describes one reportable sensitive occurrence before the finding is built.
//
// Optional column, metadata, and severity enrich the user's report when available.
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
  severity?: Finding["severity"];
}

// Reports one user-visible finding with a detector-owned marker and an optional match column.
// The matched value is used only to select a public category; every occurrence reaches the report.
function pushSensitiveFinding(args: SensitiveFindingArgs): void {
  const displayMarker = fixedMarkerForSensitiveFinding(args);
  // Missing location and metadata fields remain absent or empty so report consumers can distinguish unavailable user context.
  args.findings.push(
    makeFinding({
      ruleId: args.ruleId,
      message: `${args.message} Redacted preview: ${displayMarker}.`,
      filePath: args.file.displayPath,
      line: args.line,
      ...(args.column === undefined ? {} : { column: args.column }),
      severity: args.severity ?? "error",
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

// Parses a secret-labelled assignment and returns it only when its value is credible and literal for that file type.
// In scripts, unquoted right-hand sides are code expressions rather than user-visible embedded strings.
function hardcodedEnvValue(line: string, minLength: number, requiresQuotedValue: boolean): { keyName: string; value: string } | undefined {
  const candidate = envValueCandidate(line);
  // Missing, placeholder-shaped, or short values do not represent a credential the user needs to remove.
  if (!candidate || !isHardcodedEnvCandidate(candidate.value, minLength)) {
    return undefined;
  }
  // In script files, an unquoted right-hand side is code rather than a literal value embedded by the user.
  if (requiresQuotedValue && !candidate.isQuoted) {
    return undefined;
  }
  return candidate;
}

// Checks whether a user's file treats unquoted assignment values as code expressions.
// Script extensions require quotes; config formats keep their normal unquoted-literal behavior.
function isScriptSourcePath(displayPath: string): boolean {
  return /\.(?:ts|tsx|mts|cts|js|jsx|mjs|cjs)$/i.test(displayPath);
}

const SECRET_ASSIGNMENT_PATTERN = /^\s*((?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)|[A-Z][A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_-]*)\s*[:=]\s*(?:"([^"\r\n]+)"|'([^'\r\n]+)'|`([^`\r\n]+)`|([^"'`\s#]+))/i;

// Extracts one secret-labelled literal assignment for later detector checks.
// Missing output means the user's line has no supported key/value shape; comments never inflate the captured value.
function envValueCandidate(line: string): { keyName: string; value: string; isQuoted: boolean } | undefined {
  const match = line.match(SECRET_ASSIGNMENT_PATTERN);
  // A user may have supplied an unrelated line or unknown key, which cannot produce this finding.
  if (!match) {
    return undefined;
  }
  const keyName = match[1];
  const quotedValue = match[2] ?? match[3] ?? match[4];
  const secretValue = quotedValue ?? match[5];
  // A user may have supplied an empty or unterminated assignment; neither is a secret candidate.
  if (!keyName || !secretValue) {
    return undefined;
  }
  return { keyName, value: secretValue, isQuoted: quotedValue !== undefined };
}

// Checks whether an extracted assignment is long, non-placeholder, and credential-shaped.
// Users see a finding only when all three signals agree, reducing noise from ordinary examples.
function isHardcodedEnvCandidate(secretValue: string, minLength: number): boolean {
  return secretValue.length >= minLength && !isPlaceholderSecretValue(secretValue) && hasLetterAndDigit(secretValue);
}

// Recognizes obvious example words that users commonly place in documentation and fixtures.
// Matching is case-insensitive so capitalization alone does not create a noisy secret finding.
function isPlaceholderSecretValue(secretValue: string): boolean {
  return /^(?:x-api-key|token|secret|password|example|sample|placeholder)$/i.test(secretValue);
}

// Checks for the letter-and-digit mix expected in generated credential values.
// Pure words and numbers stay out of the user's report before more expensive entropy work begins.
function hasLetterAndDigit(candidateText: string): boolean {
  return /[A-Za-z]/.test(candidateText) && /[0-9]/.test(candidateText);
}

// Applies cheap inert-shape checks before character diversity and entropy scoring.
// This order preserves the same user result while avoiding expensive work for obvious non-secrets.
function isHighEntropySecretCandidate(candidateText: string, minLength: number): boolean {
  // Known public or readable shapes do not require a secret warning in the user's report.
  if (isExcludedHighEntropyCandidate(candidateText, minLength)) {
    return false;
  }
  // Without lowercase, uppercase, and digits, the literal lacks the credential diversity this rule promises.
  if (!hasLowerUpperAndDigit(candidateText)) {
    return false;
  }
  // Too few distinct characters indicate repetition rather than a generated secret the user should rotate.
  if (!hasEnoughDistinctCharacters(candidateText)) {
    return false;
  }
  return shannonEntropy(candidateText) >= 4;
}

// Recognizes high-entropy shapes users commonly commit on purpose: digests, paths, alphabets, and readable identifiers.
// Returning true keeps these detector-owned non-secrets out of reports without consulting user preview values.
function isExcludedHighEntropyCandidate(candidateText: string, minLength: number): boolean {
  return candidateText.length < minLength
    || isHexDigest(candidateText)
    || isSubresourceIntegrityHash(candidateText)
    || isRepoPathShape(candidateText)
    || isCharacterAlphabetString(candidateText)
    || isWordSegmentIdentifier(candidateText);
}

// Recognizes public encoding alphabets by a run of at least ten consecutive character codes.
// Credential generators rarely produce that sequence, so users avoid a noisy entropy finding.
function isCharacterAlphabetString(candidateText: string): boolean {
  let runLength = 1;
  // Each character extends or resets the public alphabet sequence being recognized.
  for (let index = 1; index < candidateText.length; index += 1) {
    // Consecutive character codes indicate an intentional alphabet rather than opaque credential material.
    if (candidateText.charCodeAt(index) === candidateText.charCodeAt(index - 1) + 1) {
      runLength += 1;
      // Ten consecutive characters are enough to keep this public alphabet out of the user's findings.
      if (runLength >= 10) {
        return true;
      }
    } else {
      runLength = 1;
    }
  }
  return false;
}

// Recognizes readable namespaces, constants, and catalog names made entirely from short word-like segments.
// Token-shaped segments are rejected first so JWTs and base64url credentials remain visible to users.
function isWordSegmentIdentifier(candidateText: string): boolean {
  // Base64 punctuation makes the value token-like, so it must remain eligible for a user finding.
  if (candidateText.includes("+") || candidateText.includes("=")) {
    return false;
  }
  // A recognizable segmented token must not inherit the readable-identifier exemption.
  if (isTokenLikeSegmentedSecret(candidateText)) {
    return false;
  }
  const segments = candidateText.split(/[/._-]+/);
  // A single segment is not a namespace, constant, or slug and therefore lacks this public-shape evidence.
  if (segments.length < 2) {
    return false;
  }
  return segments.every(isWordLikeSegment);
}

// Recognizes JWT prefixes and long mixed-case segments that remain credential-like despite separators.
// This guard runs before readable-word exemptions so users do not lose segmented secret findings.
function isTokenLikeSegmentedSecret(candidateText: string): boolean {
  // The standard JWT header prefix keeps this value visible to users even when separators resemble an identifier.
  if (candidateText.startsWith("eyJ")) {
    return true;
  }
  return candidateText.split(/[/._-]+/).some((segment) => segment.length >= 20 && hasLowerUpperAndDigit(segment));
}

// Recognizes a short word or version segment with at most one letter-to-digit boundary.
// Repeated transitions look token-like and keep the candidate visible for user review.
function isWordLikeSegment(segment: string): boolean {
  // Empty, long, or punctuated segments are too token-like to earn the readable-identifier exemption.
  if (segment.length === 0 || segment.length > 16 || !/^[A-Za-z0-9]+$/.test(segment)) {
    return false;
  }
  return letterDigitTransitionCount(segment) <= 1;
}

// Counts letter-to-digit boundaries used to distinguish readable version names from token material.
// Users avoid noise for names such as `Example2`, while repeatedly alternating segments remain reportable.
function letterDigitTransitionCount(segment: string): number {
  let transitions = 0;
  // Each adjacent character pair can add one boundary to the identifier-shape decision.
  for (let index = 1; index < segment.length; index += 1) {
    // A change between letter and digit runs makes the segment incrementally more token-like.
    if (isDigitCharCode(segment.charCodeAt(index - 1)) !== isDigitCharCode(segment.charCodeAt(index))) {
      transitions += 1;
    }
  }
  return transitions;
}

// Checks one character code for a decimal digit while evaluating identifier transitions.
// Using codes avoids an absent string index and keeps the user's classification deterministic.
function isDigitCharCode(code: number): boolean {
  return code >= 48 && code <= 57;
}

// Recognizes repository paths by a known extension plus a conventional project segment or milestone filename.
// Slash-containing opaque tokens stay reportable because path punctuation alone is not enough evidence.
function isRepoPathShape(candidateText: string): boolean {
  const normalized = candidateText.replaceAll("\\", "/");
  const hasKnownExtension = /\.(?:md|mdx|ts|tsx|js|jsx|mjs|cjs|json|yaml|yml|toml|html|css|svg|sh)$/.test(candidateText);
  // Without a known file extension, the value lacks enough evidence to hide a possible secret from the user.
  if (!hasKnownExtension) {
    return false;
  }
  // A basename needs an ADR or milestone shape because it has no directory segment proving it is a project path.
  if (!normalized.includes("/")) {
    return isRepoPathLikeFilename(normalized);
  }
  return hasKnownRepoPathSegment(normalized);
}

// Recognizes ADR and milestone filenames that users may reference without a directory prefix.
// A match keeps these public project artifacts out of high-entropy findings.
function isRepoPathLikeFilename(candidateText: string): boolean {
  return /^(?:ADR-\d{3}|M\d{2,3})-[A-Za-z0-9_.-]+\.(?:md|mdx)$/i.test(candidateText);
}

// Recognizes paths under conventional source, test, documentation, workflow, and package locations.
// Unknown slash-separated strings remain reportable because they may still be opaque credentials.
function hasKnownRepoPathSegment(candidateText: string): boolean {
  return /(?:^|\/)(?:\.goat-flow|src|test|tests|fixtures?|docs|scripts|bin|workflow|package(?:-lock)?\.json)(?:\/|$)/.test(candidateText);
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

// Recognizes all-hex values commonly used for public digests and tooling identifiers.
// A match keeps those expected project values out of the user's high-entropy findings.
function isHexDigest(candidateText: string): boolean {
  return /^[0-9a-f]+$/i.test(candidateText);
}

// Recognizes public Subresource Integrity digests from registry metadata and HTML attributes.
// A match keeps expected integrity values out of the user's secret report.
function isSubresourceIntegrityHash(candidateText: string): boolean {
  return /^sha(?:1|256|384|512)-[A-Za-z0-9+/=]+$/.test(candidateText);
}

// Checks for lowercase, uppercase, and digits before entropy scoring.
// Values missing a class are less credential-like and stay out of this user's finding set.
function hasLowerUpperAndDigit(candidateText: string): boolean {
  return /[a-z]/.test(candidateText) && /[A-Z]/.test(candidateText) && /[0-9]/.test(candidateText);
}

// Checks whether a literal has enough distinct characters to resemble a generated secret.
// The capped, length-scaled threshold avoids flagging repeated text in the user's source.
function hasEnoughDistinctCharacters(candidateText: string): boolean {
  return new Set(candidateText).size >= Math.min(12, Math.ceil(candidateText.length / 3));
}

// Calculates Shannon entropy for the final generated-secret decision.
// The caller compares this score with the documented threshold before showing users a finding.
function shannonEntropy(candidateText: string): number {
  const counts = new Map<string, number>();
  // Each character contributes to the frequency distribution used for the user's entropy decision.
  for (const character of candidateText) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((sum, count) => {
    const probability = count / candidateText.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}

export { analyseSensitiveData };
