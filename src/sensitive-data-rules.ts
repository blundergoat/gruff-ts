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

/**
 * Runs every sensitive-data detector for one user file in deterministic report order.
 * Keeping pattern order stable prevents baseline churn when no source behavior changed.
 *
 * @param file - Source file metadata supplying the display path for reported findings.
 * @param source - Full source text scanned across pattern and specialized detectors.
 * @param findings - Accumulator array receiving redacted sensitive-data findings.
 * @returns Nothing. Appends matching findings to `findings` in deterministic detector order.
 */
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
      // A URL shape written as a template literal type names no credential at all, and a stock pair on a local host is a
      // documented development default.
      const matchEnd = (match.index ?? 0) + matchedSensitiveText.length;
      if (ruleId === "sensitive-data.database-url-password"
        && (isTypeLevelUrlCredential(matchedSensitiveText) || isStockDevelopmentUrl(matchedSensitiveText, source.slice(matchEnd, matchEnd + 256)))) {
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

/**
 * Recognizes a URL credential in type position where the password is wholly `${string}` or `${number}`.
 * Only an interpolated type-keyword password straight after the user qualifies; literal passwords or runtime variables still report.
 * The match stops at `@` because extending it to the host would silence hosts containing "example" (M22 activation bundle, decision 4).
 *
 * @param matchedSensitiveText - Matched scheme-and-userinfo substring ending at `@`.
 * @returns True when `matchedSensitiveText` ends with a type-only `${string}` or `${number}` password interpolation.
 */
function isTypeLevelUrlCredential(matchedSensitiveText: string): boolean {
  return /:\/\/[^\/\s:@]+:\$\{\s*(?:string|number)\s*\}@$/.test(matchedSensitiveText);
}

// Stock development user names and passwords, compared case-insensitively and whole (FAMILY-CONTRACT.md section 5).
// They are documented defaults such as `postgres:postgres` or `scott:tiger`, not credentials, so they are held as plain text.
const STOCK_DEVELOPMENT_WORDS = new Set([
  "admin", "bar", "dbpass", "dbuser", "default", "demo", "example", "foo", "guest", "mysql", "pass", "passwd",
  "password", "postgres", "root", "sa", "scott", "secret", "test", "tiger", "user", "username",
]);

// Loopback hosts, on which a stock pair is a development default rather than a live weakness.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "0.0.0.0"]);

/**
 * Checks whether matched credentials are stock development defaults paired with a qualifying local host.
 * Credentials and hosts compare case-insensitively; other hosts stay reportable under FAMILY-CONTRACT.md section 5.
 * The match stops at `@` to keep hostnames out of example checks.
 *
 * @param matchedSensitiveText - Matched scheme-and-userinfo substring ending at `@`.
 * @param textAfterAt - Authority slice immediately following `@`, used to extract the host.
 * @returns True when user and password are in `STOCK_DEVELOPMENT_WORDS` and the host is loopback or a bare single-label name.
 */
function isStockDevelopmentUrl(matchedSensitiveText: string, textAfterAt: string): boolean {
  const userInfo = /:\/\/([^\/\s:@]+):([^\/\s@]+)@$/.exec(matchedSensitiveText);
  const user = userInfo?.[1]?.toLowerCase() ?? "";
  const password = userInfo?.[2]?.toLowerCase() ?? "";
  // Any username or password outside the stock-word set keeps the finding.
  if (!STOCK_DEVELOPMENT_WORDS.has(user) || !STOCK_DEVELOPMENT_WORDS.has(password)) {
    return false;
  }
  const authority = (/^[^\/?#\s"'`]*/.exec(textAfterAt)?.[0] ?? "").toLowerCase();
  // A bracketed IPv6 host such as `[::1]:5432` keeps its colons inside the brackets.
  const bracketed = /^\[([^\]]+)\]/.exec(authority);
  const host = bracketed ? (bracketed[1] ?? "") : (authority.split(":")[0] ?? "");
  return LOOPBACK_HOSTS.has(host) || (host !== "" && !host.includes(".") && !host.includes(":"));
}

/**
 * Checks whether the matched credential contains an example marker or matches a supported mask.
 * The detector uses this result to skip placeholder matches before creating findings.
 *
 * @param matchedSensitiveText - Candidate credential text extracted from source.
 * @returns True when `matchedSensitiveText` contains an example/placeholder marker or a masked run.
 */
function isExplicitExampleCredential(matchedSensitiveText: string): boolean {
  return /EXAMPLE|REDACTED|PLACEHOLDER|CHANGEME/i.test(matchedSensitiveText) || isMaskedCredential(matchedSensitiveText);
}

/**
 * Checks whether a matched AWS access key has an all-X body, as required by FAMILY-CONTRACT.md section 5.
 * A real key can contain runs of `X`, so the mask must cover the entire 16-character body.
 *
 * @param matchedSensitiveText - Candidate AWS access key beginning with `AKIA` or `ASIA`.
 * @returns True when all 16 characters after the prefix are uppercase `X`.
 */
function isMaskedAwsAccessKey(matchedSensitiveText: string): boolean {
  return /^(?:AKIA|ASIA)X{16}$/.test(matchedSensitiveText);
}

/**
 * Recognizes a value whose body was masked out with a run of `*` or `X`, which names no credential at all.
 *
 * @param matchedSensitiveText - Candidate credential text extracted from source.
 * @returns True when `matchedSensitiveText` contains four consecutive `*` or `X` characters.
 */
function isMaskedCredential(matchedSensitiveText: string): boolean {
  return /\*{4}|X{4}/.test(matchedSensitiveText);
}

/**
 * Scans source lines for labelled medical-record numbers using `file` to anchor each finding.
 * Stable contract: a supported label is required, and only the first matching identifier on each line is reported.
 *
 * @param file - Source file metadata supplying the display path for findings.
 * @param source - Full source text split into lines for MRN label matching.
 * @param findings - Accumulator array receiving fixed-marker PHI findings.
 * @returns Nothing. Appends fixed-marker MRN findings to `findings`.
 */
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

/**
 * Scans `source` for a GCP service-account key and reports only when type and private-key evidence coexist.
 * Stable contract: users receive one marker at the type field, while matched identifiers and key material stay hidden.
 *
 * @param file - Source file metadata supplying the display path for the finding.
 * @param source - Full source text checked for `"type": "service_account"` and private-key evidence.
 * @param findings - Accumulator array receiving the service-account finding when both signals match.
 * @returns Nothing. Appends at most one fixed-marker finding to `findings`.
 */
function analyseGcpServiceAccountKeys(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const typeMatch = source.match(/"type"\s*:\s*"service_account"/);
  // Private-key evidence anywhere in the source can corroborate the type field, regardless of field order.
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

/**
 * Scans `source` for payment-card candidates and appends findings only after network, length, checksum, and context checks pass.
 * Stable contract: canonical grouping supplies context; bare digit runs need card vocabulary before users see a finding.
 *
 * @param file - Source file metadata supplying the display path for findings.
 * @param source - Full source text scanned for grouped or bare digit runs.
 * @param findings - Accumulator array receiving credit-card PII findings.
 * @returns Nothing. Appends matching payment-card findings to `findings`.
 */
function analysePaymentCardNumbers(file: SensitiveSourceFile, source: string, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  // Each digit run is checked independently because a user can paste more than one card-like value into a line or file.
  for (const match of source.matchAll(/\b(?:\d[ -]?){12,18}\d\b/g)) {
    const matchedDigitRun = match[0] ?? "";
    const normalizedCardNumber = normalizedPaymentCardNumber(matchedDigitRun);
    const line = byteLine(source, match.index ?? 0);
    // After the card number passes validation, canonical grouping supplies context. A run without that grouping needs card vocabulary on its line.
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

/**
 * Checks whether `matchedDigitRun` is reportable: `normalizedCardNumber` must pass network, length, and checksum checks.
 * The run must also have canonical grouping, or `contextLine` must contain card vocabulary, since ordinary numbers can pass Luhn.
 *
 * @param matchedDigitRun - Raw candidate digit run with any original spaces or hyphens.
 * @param normalizedCardNumber - Digit-only candidate value after stripping separators.
 * @param contextLine - Source line surrounding `matchedDigitRun`, checked for card vocabulary.
 * @returns True when `normalizedCardNumber` is a valid card number with canonical grouping or card context.
 */
function isReportablePaymentCardCandidate(matchedDigitRun: string, normalizedCardNumber: string, contextLine: string): boolean {
  if (!isPaymentCardNumber(normalizedCardNumber)) {
    return false;
  }
  return hasCanonicalPaymentCardGrouping(matchedDigitRun, normalizedCardNumber) || hasPaymentCardContext(contextLine);
}

/**
 * Checks whether `matchedDigitRun` uses one separator and the grouping expected for `normalizedCardNumber`'s network and length.
 * Noncanonical chunks such as `8-8` supply no grouping context; callers can still accept them when the line contains card vocabulary.
 *
 * @param matchedDigitRun - Raw candidate digit run containing spaces or hyphens.
 * @param normalizedCardNumber - Digit-only card value used to select expected group sizes.
 * @returns True when `matchedDigitRun` uses a single separator kind matching the issuer's canonical chunk sizes.
 */
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

/**
 * Recognizes card vocabulary around an otherwise ambiguous digit run.
 * Identifier forms such as `cardNumber` count; `PAN` must be a whole word to avoid matching unrelated words such as `panel`.
 *
 * @param lineText - Full source line containing the candidate digit run.
 * @returns True when `lineText` contains card-related terms or a whole-word `PAN` token.
 */
function hasPaymentCardContext(lineText: string): boolean {
  return /(?:\bpan\b|card|payment|credit|debit|visa|master|amex|discover|jcb|diners)/i.test(lineText);
}

/**
 * Scans `source` for npm `_authToken` values and appends findings for recognized literals, including tokens without `npm_`.
 * Stable contract: scoped and registry `_authToken` lines remain reportable when the general provider pattern cannot classify their prefix.
 *
 * @param file - Source file metadata supplying the display path for findings.
 * @param source - Full source text split into lines to inspect registry auth assignments.
 * @param findings - Accumulator array receiving redacted npm auth token findings.
 * @returns Nothing. Appends matching `_authToken` findings to `findings`.
 */
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

/**
 * Extracts the matched literal token from a bare, scoped, or registry-prefixed npm auth line.
 * Missing output means the user's line has no supported literal token for this detector.
 *
 * @param line - Single source or config line checked for a literal `_authToken=` assignment.
 * @returns Matched token literal of at least 20 characters, or `undefined` when no supported token matches.
 */
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

/**
 * Checks whether a matched value is, exactly and whole, a vendor-documented sample such as AWS's example key.
 * When `metadata` identifies a credit card, compares digits only; absent or other metadata keeps the original text.
 *
 * @param matchedSensitiveText - Raw matched sensitive value before digest comparison.
 * @param metadata - Optional finding metadata whose `piiKind` selects digit-only normalization for credit cards.
 * @returns True when the SHA-256 digest of the compared value matches `DOCUMENTED_SAMPLE_DIGESTS`.
 */
function isDocumentedSample(matchedSensitiveText: string, metadata: Record<string, unknown> | undefined): boolean {
  const comparedText = metadata?.["piiKind"] === "credit-card" ? matchedSensitiveText.replace(/\D/g, "") : matchedSensitiveText;
  return DOCUMENTED_SAMPLE_DIGESTS.has(createHash("sha256").update(comparedText, "utf8").digest("hex"));
}

/**
 * Appends a redacted finding to `args.findings`, unless its matched value is a vendor-documented sample.
 * The redaction contract uses matched text only to choose the public marker and check for a documented sample.
 *
 * @param args - Occurrence details, source location, accumulator array, and matched text used only for redaction.
 * @returns Nothing. Appends one redacted `Finding` to `args.findings` unless skipped as a documented sample.
 */
function pushSensitiveFinding(args: SensitiveFindingArgs): void {
  // A pasted documentation sample, e.g. AWS's example key id from its docs, is not a credential, so the user sees nothing.
  if (isDocumentedSample(args.matchedSensitiveText, args.metadata)) {
    return;
  }
  const displayMarker = fixedMarkerForSensitiveFinding(args);
  // An unavailable column is omitted. The fixed marker replaces any supplied preview and preserves the other metadata.
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

/**
 * Selects the fixed category marker users see for one sensitive finding.
 * Uses `args.ruleId`, matched text, and optional metadata to avoid exposing the value; only an approved public URL scheme may be retained.
 * The stable fallback for unknown rules is `[redacted]`. Without metadata, PII uses `[redacted:ssn]` and API keys classify by prefix.
 *
 * @param args - Finding rule id, matched text, and optional metadata controlling marker selection.
 * @returns Fixed public redaction marker string for `args.ruleId`.
 */
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

/**
 * Builds the fixed connection-string marker users see, retaining only the detector-approved public scheme.
 * The matched URL supplies the allowed scheme, which the marker shows in lowercase.
 *
 * @param matchedUrl - Matched credentialed URL whose leading scheme is checked against the allowlist.
 * @returns Scheme-scoped connection-string marker, or `[redacted]` when no approved scheme matches.
 */
function fixedConnectionStringMarker(matchedUrl: string): string {
  const acceptedScheme = matchedUrl.match(/^(https?|postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql):\/\//i)?.[1]?.toLowerCase();
  // A missing detector-approved scheme gives users a generic marker rather than echoing any URL text.
  if (!acceptedScheme) {
    return "[redacted]";
  }
  return `[redacted:connection-string:${acceptedScheme}]`;
}

/**
 * Selects a fixed provider marker for `matchedToken`; optional `metadata` identifies npm auth lines lacking a public prefix.
 * Without npm auth metadata, uses a recognized prefix or `[redacted]` to avoid exposing matched token characters.
 *
 * @param matchedToken - Matched API key or token string classified by prefix or `_authToken` metadata.
 * @param metadata - Optional metadata whose `keyName` identifies unprefixed `_authToken` values.
 * @returns Fixed provider redaction marker, or `[redacted]` for unrecognized tokens.
 */
function fixedApiKeyMarker(matchedToken: string, metadata: Record<string, unknown> | undefined): string {
  // An npm auth line may omit the public `npm_` prefix, but its detector-owned key name still identifies the category.
  if (metadata?.keyName === "_authToken" || matchedToken.startsWith("npm_")) {
    return "[redacted:npm-token]";
  }
  if (/^(?:ghp_|github_pat_|gh[ousr]_)/.test(matchedToken)) {
    return "[redacted:github-token]";
  }
  // Slack tokens and webhook URLs share one fixed provider marker in user reports.
  if (/^(?:xox[baprs]-|https:\/\/hooks\.slack\.com\/services\/)/.test(matchedToken)) {
    return "[redacted:slack-token]";
  }
  // The public live-key prefix selects the Stripe live-key label. Stripe test-key matches use the generic marker.
  if (matchedToken.startsWith("sk_live_")) {
    return "[redacted:stripe-live-key]";
  }
  if (matchedToken.startsWith("AIza")) {
    return "[redacted:google-api-key]";
  }
  if (matchedToken.startsWith("sk-ant-")) {
    return "[redacted:anthropic-api-key]";
  }
  if (matchedToken.startsWith("glpat-")) {
    return "[redacted:gitlab-token]";
  }
  return "[redacted]";
}

/**
 * Removes spaces and hyphens before validating a payment-card value the user may have pasted.
 * Used for network, checksum, and grouping checks, never for report output.
 *
 * @param candidateText - Raw digit run possibly containing space or hyphen separators.
 * @returns Copy of `candidateText` with all space and hyphen separators removed.
 */
function normalizedPaymentCardNumber(candidateText: string): string {
  return candidateText.replace(/[ -]/g, "");
}

/**
 * Checks issuer shape, supported length, and Luhn checksum before showing a payment-card finding.
 * Ordinary long numbers stay out of the user's report when any gate fails.
 *
 * @param cardNumber - Normalized candidate string checked for digits, length 13-19, known prefix, and Luhn validity.
 * @returns True when `cardNumber` passes all digit, length, issuer-prefix, and Luhn checksum gates.
 */
function isPaymentCardNumber(cardNumber: string): boolean {
  return /^[0-9]+$/.test(cardNumber) && cardNumber.length >= 13 && cardNumber.length <= 19 && hasKnownPaymentCardPrefix(cardNumber) && passesLuhnCheck(cardNumber);
}

/**
 * Checks whether normalized `cardNumber` has both a supported issuer prefix and a length accepted for that issuer.
 * Network-specific helpers keep user-facing false-positive tuning isolated and readable.
 *
 * @param cardNumber - Digit-only card candidate checked against Visa, Mastercard, Amex, Discover, Diners, and JCB rules.
 * @returns True when `cardNumber` matches any supported payment-card network and its accepted lengths.
 */
function hasKnownPaymentCardPrefix(cardNumber: string): boolean {
  return isVisaPaymentCard(cardNumber)
    || isMastercardPaymentCard(cardNumber)
    || isAmericanExpressPaymentCard(cardNumber)
    || isDiscoverPaymentCard(cardNumber)
    || isDinersPaymentCard(cardNumber)
    || isJcbPaymentCard(cardNumber);
}

/**
 * Checks whether digit-only `cardNumber` starts with `4` and has a supported Visa length of 13, 16, or 19 digits.
 *
 * @param cardNumber - Digit-only card candidate tested against Visa prefix and length rules.
 * @returns True when `cardNumber` begins with `4` and has length 13, 16, or 19.
 */
function isVisaPaymentCard(cardNumber: string): boolean {
  return cardNumber.startsWith("4") && isPaymentCardLength(cardNumber, [13, 16, 19]);
}

/**
 * Checks whether digit-only `cardNumber` has 16 digits and a Mastercard prefix in `51-55` or `2221-2720`.
 *
 * @param cardNumber - Digit-only card candidate tested against Mastercard prefix ranges and length.
 * @returns True when `cardNumber` is 16 digits long and falls in a supported Mastercard prefix range.
 */
function isMastercardPaymentCard(cardNumber: string): boolean {
  const firstTwoDigits = Number(cardNumber.slice(0, 2));
  const firstFourDigits = Number(cardNumber.slice(0, 4));
  return (isInRange(firstTwoDigits, 51, 55) || isInRange(firstFourDigits, 2221, 2720)) && isPaymentCardLength(cardNumber, [16]);
}

/**
 * Checks whether digit-only `cardNumber` has an American Express prefix (`34` or `37`) and 15 digits.
 *
 * @param cardNumber - Digit-only card candidate tested against American Express prefix and length rules.
 * @returns True when `cardNumber` starts with `34` or `37` and has length 15.
 */
function isAmericanExpressPaymentCard(cardNumber: string): boolean {
  return (cardNumber.startsWith("34") || cardNumber.startsWith("37")) && isPaymentCardLength(cardNumber, [15]);
}

/**
 * Checks whether digit-only `cardNumber` has 16 or 19 digits and a supported Discover prefix (`6011`, `65`, or `644-649`).
 *
 * @param cardNumber - Digit-only card candidate tested against Discover prefixes and lengths.
 * @returns True when `cardNumber` matches a supported Discover prefix with length 16 or 19.
 */
function isDiscoverPaymentCard(cardNumber: string): boolean {
  const firstThreeDigits = Number(cardNumber.slice(0, 3));
  return (cardNumber.startsWith("6011") || cardNumber.startsWith("65") || isInRange(firstThreeDigits, 644, 649)) && isPaymentCardLength(cardNumber, [16, 19]);
}

/**
 * Checks whether digit-only `cardNumber` has 14 digits and a Diners Club prefix (`300-305`, `36`, `38`, or `39`).
 *
 * @param cardNumber - Digit-only card candidate tested against Diners Club prefixes and length.
 * @returns True when `cardNumber` matches a supported Diners Club prefix with length 14.
 */
function isDinersPaymentCard(cardNumber: string): boolean {
  const firstThreeDigits = Number(cardNumber.slice(0, 3));
  return (isInRange(firstThreeDigits, 300, 305) || cardNumber.startsWith("36") || cardNumber.startsWith("38") || cardNumber.startsWith("39")) && isPaymentCardLength(cardNumber, [14]);
}

/**
 * Checks whether digit-only `cardNumber` has 16-19 digits and a JCB prefix from `3528` through `3589`.
 *
 * @param cardNumber - Digit-only card candidate tested against JCB prefix range and length rules.
 * @returns True when `cardNumber` has a leading prefix in `3528-3589` and length 16 through 19.
 */
function isJcbPaymentCard(cardNumber: string): boolean {
  const firstFourDigits = Number(cardNumber.slice(0, 4));
  return isInRange(firstFourDigits, 3528, 3589) && isPaymentCardLength(cardNumber, [16, 17, 18, 19]);
}

/**
 * Checks whether a normalized card uses a length supported by its detected network.
 * Keeping the length table explicit makes the user-facing classification easier to audit.
 *
 * @param cardNumber - Digit-only card candidate whose character length is checked.
 * @param allowedLengths - Network-permitted digit counts matched against `cardNumber.length`.
 * @returns True when `allowedLengths` includes `cardNumber.length`.
 */
function isPaymentCardLength(cardNumber: string, allowedLengths: number[]): boolean {
  return allowedLengths.includes(cardNumber.length);
}

/**
 * Checks an issuer identification number against an inclusive network range.
 * Card-prefix helpers use it to decide whether the user should receive a payment-data finding.
 *
 * @param candidateNumber - Parsed leading prefix integer extracted from the card candidate.
 * @param minimum - Inclusive lower bound of the issuer range.
 * @param maximum - Inclusive upper bound of the issuer range.
 * @returns True when `candidateNumber` lies between `minimum` and `maximum` inclusive.
 */
function isInRange(candidateNumber: number, minimum: number, maximum: number): boolean {
  return candidateNumber >= minimum && candidateNumber <= maximum;
}

/**
 * Runs the standard Luhn checksum over normalized digits before a card finding reaches the user.
 * Invalid checksums keep ordinary long numeric identifiers quiet.
 *
 * @param cardNumber - Digit-only card candidate summed from right to left under Luhn weights.
 * @returns True when the weighted digit sum modulo 10 equals zero.
 */
function passesLuhnCheck(cardNumber: string): boolean {
  const digits = [...cardNumber].reverse().map((digit) => Number(digit));
  const sum = digits.reduce((total, digit, index) => total + luhnDigitContribution(digit, index), 0);
  return sum % 10 === 0;
}

/**
 * Calculates one digit's Luhn contribution while validating a possible payment-card value.
 * `indexFromRight` is zero-based, so even positions stay unchanged while odd positions double `digit` and subtract 9 when over 9.
 *
 * @param digit - Single decimal digit (0-9) from the candidate card number.
 * @param indexFromRight - Zero-based position counting from the rightmost digit.
 * @returns Weighted Luhn contribution (`digit` at even indexes, doubled and folded at odd indexes).
 */
function luhnDigitContribution(digit: number, indexFromRight: number): number {
  if (indexFromRight % 2 === 0) {
    return digit;
  }
  const doubled = digit * 2;
  return doubled > 9 ? doubled - 9 : doubled;
}

export { analyseSensitiveData };
