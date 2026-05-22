// Sensitive-data scanners and redaction helpers for secret-like raw text findings.
import { ruleSeverity, threshold } from "./config.ts";
import { makeFinding } from "./findings.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

// Just the display path — sensitive-data rules anchor findings on file path + line and never need
// the absolute path. Keeping this trimmed keeps the contract narrow for testability.
interface SensitiveSourceFile {
  displayPath: string;
}

// Pillar entry point. The pattern array order is the deterministic emission order for findings,
// which the fingerprint contract depends on — reordering would churn baselines without behaviour change.
function analyseSensitiveData(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql):\/\/[^\/\s:@]+:[^\/\s@]+@/g, "Database URL appears to include a password."],
    [
      "sensitive-data.api-key-pattern",
      /\b(?:sk_live_[A-Za-z0-9_-]{12,}|sk_test_[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|gh[ousr]_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+\/[A-Za-z0-9_-]+|https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+)\b/g,
      "API key pattern detected.",
    ],
    ["sensitive-data.pii-pattern", /\b\d{3}-\d{2}-\d{4}\b/g, "PII-like identifier pattern detected."],
  ];

  for (const [ruleId, pattern, message] of patterns) {
    for (const match of source.matchAll(pattern)) {
      const raw = match[0] ?? "";
      pushSensitiveFinding(config, findings, file, ruleId, message, byteLine(source, match.index ?? 0), raw, "high");
    }
  }

  analyseHardcodedEnvironmentValues(file, source, config, findings);
  analyseNpmAuthTokens(file, source, config, findings);
  analyseHighEntropyStrings(file, source, config, findings);
}

// Stable redaction contract: parses `_authToken=` config lines even when values lack an npm_ prefix.
function analyseNpmAuthTokens(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const token = npmAuthTokenValue(line);
    if (!token) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.api-key-pattern",
      "npm auth token pattern detected.",
      index + 1,
      token,
      "high",
      { keyName: "_authToken" },
    );
  }
}

// Extracts the token portion from scoped or registry-prefixed npm auth config lines.
function npmAuthTokenValue(line: string): string | undefined {
  const match = line.match(/(?:^|:)_authToken\s*=\s*([A-Za-z0-9_-]{20,})\b/);
  return match?.[1];
}

// Targets `KEY=value` and `KEY: value` assignments where the key name signals secrets (API_KEY,
// TOKEN, PASSWORD…). The `minLength` threshold keeps short fixture values like `PLACEHOLDER`
// from churning the baseline — it is part of the rule's stable, deterministic contract.
function analyseHardcodedEnvironmentValues(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const minLength = threshold(config, "sensitive-data.hardcoded-env-value", 16);
  const lines = source.split(/\r?\n/);
  for (const [index, line] of lines.entries()) {
    const envValue = hardcodedEnvValue(line, minLength);
    if (!envValue) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.hardcoded-env-value",
      `Environment-style value \`${envValue.keyName}\` appears to be hardcoded with secret-like content.`,
      index + 1,
      envValue.value,
      "medium",
      { keyName: envValue.keyName, length: envValue.value.length },
      ruleSeverity(config, "sensitive-data.hardcoded-env-value", "error"),
    );
  }
}

// Shannon-entropy detector with three guardrails (length, case diversity, distinct characters)
// because plain entropy alone fires on package-lock SRI hashes; the layered checks keep findings
// stable across runs and prevent noisy regressions in node_modules-heavy projects.
function analyseHighEntropyStrings(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const minLength = threshold(config, "sensitive-data.high-entropy-string", 32);
  for (const match of source.matchAll(/(["'`])([A-Za-z0-9_+=./-]{32,})\1/g)) {
    const raw = match[2] ?? "";
    if (!isHighEntropySecretCandidate(raw, minLength)) {
      continue;
    }
    pushSensitiveFinding(
      config,
      findings,
      file,
      "sensitive-data.high-entropy-string",
      "High-entropy string literal may be an embedded secret.",
      byteLine(source, match.index ?? 0),
      raw,
      "medium",
      { length: raw.length, detector: "high-entropy-string" },
      ruleSeverity(config, "sensitive-data.high-entropy-string", "error"),
    );
  }
}

function pushSensitiveFinding(
  config: Config,
  findings: Finding[],
  file: SensitiveSourceFile,
  ruleId: string,
  message: string,
  line: number,
  raw: string,
  confidence: Finding["confidence"],
  metadata: Record<string, unknown> = {},
  severity: Finding["severity"] = "error",
): void {
  const preview = redact(raw);
  if (config.secretPreviews.has(preview)) {
    return;
  }
  findings.push(
    makeFinding({
      ruleId,
      message: `${message} Redacted preview: ${preview}.`,
      filePath: file.displayPath,
      line,
      severity,
      pillar: "sensitive-data",
      confidence,
      remediation: "Remove the sensitive value and load it from a secure runtime source.",
      metadata: { ...metadata, preview },
    }),
  );
}

// Two-stage filter: parse the line into a (key, value) pair, then apply the secret-shape filters.
// Splitting them keeps the regex simple — the line shape is shared, only the value test changes.
function hardcodedEnvValue(line: string, minLength: number): { keyName: string; value: string } | undefined {
  const candidate = envValueCandidate(line);
  if (!candidate || !isHardcodedEnvCandidate(candidate.value, minLength)) {
    return undefined;
  }
  return candidate;
}

// Matches the documented secret-key vocabulary (API_KEY, TOKEN, SECRET, PASSWORD, DATABASE_URL,
// DSN, CREDENTIAL). Expanding this list will widen sensitive-data coverage — keep it intentional.
function envValueCandidate(line: string): { keyName: string; value: string } | undefined {
  const match = line.match(/^\s*((?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)|[A-Z][A-Z0-9_-]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_-]*)\s*[:=]\s*["']?([^"'\s#]+)["']?/i);
  const keyName = match?.[1] ?? "";
  const secretValue = match?.[2] ?? "";
  if (!keyName) {
    return undefined;
  }
  return { keyName, value: secretValue };
}

// Three predicates combined: long enough, not a literal placeholder, and shape-like (letters + digits).
// All three are required — dropping any one regresses to noisy findings on fixture values.
function isHardcodedEnvCandidate(secretValue: string, minLength: number): boolean {
  return secretValue.length >= minLength && !isPlaceholderSecretValue(secretValue) && hasLetterAndDigit(secretValue);
}

// Allowlist of obvious fixture words. Case-insensitive so `Placeholder`, `PASSWORD` and similar
// fixture values stay quiet. Extend deliberately — the cost of a missing word is a false positive.
function isPlaceholderSecretValue(secretValue: string): boolean {
  return /^(?:x-api-key|token|secret|password|example|sample|placeholder)$/i.test(secretValue);
}

// Cheap shape filter: rejects all-letters words and all-digit numbers before the more expensive
// entropy work runs. False negatives here are acceptable; false positives waste maintainer time.
function hasLetterAndDigit(candidateText: string): boolean {
  return /[A-Za-z]/.test(candidateText) && /[0-9]/.test(candidateText);
}

// Layered filter for the entropy detector. Order matters: cheap rejections (length, hex digest,
// SRI hash) run before character-set checks before the entropy calculation itself, which is the
// most expensive step. Reordering changes nothing semantically but can regress scan performance.
function isHighEntropySecretCandidate(candidateText: string, minLength: number): boolean {
  if (isExcludedHighEntropyCandidate(candidateText, minLength)) {
    return false;
  }
  if (!hasLowerUpperAndDigit(candidateText)) {
    return false;
  }
  if (!hasEnoughDistinctCharacters(candidateText)) {
    return false;
  }
  return shannonEntropy(candidateText) >= 4;
}

// Entropy false-positive escape hatches. Hex digests and SRI hashes both look "high entropy" but
// are well-known non-secrets — without these exclusions, package-lock.json scans become noise.
// Repo-relative path-shaped strings (slashes plus a known extension and a conventional prefix
// segment) also clear the entropy bar without being secrets; the path-shape guard suppresses them.
function isExcludedHighEntropyCandidate(candidateText: string, minLength: number): boolean {
  return candidateText.length < minLength || isHexDigest(candidateText) || isSubresourceIntegrityHash(candidateText) || isRepoPathShape(candidateText);
}

// Path-shape guard: a string that contains at least one `/`, has a path-like extension, AND lives
// under a conventional source/docs/test/workflow prefix is almost always a repo-relative reference
// rather than a secret. The combined gate keeps the rule firing on real high-entropy material that
// happens to contain slashes.
function isRepoPathShape(candidateText: string): boolean {
  if (!candidateText.includes("/")) {
    return false;
  }
  const hasKnownExtension = /\.(?:md|mdx|ts|tsx|js|jsx|mjs|cjs|json|yaml|yml|toml|html|css|svg|sh)$/.test(candidateText);
  const hasKnownPrefix = /^(?:\.?[A-Za-z][A-Za-z0-9_-]*\/)+/.test(candidateText);
  return hasKnownExtension && hasKnownPrefix;
}

// All-hex strings — typical for SHA digests, content hashes, and tooling identifiers.
function isHexDigest(candidateText: string): boolean {
  return /^[0-9a-f]+$/i.test(candidateText);
}

// SRI hashes from `package-lock.json` and `<script integrity=...>` attributes. Excluded so the
// detector stays quiet on dependency manifests.
function isSubresourceIntegrityHash(candidateText: string): boolean {
  return /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(candidateText);
}

// Three-class character requirement that filters out single-case identifiers and pure base64 hashes
// before the entropy calculation runs. Real API tokens almost always contain all three classes.
function hasLowerUpperAndDigit(candidateText: string): boolean {
  return /[a-z]/.test(candidateText) && /[A-Z]/.test(candidateText) && /[0-9]/.test(candidateText);
}

// Distinct-character guard. The cap at 12 keeps a long alphabet from inflating the requirement;
// the `ceil(length/3)` floor scales the threshold with the candidate length.
function hasEnoughDistinctCharacters(candidateText: string): boolean {
  return new Set(candidateText).size >= Math.min(12, Math.ceil(candidateText.length / 3));
}

// Standard Shannon entropy in bits per symbol. The 4.0-bit threshold in the caller corresponds
// roughly to a uniform alphabet of 16 distinct characters — the typical floor for real secrets.
function shannonEntropy(candidateText: string): number {
  const counts = new Map<string, number>();
  for (const character of candidateText) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((sum, count) => {
    const probability = count / candidateText.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}

// Preview format used in finding messages. Short values are fully masked; longer values show only
// the first/last 4 characters so an operator can identify which secret to rotate without leaking it.
function redact(rawSecret: string): string {
  if (rawSecret.length <= 8) {
    return `${"*".repeat(rawSecret.length)} (redacted, ${rawSecret.length} chars)`;
  }
  return `${rawSecret.slice(0, 4)}...${rawSecret.slice(-4)} (redacted, ${rawSecret.length} chars)`;
}

export { analyseSensitiveData };
