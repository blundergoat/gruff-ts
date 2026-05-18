import { ruleSeverity, threshold } from "./config.ts";
import { makeFinding } from "./findings.ts";
import { byteLine } from "./text-scans.ts";
import type { Config, Finding } from "./types.ts";

interface SensitiveSourceFile {
  displayPath: string;
}

function analyseSensitiveData(file: SensitiveSourceFile, source: string, config: Config, findings: Finding[]): void {
  const patterns: Array<[string, RegExp, string]> = [
    ["sensitive-data.aws-access-key", /AKIA[0-9A-Z]{16}/g, "AWS access key pattern detected."],
    ["sensitive-data.private-key", /BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY/g, "Private key block detected."],
    ["sensitive-data.jwt-token", /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "JWT-looking token detected."],
    ["sensitive-data.database-url-password", /[a-z]+:\/\/[^:\s]+:[^@\s]+@/g, "Database URL appears to include a password."],
    [
      "sensitive-data.api-key-pattern",
      /\b(?:sk_live_[A-Za-z0-9_-]{12,}|sk_test_[A-Za-z0-9_-]{12,}|sk-proj-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g,
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
  analyseHighEntropyStrings(file, source, config, findings);
}

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

function hardcodedEnvValue(line: string, minLength: number): { keyName: string; value: string } | undefined {
  const candidate = envValueCandidate(line);
  if (!candidate || !isHardcodedEnvCandidate(candidate.value, minLength)) {
    return undefined;
  }
  return candidate;
}

function envValueCandidate(line: string): { keyName: string; value: string } | undefined {
  const match = line.match(/^\s*([A-Z][A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|DATABASE_URL|DSN)[A-Z0-9_]*)\s*[:=]\s*["']?([^"'\s#]+)["']?/i);
  const keyName = match?.[1] ?? "";
  const secretValue = match?.[2] ?? "";
  if (!keyName) {
    return undefined;
  }
  return { keyName, value: secretValue };
}

function isHardcodedEnvCandidate(value: string, minLength: number): boolean {
  return value.length >= minLength && !isPlaceholderSecretValue(value) && hasLetterAndDigit(value);
}

function isPlaceholderSecretValue(value: string): boolean {
  return /^(?:x-api-key|token|secret|password|example|sample|placeholder)$/i.test(value);
}

function hasLetterAndDigit(value: string): boolean {
  return /[A-Za-z]/.test(value) && /[0-9]/.test(value);
}

function isHighEntropySecretCandidate(value: string, minLength: number): boolean {
  if (isExcludedHighEntropyCandidate(value, minLength)) {
    return false;
  }
  if (!hasLowerUpperAndDigit(value)) {
    return false;
  }
  if (!hasEnoughDistinctCharacters(value)) {
    return false;
  }
  return shannonEntropy(value) >= 4;
}

function isExcludedHighEntropyCandidate(value: string, minLength: number): boolean {
  return value.length < minLength || isHexDigest(value) || isSubresourceIntegrityHash(value);
}

function isHexDigest(value: string): boolean {
  return /^[0-9a-f]+$/i.test(value);
}

function isSubresourceIntegrityHash(value: string): boolean {
  return /^sha(?:256|384|512)-[A-Za-z0-9+/=]+$/.test(value);
}

function hasLowerUpperAndDigit(value: string): boolean {
  return /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value);
}

function hasEnoughDistinctCharacters(value: string): boolean {
  return new Set(value).size >= Math.min(12, Math.ceil(value.length / 3));
}

function shannonEntropy(value: string): number {
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  return [...counts.values()].reduce((sum, count) => {
    const probability = count / value.length;
    return sum - probability * Math.log2(probability);
  }, 0);
}

function redact(value: string): string {
  if (value.length <= 8) {
    return `${"*".repeat(value.length)} (redacted, ${value.length} chars)`;
  }
  return `${value.slice(0, 4)}...${value.slice(-4)} (redacted, ${value.length} chars)`;
}

export { analyseSensitiveData };
