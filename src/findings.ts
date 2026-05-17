import { createHash } from "node:crypto";
import type { Confidence, Finding, Pillar, Severity } from "./types.ts";

interface FindingInput {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  severity: Severity;
  pillar: Pillar;
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}

function makeFinding(input: FindingInput): Finding {
  const fingerprint = createHash("sha256")
    .update([input.ruleId, input.filePath, input.line ?? "", input.symbol ?? ""].join("\0"))
    .digest("hex")
    .slice(0, 16);
  return {
    ruleId: input.ruleId,
    message: input.message,
    filePath: input.filePath,
    ...(input.line ? { line: input.line } : {}),
    severity: input.severity,
    pillar: input.pillar,
    secondaryPillars: [],
    tier: "v0.1",
    confidence: input.confidence,
    ...(input.symbol ? { symbol: input.symbol } : {}),
    ...(input.remediation ? { remediation: input.remediation } : {}),
    metadata: input.metadata ?? {},
    fingerprint,
  };
}

export { makeFinding };
