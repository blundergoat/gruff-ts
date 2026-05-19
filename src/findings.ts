import { createHash } from "node:crypto";
import type { Confidence, Finding, Pillar, Severity } from "./types.ts";

// Caller-supplied fields. makeFinding hashes (ruleId, filePath, line, symbol) into the fingerprint,
// so any field added here that should affect baseline identity must also be folded into that hash.
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

// Builds the canonical Finding shape. The 16-hex fingerprint is the baseline identity used by
// `gruff.baseline.v1`; changing the hashed fields or their join order is a baseline-breaking
// schema change. Optional fields are omitted (not set to undefined) so finding equality stays stable.
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
