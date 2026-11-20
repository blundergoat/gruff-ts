// Finding construction keeps report fields, baseline fingerprints, and cross-edit identities consistent.
//
// Rules provide user-facing evidence through one shared input shape.
// This module omits absent fields and adds deterministic identifiers before any renderer or baseline sees the finding.
import { createHash } from "node:crypto";
import type { Confidence, Finding, Pillar, Severity } from "./types.ts";

// Describes the evidence one rule supplies before a complete user-facing finding is built.
//
// Optional locations and guidance stay absent when the rule cannot provide them.
// Stable contract: centralized identifiers make every report and baseline interpret the same occurrence consistently.
interface FindingInput {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  endLine?: number;
  // The optional one-based column separates same-line occurrences in reports without changing the baseline fingerprint (ADR-017).
  column?: number;
  severity: Severity;
  pillar: Pillar;
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
}

// Builds a report finding from findingInput, which supplies the rule, location, message, severity and supporting evidence.
// Returns the finding with a stable baseline fingerprint and cross-edit identity.
function makeFinding(findingInput: FindingInput): Finding {
  // Missing line or symbol values occupy stable empty slots so that the fields keep their positions in the fingerprint input.
  const fingerprint = createHash("sha256")
    .update([findingInput.ruleId, findingInput.filePath, findingInput.line ?? "", findingInput.symbol ?? ""].join("\0"))
    .digest("hex")
    .slice(0, 16);
  // Omits missing or zero coordinates and empty optional text so consumers can treat them as unavailable. Missing metadata becomes an empty object.
  return {
    ruleId: findingInput.ruleId,
    message: findingInput.message,
    filePath: findingInput.filePath,
    ...(findingInput.line ? { line: findingInput.line } : {}),
    ...(findingInput.endLine ? { endLine: findingInput.endLine } : {}),
    ...(findingInput.column ? { column: findingInput.column } : {}),
    severity: findingInput.severity,
    pillar: findingInput.pillar,
    secondaryPillars: [],
    tier: "v0.1",
    confidence: findingInput.confidence,
    ...(findingInput.symbol ? { symbol: findingInput.symbol } : {}),
    ...(findingInput.remediation ? { remediation: findingInput.remediation } : {}),
    metadata: findingInput.metadata ?? {},
    fingerprint,
    stableIdentity: stableIdentityFor(findingInput),
  };
}

// Builds the line-insensitive identity external diff tools use to track a finding across edits.
// Match columns distinguish same-line occurrences without storing secret-derived text.
function stableIdentityFor(findingInput: FindingInput): string {
  // Empty or missing symbols cannot identify the user's code, so those findings fall back to their user-facing message.
  const hasNamedSymbol = typeof findingInput.symbol === "string" && findingInput.symbol.length > 0;
  const symbolOrMessage = hasNamedSymbol ? findingInput.symbol : findingInput.message;
  // A named symbol already identifies the user's code; otherwise a known column keeps same-line occurrences separate.
  const occurrenceIdentity = hasNamedSymbol || findingInput.column === undefined
    ? symbolOrMessage
    : `${symbolOrMessage}\0column:${findingInput.column}`;
  return createHash("sha256")
    .update([findingInput.ruleId, findingInput.filePath, occurrenceIdentity].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

export { makeFinding };
