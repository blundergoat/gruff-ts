// Size and complexity findings report in two bands (FAMILY-CONTRACT.md section 12, search `Size and complexity findings
// in two bands`). A unit over its limit but under one and a half times it gets an advisory notice not to grow; at that
// ratio or above it keeps its severity and the advice to split or simplify. The message never changes between bands,
// so a finding keeps its identity when its unit crosses the boundary.

import type { Severity } from "./types.ts";

// The fixed ratio at which a finding moves into the upper band; no option changes it.
const UPPER_BAND_RATIO = 1.5;

export const LOWER_BAND_FUNCTION = "Do not add to this function; put new code in a new function.";
export const LOWER_BAND_FILE = "Do not add to this file; put new code in a new file.";
export const LOWER_BAND_PARAMETER = "Do not add another parameter to this function.";
export const SPLIT_FILE = "Split this file by responsibility, one responsibility per file.";
export const SPLIT_FUNCTION = "Split this function at its steps, one step per function.";
export const GROUP_PARAMETERS = "Group the parameters that travel together into one object, or split the function by caller.";
export const SIMPLIFY_PATH = "Simplify the execution path: return early, merge branches that lead to the same result, and drop flags that steer later branches. Moving branches into helpers leaves the path as hard to follow.";

/** The value of a banded finding's `limitBand` metadata key. */
export type LimitBand = "lower" | "upper";

// The severity, advice and band key one banded finding carries.
export interface BandedFields {
  severity: Severity;
  remediation: string;
  limitBand: LimitBand;
}

// Names the band a measured value falls in against the limit in force, compared without rounding.
export function limitBand(measured: number, limit: number): LimitBand {
  return measured >= UPPER_BAND_RATIO * limit ? "upper" : "lower";
}

// Puts one size or complexity finding in its band: a lower-band finding is advisory whatever severity the user
// configured, and either band carries its own advice.
export function bandedFields(measured: number, limit: number, configuredSeverity: Severity, lowerAdvice: string, upperAdvice: string): BandedFields {
  const band = limitBand(measured, limit);
  return band === "lower"
    ? { severity: "advisory", remediation: lowerAdvice, limitBand: band }
    : { severity: configuredSeverity, remediation: upperAdvice, limitBand: band };
}
