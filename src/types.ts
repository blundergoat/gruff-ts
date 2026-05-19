/** Finding impact level used for scoring, output, and fail-on thresholds. */
export type Severity = "advisory" | "warning" | "error";

/** High-level rubric category assigned to every finding. */
export type Pillar =
  | "size"
  | "complexity"
  | "dead-code"
  | "waste"
  | "naming"
  | "documentation"
  | "modernisation"
  | "security"
  | "sensitive-data"
  | "test-quality"
  | "design";

/** Analyzer confidence attached to a finding or descriptor. */
export type Confidence = "low" | "medium" | "high";

/** Output renderer selected by CLI options or direct callers. */
export type OutputFormat = "text" | "json" | "html" | "markdown" | "github" | "hotspot" | "sarif";

/** Minimum severity that causes a non-zero CLI exit. */
export type FailThreshold = "none" | "advisory" | "warning" | "error";

/** Public options contract consumed by the analyzer core and CLI. */
export interface AnalysisOptions {
  paths: string[];
  config?: string;
  noConfig: boolean;
  format: OutputFormat;
  failOn: FailThreshold;
  includeIgnored: boolean;
  diff?: string;
  historyFile?: string;
  baseline?: string;
  generateBaseline?: string;
  noBaseline: boolean;
}

/** Loaded analyzer configuration derived from optional gruff config files. */
export interface Config {
  ignoredPaths: string[];
  acceptedAbbreviations: Set<string>;
  secretPreviews: Set<string>;
  bannedGenericNames: Set<string>;
  booleanPrefixes: Set<string>;
  hungarianPrefixes: Set<string>;
  placeholderNames: Set<string>;
  abbreviationDenylist: Set<string>;
  negativeBooleanAllowed: Set<string>;
  knownAcronyms: Set<string>;
  rules: Map<string, { enabled?: boolean; threshold?: number; severity?: Severity; options: Map<string, number> }>;
}

/** Stable analysis finding emitted by a rule. */
export interface Finding {
  ruleId: string;
  message: string;
  filePath: string;
  line?: number;
  endLine?: number;
  column?: number;
  severity: Severity;
  pillar: Pillar;
  secondaryPillars: Pillar[];
  tier: "v0.1";
  confidence: Confidence;
  symbol?: string;
  remediation?: string;
  metadata: Record<string, unknown>;
  fingerprint: string;
}

/** Non-finding runtime diagnostic emitted while preparing or reading inputs. */
export interface RunDiagnostic {
  diagnosticType: string;
  message: string;
  filePath?: string;
  line?: number;
}

/** Stable gruff.analysis.v1 report schema returned by analyse and JSON report commands. */
export interface AnalysisReport {
  schemaVersion: "gruff.analysis.v1";
  tool: { name: "gruff-ts"; version: string };
  run: { projectRoot: string; format: OutputFormat; failOn: FailThreshold; generatedAt: string };
  summary: { advisory: number; warning: number; error: number; total: number };
  paths: { analysedFiles: number; ignoredPaths: string[]; missingPaths: string[] };
  diagnostics: RunDiagnostic[];
  findings: Finding[];
  score: {
    composite: number;
    grade: string;
    pillars: Array<{ pillar: Pillar; score: number; findings: number }>;
    topOffenders: Array<{ filePath: string; score: number; findings: number }>;
  };
  baseline?: { path: string; source: string; suppressed: number; generated: boolean };
}

/** Static catalogue entry describing a rule's purpose and configuration knobs. */
export interface RuleDescriptor {
  ruleId: string;
  pillar: Pillar;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
  threshold?: number;
  optionKeys?: readonly string[];
  fixtureExemption?: string;
}
