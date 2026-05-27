/** Finding impact level used for scoring, output, and fail-on thresholds. */
export type Severity = "advisory" | "warning" | "error";

/** High-level rubric category assigned to every finding. */
export type Pillar =
  | "size"
  | "complexity"
  | "dead-code"
  | "maintainability"
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
  shouldSkipConfig: boolean;
  format: OutputFormat;
  failOn: FailThreshold;
  shouldIncludeIgnored: boolean;
  diff?: string;
  historyFile?: string;
  baseline?: string;
  generateBaseline?: string;
  shouldSkipBaseline: boolean;
}

/** Command keys that participate in the `minimumSeverity:` config block. `dashboard` is omitted on purpose - it has no `--fail-on` flag and accepting it as a key would silently no-op. See ADR-004. */
export type MinimumSeverityCommand = "analyse" | "summary" | "report";

/**
 * Loaded analyzer configuration derived from optional gruff config files. The schema invariant is
 * that `schemaVersion` is fixed at the supported version and every field has a defined default in
 * `defaultConfig()` so consumers can rely on the shape without per-field guards.
 */
export interface Config {
  /**
   * Required top-level config-schema version. Pre-1.0 break: every `.gruff-ts.yaml` must declare
   * `schemaVersion: gruff-ts.config.v0.1` or loading throws. Lives in the `gruff-ts.config.*`
   * namespace, distinct from the output schemas (`gruff.analysis.v2`, etc.). See ADR-004.
   */
  schemaVersion: "gruff-ts.config.v0.1";
  ignoredPaths: string[];
  acceptedAbbreviations: Set<string>;
  secretPreviews: Set<string>;
  bannedGenericNames: Set<string>;
  booleanPrefixes: Set<string>;
  hungarianPrefixes: Set<string>;
  placeholderNames: Set<string>;
  negativeBooleanAllowed: Set<string>;
  knownAcronyms: Set<string>;
  /**
   * Per-command default for `--fail-on`. Precedence: CLI flag > this map > binary default.
   * `dashboard` is intentionally not a valid key (no `--fail-on` flag exists for it); the parser
   * rejects `dashboard` with a documented error. See ADR-004.
   */
  minimumSeverity: Map<MinimumSeverityCommand, FailThreshold>;
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

/** Stable gruff.analysis.v2 report schema returned by analyse and JSON report commands. */
export interface AnalysisReport {
  schemaVersion: "gruff.analysis.v2";
  tool: { name: "gruff-ts"; version: string };
  run: { projectRoot: string; format: OutputFormat; failOn: FailThreshold; generatedAt: string };
  summary: { advisory: number; warning: number; error: number; total: number };
  paths: { analysedFiles: number; ignoredPaths: string[]; missingPaths: string[] };
  diagnostics: RunDiagnostic[];
  findings: Finding[];
  score: {
    composite: number;
    grade: string;
    pillars: Array<{ pillar: Pillar; score: number; penalty: number; findings: number }>;
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
  /**
   * Names of `allowlists.*` keys in `.gruff-ts.yaml` that override or extend the rule's
   * behaviour. Mirrors the `optionKeys` shape but targets the cross-pillar allowlist surface
   * (e.g. `naming.boolean-prefix` consults `allowlists.booleanPrefixes`). Surfaced in the
   * `list-rules --format=json` payload and the per-rule remediation text so operators don't
   * have to grep `.gruff-ts.yaml` and `src/config.ts` to find the override knob.
   */
  allowlistKeys?: readonly string[];
  fixtureExemption?: string;
}
