// Shared analyzer types define the settings, findings, diagnostics, and reports exposed across the TypeScript port.
//
// CLI commands and rules use these shapes so users and integrations receive one stable interpretation of missing and present values.

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

/** Changed-region filter precision for diff-aware analysis. */
export type ChangedScopeMode = "symbol" | "hunk" | "file";

/** Records which layer selected the effective bounded deep-scan settings. */
export type DeepScanBudgetOverrideState = "default" | "config" | "cli";

/** Effective per-source bounds for expensive script analysis. */
export interface DeepScanBudget {
  enabled: boolean;
  maxLines: number;
  maxBytes: number;
  override: DeepScanBudgetOverrideState;
}

/** Atomic CLI override; disabling the budget intentionally carries no numeric limits. */
export type DeepScanBudgetOverride =
  | { enabled: false }
  | { enabled: true; maxLines: number; maxBytes: number };

/**
 * Defines the stable options contract resolved from one user command before analysis starts.
 *
 * Optional paths and filters stay absent when the user did not select them, allowing downstream code to preserve default behavior.
 */
export interface AnalysisOptions {
  paths: string[];
  config?: string;
  /** CLI profile name or file; missing means use the config-file profile or the recommended default. */
  profile?: string;
  shouldSkipConfig: boolean;
  format: OutputFormat;
  failOn: FailThreshold;
  shouldIncludeIgnored: boolean;
  diff?: string;
  since?: string;
  changedRanges?: string;
  changedScope: ChangedScopeMode;
  diffPatch?: string;
  historyFile?: string;
  baseline?: string;
  generateBaseline?: string;
  shouldSkipBaseline: boolean;
  deepScanBudget?: DeepScanBudgetOverride;
}

/** Commands that support `minimumSeverity`; dashboard is absent because it has no `--fail-on` behavior (ADR-004). */
export type MinimumSeverityCommand = "analyse" | "summary" | "report";

/**
 * Describes the complete settings used for one user scan after defaults, profiles, and config overlays.
 *
 * Every collection is present even when empty, while the fixed schema version lets consumers use the shape without field guards.
 */
export interface Config {
  /** Required config-schema version; missing or different values stop the user's command before analysis (ADR-004). */
  schemaVersion: "gruff-ts.config.v0.1";
  ignoredPaths: string[];
  acceptedAbbreviations: Set<string>;
  bannedGenericNames: Set<string>;
  acceptedBooleanNames: Set<string>;
  acceptedClassFilePairs: Set<string>;
  acceptedCasingPairs: Set<string>;
  booleanPrefixes: Set<string>;
  hungarianPrefixes: Set<string>;
  placeholderNames: Set<string>;
  negativeBooleanAllowed: Set<string>;
  knownAcronyms: Set<string>;
  /** Per-command `--fail-on` defaults; an empty map means each command continues to its binary default (ADR-004). */
  minimumSeverity: Map<MinimumSeverityCommand, FailThreshold>;
  rules: Map<string, { enabled?: boolean; threshold?: number; severity?: Severity; options: Map<string, number> }>;
  deepScanBudget: DeepScanBudget;
  /** Reviewed sensitive-data suppressions in declaration order; an empty list means nothing is suppressed. */
  sensitiveExclusions: SensitiveExclusion[];
}

/**
 * Describes one reviewed suppression from the config file's `sensitiveExclusions:` section.
 *
 * The scope is exactly one rule id in exactly one project-relative file, narrowed further when the user supplies a symbol.
 * Stable contract: nothing is matched against a finding's message or its detected value, so a suppression can never depend on secret material.
 */
export interface SensitiveExclusion {
  rule: string;
  path: string;
  /** Present only when the user narrowed the scope; a finding without that exact symbol keeps reporting. */
  symbol?: string;
  reason: string;
}

/**
 * Reports what one configured sensitive exclusion suppressed during the user's scan.
 *
 * Every configured entry publishes a row even when it matched nothing, so a suppression is counted rather than silently invisible.
 * `symbol` is null when the entry did not narrow to one, and `paths` holds the entry's single configured path as the family-shaped list.
 */
export interface SuppressionSummary {
  index: number;
  rule: string;
  paths: string[];
  symbol: string | null;
  reason: string;
  suppressed: number;
}

/**
 * Describes one rule override inside a profile before it joins the user's effective configuration.
 *
 * Missing fields inherit from the base profile or descriptor; a missing options map means the profile did not tune numeric options.
 */
export interface ProfileRuleSetting {
  enabled?: boolean;
  threshold?: number;
  severity?: Severity;
  options?: Map<string, number>;
}

/**
 * What a user writes for `profile:` (or passes to `--profile`): a built-in name / file path string,
 * or an inline object that extends a base profile and layers per-rule and path overrides on top.
 */
export type ProfileSpec = string | InlineProfileSpec;

/**
 * Describes the inline profile form users can place in configuration.
 *
 * Missing `extends` selects recommended; missing rules or ignored paths inherit the base, while supplied values use child-wins behavior.
 */
export interface InlineProfileSpec {
  extends?: string;
  rules?: Record<string, ProfileRuleSetting>;
  ignoredPaths?: string[];
}

/**
 * Describes a fully resolved profile ready to sit beneath the user's direct configuration.
 *
 * Empty rules or ignored paths mean the profile adds no values in that area; the recommended profile is therefore a no-op delta.
 */
export interface ProfileDefinition {
  name: string;
  rules: Map<string, ProfileRuleSetting>;
  ignoredPaths: string[];
}

/**
 * Defines the stable finding contract shown in user reports and machine integrations.
 *
 * Missing locations, symbols, or remediation mean the rule could not provide that context; metadata remains an object even when empty.
 */
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
  stableIdentity: string;
}

/**
 * Describes a runtime problem encountered while preparing or reading the user's scan inputs.
 *
 * Missing file or line fields mean the problem applies to the command or input set rather than one precise source location.
 */
export interface RunDiagnostic {
  diagnosticType: string;
  message: string;
  filePath?: string;
  line?: number;
  /** False marks a visible diagnostic that must not change an otherwise-successful exit status. */
  invalidatesRun?: false;
}

/**
 * Names the policy source that excluded a path from the user's scan.
 *
 * Config ignores always apply; `--include-ignored` can bypass discovery ignores from Git or Gruff defaults (ADR-003).
 */
export type IgnoreSource = "config" | "gitignore" | "default";

/**
 * Describes one path excluded from the user's analysis surface.
 *
 * The source and matching pattern explain why it was skipped, so no field is optional or empty for a recorded entry.
 */
export interface SkippedPath {
  path: string;
  source: IgnoreSource;
  pattern: string;
}

/**
 * Describes a non-fatal difference between the scan surface requested by the user and the files Gruff could analyze.
 *
 * Notes explain empty, bounded, or non-text inputs without changing exit status; fatal preparation problems remain diagnostics.
 */
export interface ScanSurfaceNote {
  noteType: "no-analysable-files" | "bounded-deep-scan" | "non-text-file";
  path: string;
  message: string;
}

/**
 * Defines the stable `gruff.analysis.v2` report contract returned to users and integrations.
 *
 * Empty findings or diagnostics mean none occurred; optional notes, suppression, and baseline fields appear only when that feature participated.
 */
export interface AnalysisReport {
  schemaVersion: "gruff.analysis.v2";
  tool: { name: "gruff-ts"; version: string };
  run: { projectRoot: string; format: OutputFormat; failOn: FailThreshold; generatedAt: string };
  summary: { advisory: number; warning: number; error: number; total: number };
  paths: { analysedFiles: number; ignoredPaths: string[]; skipped: SkippedPath[]; missingPaths: string[] };
  diagnostics: RunDiagnostic[];
  /** Missing means the scan produced no non-fatal surface notes. */
  notes?: ScanSurfaceNote[];
  /** One audit row per configured `sensitiveExclusions:` entry, in declaration order; empty when none are configured. */
  suppressions: SuppressionSummary[];
  findings: Finding[];
  suppressedCount?: number;
  score: {
    composite: number;
    grade: string;
    pillars: Array<{ pillar: Pillar; score: number; penalty: number; findings: number }>;
    topOffenders: Array<{ filePath: string; score: number; findings: number }>;
  };
  baseline?: { path: string; source: string; suppressed: number; generated: boolean };
}

/**
 * Describes one rule in the catalogue shown by `list-rules` and used during configuration validation.
 *
 * Missing thresholds, options, allowlists, or fixture exemptions mean the rule does not expose that user-facing control.
 */
export interface RuleDescriptor {
  ruleId: string;
  pillar: Pillar;
  severity: Severity;
  confidence: Confidence;
  description: string;
  remediation: string;
  threshold?: number;
  optionKeys?: readonly string[];
  /** Allowlist keys shown to users for this rule; missing means the rule has no allowlist control. */
  allowlistKeys?: readonly string[];
  fixtureExemption?: string;
}
