// `gruff.hook.v2` adapter: owns the agent-hook JSON shape independently of the analysis v3 envelope.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import { tmpdir } from "node:os";
import { applyBaseline, BASELINE_SCHEMA_VERSION } from "./baseline-file.ts";
import { absolutize, displayPath } from "./discovery.ts";
import { VERSION } from "./constants.ts";
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisOptions, AnalysisReport, Confidence, Finding, RunDiagnostic, Severity, SkippedPath, SuppressionSummary } from "./types.ts";

type HookScope = "line" | "symbol" | "file" | "project";
type FlagOrder = "any" | "flags-before-path";
type HookAnalysisViews = { currentReport: AnalysisReport; scopedReport: AnalysisReport };
type HookAnalysisRunner = ((options: AnalysisOptions) => AnalysisReport) & {
  hookViews?: (currentOptions: AnalysisOptions, scopedOptions: AnalysisOptions, hasChangedRegion: boolean) => HookAnalysisViews;
};

// Inputs for one hook render: full-scan options, changed-region options, and optional baseline/diff
// bases used for new-only filtering.
interface HookReportInput {
  currentOptions: AnalysisOptions;
  scopedOptions: AnalysisOptions;
  baselinePath?: string;
  diffBase?: string;
  hasChangedRegion: boolean;
}

/*
 * What the caller asked the hook to block on, read once the payload is built.
 *
 * Every field is a gate rather than a filter: nothing here changes what the agent is shown, only whether the
 * edit is allowed to stand.
 */
export interface HookExitGate {
  failOn: Severity | "none";
  minConfidence: Confidence;
  shouldFailOnNew: boolean;
  shouldFailOnDiagnostics: boolean;
}

// The gruff.hook.v2 envelope written to stdout; field names are the cross-analyzer contract.
interface HookReport {
  contractVersion: "gruff.hook.v2";
  analyzer: { name: "gruff-ts"; version: string };
  // Audit data a consumer needs to trust the verdict: what ran, over what, and against which baseline.
  run: HookRun;
  findings: HookFinding[];
  // File-scoped parse/read diagnostics relevant to the analysed change, reported in-band. The
  // default hook exit stays 0; only an explicit --fail-on-diagnostics run turns these into exit 1.
  diagnostics: HookDiagnostic[];
  suppressed: { count: number };
  // The section 13a audit: one row per configured sensitive exclusion this run applied.
  suppressions: HookSuppression[];
  ignored: { paths: SkippedPath[] };
  config: { schemaOk: boolean; error: HookConfigError | null };
}

/*
 * What one hook run was asked to do, so a clean payload is never ambiguous.
 *
 * Without it a run that analysed nothing and a run that found nothing look identical on the wire.
 * Stable contract: every field is present on every run, and `analysedFiles` reports zero rather than omitting itself.
 */
interface HookRun {
  mode: "changed-ranges" | "diff" | "since" | "full";
  scope: "symbol" | "hunk" | "file";
  paths: string[];
  analysedFiles: number;
  baseline: { applied: boolean; schemaVersion: string | null; path: string | null };
}

// A configuration failure the consumer can act on; never a bare string, so the fix is machine-readable too.
interface HookConfigError {
  message: string;
  remediation: string;
}

// One configured sensitive exclusion and what it removed from this run, per section 13a.
interface HookSuppression {
  rule: string;
  path: string;
  symbol?: string;
  reason: string;
  suppressed: number;
  source?: "built-in" | "inline" | "duplicate";
}

// One diagnostic projected into the hook contract: what kind of problem, how much it matters, where, and the
// message a consumer can surface. `file`/`line` are absent for operational diagnostics with no anchor.
interface HookDiagnostic {
  type: string;
  severity: "info" | "warning" | "fatal";
  message: string;
  file?: string;
  line?: number;
  invalidatesRun?: false;
}

// A finding projected into the hook contract, with enum scope and non-null remediation, named by the ratified
// family identity and keyed for new-only tracking by the port-local fingerprint.
interface HookFinding {
  ruleId: string;
  pillar: string;
  severity: Severity;
  confidence: Confidence;
  scope: HookScope;
  file: string;
  line?: number;
  // The last line of the finding's span, equal to `line` for a single-line finding; a consumer cannot guess it.
  endLine?: number;
  // One-based match column, present when the scanner pinpointed the occurrence. Two secrets on one
  // line share every other field, so this is the only thing that lets a consumer tell them apart.
  column?: number;
  symbol: string | null;
  // The 1-based declaration ordinal the identity hashed, and 0 when the finding names no symbol.
  symbolOrdinal: number;
  message: string;
  remediation: string;
  metadata: Record<string, unknown>;
  // The ratified family identity, and null for a sensitive finding, which the identity contract never names.
  stableIdentity: string | null;
  // What an applied baseline made of this finding, and null when no baseline was applied.
  baselineStatus: string | null;
  fingerprint: string;
}

// What a baseline made of each finding this run produced, so the payload can report a status per finding.
type HookBaselineStatuses = Map<Finding, string>;

const HOOK_CONTRACT_VERSION = "gruff.hook.v2";
const FILE_SCOPE_RULE_IDS = new Set(["design.large-module-concentration", "docs.missing-file-overview", "size.file-length"]);
const PROJECT_SCOPE_RULE_IDS = new Set(["design.circular-import"]);
const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, advisory: 2 };
// Gate order, loosest last: a finding at or above the requested floor reaches the gate.
const SEVERITY_GATE_RANK: Record<Severity, number> = { error: 2, warning: 1, advisory: 0 };
const CONFIDENCE_GATE_RANK: Record<Confidence, number> = { high: 2, medium: 1, low: 0 };
const DESCRIPTORS = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor]));
// Every number a finding's subject can carry after its symbol; the trailing group is the declaration ordinal.
const TRAILING_ORDINAL = /#(\d+)$/u;
const CONFIG_ERROR_REMEDIATION = "Fix the reported problem in .gruff-ts.yaml, or pass --no-config to run without it.";

// Returns the gruff.hook.v2 capability handshake as pretty-printed JSON with a trailing newline.
// Consumers use its stable supports and flags fields to select options before submitting an analysis request.
export function renderHookCapabilities(): string {
  return JSON.stringify({
    contractVersion: HOOK_CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    supports: {
      baseline: true,
      baselineV3: true,
      changedRanges: true,
      confidenceGate: true,
      deepScanBudget: true,
      // Producer advertisement only: diagnostics are always reported in-band; the advertised
      // failOnDiagnostics flag is the explicit consumer request that changes exit semantics.
      diagnostics: true,
      diff: true,
      ignoreReport: true,
      metadata: true,
      newOnly: true,
      scopeField: true,
      stableIdentity: true,
    },
    flags: {
      baseline: "--baseline",
      changedRanges: "--changed-ranges",
      deepScanBudget: "--deep-scan-budget",
      diff: "--diff",
      failOnDiagnostics: "--fail-on-diagnostics",
      minConfidence: "--min-confidence",
    },
    flagOrder: "any" satisfies FlagOrder,
  }, null, 2) + "\n";
}

/**
 * Run analysis and apply hook filtering so the gruff.hook.v2 schema records the findings and audits the agent can act on.
 * Diff-base replay spawns Git, writes a temporary tree, and temporarily changes the process working directory.
 * An absent diff base skips replay filtering. An absent baseline skips review filtering and leaves row statuses null.
 *
 * @param runAnalyse - analysis runner used to obtain the report views and replay an available diff base
 * @param input - hook request with scan options, changed-region mode, and any baseline or diff base
 * @returns newline-terminated JSON with the run audit, filtered findings, diagnostics, exclusion audit, ignored paths, and config status
 */
export function renderHookReport(runAnalyse: HookAnalysisRunner, input: HookReportInput): string {
  const views = hookAnalysisViews(runAnalyse, input);
  const { currentReport, scopedReport } = views;
  const statuses = hookBaselineStatuses(views, input.baselinePath);
  const baseIdentities = hookDiffBaseIdentities(runAnalyse, input, currentReport);
  const kept = hookFindings(currentReport, scopedReport, input, baseIdentities, statuses);
  const suppressedCount = hookSuppressedCount(scopedReport, kept, input.hasChangedRegion);
  const findings = kept.map((finding) => toHookFinding(finding, statuses.get(finding) ?? null));
  return JSON.stringify(hookReport(scopedReport, findings, suppressedCount, hookRun(scopedReport, input)), null, 2) + "\n";
}

// Returns current and scoped reports using runAnalyse and the scan options in input, preferring runAnalyse.hookViews.
// Without that method, calls the runner twice only for a changed region; otherwise both reports share one result.
function hookAnalysisViews(runAnalyse: HookAnalysisRunner, input: HookReportInput): HookAnalysisViews {
  if (runAnalyse.hookViews) {
    return runAnalyse.hookViews(input.currentOptions, input.scopedOptions, input.hasChangedRegion);
  }
  const currentReport = runAnalyse(input.currentOptions);
  const scopedReport = input.hasChangedRegion ? runAnalyse(input.scopedOptions) : currentReport;
  return { currentReport, scopedReport };
}

/**
 * Classify hook findings against the same gruff.baseline.v3 file that analyse --generate-baseline writes, so one review serves both commands.
 * Classify the scoped report last so that its statuses take precedence for findings shared by both reports.
 *
 * @param views - Current and scoped reports whose findings need baseline classification.
 * @param baselinePath - Caller-selected baseline path, resolved from the working directory. Omission leaves the run unclassified.
 * @returns Statuses keyed by finding. A missing application status defaults to new. An omitted path yields an empty map.
 * @throws If the named baseline cannot be read or fails format, schema, or port validation.
 */
function hookBaselineStatuses(views: HookAnalysisViews, baselinePath: string | undefined): HookBaselineStatuses {
  const statuses: HookBaselineStatuses = new Map();
  // With no baseline named, no finding carries a status a consumer could misread as reviewed.
  if (baselinePath === undefined) {
    return statuses;
  }
  const resolved = absolutize(cwd(), baselinePath);
  for (const report of [views.currentReport, views.scopedReport]) {
    const application = applyBaseline(resolved, report.findings);
    report.findings.forEach((finding, index) => {
      statuses.set(finding, application.statuses[index] ?? "new");
    });
  }
  return statuses;
}

/**
 * Build an envelope for a fatal hook failure. The CLI exits with code 2 and writes the envelope unless stdout is suppressed.
 *
 * @param diagnosticType - category assigned to the sole fatal diagnostic
 * @param message - failure detail shown in the diagnostic
 * @returns newline-terminated hook JSON with empty findings, suppression rows, and ignored paths, plus default run and config fields
 */
export function renderHookFatal(diagnosticType: string, message: string): string {
  return JSON.stringify(fatalReport(diagnosticType, message), null, 2) + "\n";
}

// Returns newline-terminated hook JSON with the loader's message in the fatal diagnostic and config error, and schemaOk set to false.
// Remediation defaults to general advice so callers without a specific fix can still tell the user what to try.
export function renderHookConfigError(message: string, remediation: string = CONFIG_ERROR_REMEDIATION): string {
  const report = fatalReport("config", message);
  report.config = { schemaOk: false, error: { message, remediation } };
  return JSON.stringify(report, null, 2) + "\n";
}

// Returns a hook envelope with one fatal diagnostic built from the supplied type and message, so the caller has a payload to publish before exit 2.
// The stable contract retains the required envelope fields, with no findings or analysed files.
function fatalReport(diagnosticType: string, message: string): HookReport {
  return {
    contractVersion: HOOK_CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    run: { mode: "full", scope: "file", paths: [], analysedFiles: 0, baseline: { applied: false, schemaVersion: null, path: null } },
    findings: [],
    diagnostics: [{ type: diagnosticType, severity: "fatal", message }],
    suppressed: { count: 0 },
    suppressions: [],
    ignored: { paths: [] },
    config: { schemaOk: true, error: null },
  };
}

// Returns a gruff.hook.v2 envelope for a completed analysis with the supplied run audit, visible findings, and suppressed count.
// The analysis report supplies diagnostics, the exclusion audit, and skipped paths. The contract presents findings in stable order.
function hookReport(report: AnalysisReport, findings: HookFinding[], suppressedCount: number, run: HookRun): HookReport {
  return {
    contractVersion: HOOK_CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    run,
    findings: sortHookFindings(findings),
    diagnostics: report.diagnostics.map(toHookDiagnostic),
    suppressed: { count: suppressedCount },
    suppressions: report.suppressions.map(toHookSuppression),
    ignored: { paths: report.paths.skipped },
    config: { schemaOk: true, error: null },
  };
}

// Returns the run audit using report for the project root and analysed-file count and input for selectors and paths.
// Empty scoped paths are reported as the current directory; a present baselinePath marks applied true and reports its path.
// Without a baseline, applied is false and its schema version and path are null, so consumers can see that no review was used.
function hookRun(report: AnalysisReport, input: HookReportInput): HookRun {
  const applied = input.baselinePath !== undefined;
  return {
    mode: hookRunMode(input),
    // Every changed-region hook run widens a changed line to its declaration; a full run reads whole files.
    scope: input.hasChangedRegion ? "symbol" : "file",
    paths: input.scopedOptions.paths.length === 0 ? ["."] : [...input.scopedOptions.paths],
    analysedFiles: report.paths.analysedFiles,
    baseline: {
      applied,
      schemaVersion: applied ? BASELINE_SCHEMA_VERSION : null,
      path: applied ? displayPath(report.run.projectRoot, absolutize(cwd(), input.baselinePath ?? "")) : null,
    },
  };
}

// Names which region selector chose the work, so a consumer can tell a targeted run from a whole-tree one.
function hookRunMode(input: HookReportInput): HookRun["mode"] {
  // Explicit ranges are the narrowest selector and win when more than one is given, and an empty value is
  // still a request to scope: presence decides, not truthiness.
  if (input.scopedOptions.changedRanges !== undefined) {
    return "changed-ranges";
  }
  if (input.scopedOptions.diff || input.scopedOptions.diffPatch) {
    return "diff";
  }
  return input.scopedOptions.since ? "since" : "full";
}

// Projects a scan suppression summary into a hook audit row; an empty path list yields an empty path and a null symbol is omitted.
function toHookSuppression(summary: SuppressionSummary): HookSuppression {
  return {
    rule: summary.rule,
    // Section 13a gives each entry exactly one path; the native audit carries it in a list shape.
    path: summary.paths[0] ?? "",
    ...(summary.symbol === null ? {} : { symbol: summary.symbol }),
    reason: summary.reason,
    suppressed: summary.suppressed,
    // Built-in, inline and duplicate rows retain their source; configured rows omit it.
    ...(summary.source === undefined ? {} : { source: summary.source }),
  };
}

// Returns a hook diagnostic without throwing and omits unavailable file and line anchors.
// In the hook contract, an explicit invalidatesRun value of false means warning. An unset or true value means fatal.
function toHookDiagnostic(diagnostic: RunDiagnostic): HookDiagnostic {
  return {
    type: diagnostic.diagnosticType,
    severity: diagnostic.invalidatesRun === false ? "warning" : "fatal",
    message: diagnostic.message,
    ...(diagnostic.filePath === undefined ? {} : { file: diagnostic.filePath }),
    ...(diagnostic.line === undefined ? {} : { line: diagnostic.line }),
    ...(diagnostic.invalidatesRun === false ? { invalidatesRun: false as const } : {}),
  };
}

/**
 * Decide whether to block the edit using the same hook contract entries the agent sees.
 * Missing or non-array findings and diagnostics count as empty. The CLI uses exit code 2 for errors caught before calling this gate.
 *
 * @param renderedEnvelope - published hook envelope as JSON
 * @param gate - thresholds and options that determine which published entries block the edit
 * @returns 1 when a published entry reaches the gate and 0 otherwise
 * @throws SyntaxError - if the envelope is invalid JSON
 */
export function hookExitCode(renderedEnvelope: string, gate: HookExitGate): number {
  const payload = JSON.parse(renderedEnvelope) as { findings?: HookFinding[]; diagnostics?: HookDiagnostic[] };
  const diagnostics = Array.isArray(payload.diagnostics) ? payload.diagnostics : [];
  // When the diagnostic gate is enabled, any published diagnostic blocks the edit regardless of the finding thresholds.
  if (gate.shouldFailOnDiagnostics && diagnostics.length > 0) {
    return 1;
  }
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  return findings.some((finding) => reachesHookGate(finding, gate)) ? 1 : 0;
}

// True when one published finding reaches the gate the caller set, by baseline status or by severity and confidence.
// Severity and confidence are independent floors, so either can keep a finding from reaching the threshold.
// The gate contract treats failOn none as disabling only those floors, so enabled new-debt gating can still block.
function reachesHookGate(finding: HookFinding, gate: HookExitGate): boolean {
  // A new status can block regardless of either floor. A null status can block only through an enabled severity and confidence gate.
  if (gate.shouldFailOnNew && finding.baselineStatus === "new") {
    return true;
  }
  if (gate.failOn === "none") {
    return false;
  }
  const severity = SEVERITY_GATE_RANK[finding.severity] ?? 0;
  const confidence = CONFIDENCE_GATE_RANK[finding.confidence] ?? CONFIDENCE_GATE_RANK.high;
  return severity >= SEVERITY_GATE_RANK[gate.failOn] && confidence >= CONFIDENCE_GATE_RANK[gate.minConfidence];
}

// Analyzer identity block shared by the capability and report envelopes.
function analyzerInfo(): { name: "gruff-ts"; version: string } {
  return { name: "gruff-ts", version: VERSION };
}

/**
 * Build the findings to publish, using prior coverage to distinguish inherited issues from findings the hook can attribute to this edit.
 *
 * @param currentReport - full scan that supplies file and project candidates for re-admission
 * @param scopedReport - scoped scan that supplies the initial candidates
 * @param input - hook request that supplies changed-region mode and whether a baseline was named
 * @param baseIdentities - stable match-key counts from the diff base, or undefined to skip diff-base filtering
 * @param statuses - baseline classifications used to remove reviewed occurrences marked unchanged
 * @returns the findings kept after changed-region, diff-base, and baseline filtering
 */
function hookFindings(
  currentReport: AnalysisReport,
  scopedReport: AnalysisReport,
  input: HookReportInput,
  baseIdentities: Map<string, number> | undefined,
  statuses: HookBaselineStatuses,
): Finding[] {
  const hasChangedRegion = input.hasChangedRegion;
  // In changed-region mode, a whole-file issue needs a prior base before the hook can attribute it to the edit.
  // A named baseline or a replayed diff base lets the hook reconsider whole-file findings.
  const hasPriorBase = baseIdentities !== undefined || input.baselinePath !== undefined;
  const scopedFindings = scopedReport.findings.filter((finding) => !hasChangedRegion || scopeForFinding(finding) !== "file");
  const covered = baseCoveredOccurrences(currentReport, baseIdentities);
  const withNewFileAndProject = hasChangedRegion && hasPriorBase
    ? [...scopedFindings, ...newFileAndProjectFindings(currentReport, scopedFindings, covered)]
    : scopedFindings;
  const afterNewOnly = baseIdentities
    ? withNewFileAndProject.filter((finding) => !spendCoveredOccurrence(covered, finding))
    : withNewFileAndProject;
  // A finding marked unchanged has already been reviewed against the baseline, so it stays out of the published list.
  return afterNewOnly.filter((finding) => statuses.get(finding) !== "unchanged");
}

// Returns file and project findings in currentReport whose fingerprints are absent from scopedFindings and have no remaining base occurrence.
// Mutates covered, the remaining base counts by fingerprint, to spend one count per eligible match so that repeated occurrences compare correctly.
function newFileAndProjectFindings(currentReport: AnalysisReport, scopedFindings: Finding[], covered: Map<string, number>): Finding[] {
  const alreadyIncluded = new Set(scopedFindings.map((finding) => finding.fingerprint));
  return currentReport.findings.filter((finding) => {
    const scope = scopeForFinding(finding);
    if ((scope !== "file" && scope !== "project") || alreadyIncluded.has(finding.fingerprint)) {
      return false;
    }
    // A base that already held this occurrence says this edit did not introduce it, so it stays suppressed.
    return !spendCoveredOccurrence(covered, finding);
  });
}

// Returns counts of covered current findings by report fingerprint. Missing base counts yield an empty map.
// For each stable hook match key, spend at most its base count in line and column order to avoid covering extra matches.
function baseCoveredOccurrences(currentReport: AnalysisReport, baseCounts: Map<string, number> | undefined): Map<string, number> {
  const covered = new Map<string, number>();
  if (baseCounts === undefined) {
    return covered;
  }
  const remaining = new Map(baseCounts);
  const byLine = [...currentReport.findings].sort((left, right) => (left.line ?? 0) - (right.line ?? 0) || (left.column ?? 0) - (right.column ?? 0));
  for (const finding of byLine) {
    const key = hookMatchKey(finding);
    const count = remaining.get(key) ?? 0;
    // A key the base never held, or whose base occurrences are spent, leaves this occurrence new.
    if (count === 0) {
      continue;
    }
    remaining.set(key, count - 1);
    covered.set(finding.fingerprint, (covered.get(finding.fingerprint) ?? 0) + 1);
  }
  return covered;
}

// Mutates the caller's coverage map when the finding's fingerprint count is nonzero. Returns true after spending one occurrence.
// Returns false if the fingerprint is missing or its count is exhausted.
// The stable contract lets each covered occurrence hide one finding across file/project re-admission and the new-only filter.
function spendCoveredOccurrence(covered: Map<string, number>, finding: Finding): boolean {
  const count = covered.get(finding.fingerprint) ?? 0;
  if (count === 0) {
    return false;
  }
  covered.set(finding.fingerprint, count - 1);
  return true;
}

// Returns the stable suppressed.count total when hasChangedRegion is true, or zero for a full scan.
// Adds scopedReport's existing suppression tally, defaulting to zero, to its remaining file and project findings.
// Uses emittedFindings fingerprints to avoid counting published findings as suppressed.
function hookSuppressedCount(scopedReport: AnalysisReport, emittedFindings: Finding[], hasChangedRegion: boolean): number {
  if (!hasChangedRegion) {
    return 0;
  }
  const emittedFingerprints = new Set(emittedFindings.map((finding) => finding.fingerprint));
  const fileOrProjectAnchorResiduals = scopedReport.findings.filter((finding) => {
    const scope = scopeForFinding(finding);
    return (scope === "file" || scope === "project") && !emittedFingerprints.has(finding.fingerprint);
  }).length;
  return (scopedReport.suppressedCount ?? 0) + fileOrProjectAnchorResiduals;
}

// Returns a hook row for finding. The symbol ordinal is 0 without a stored ordinal. Missing remediation uses rule or generic advice.
// baselineStatus is the supplied review result or null when unclassified; absent symbols and stable identities are also null.
// Omits missing columns and both lines when the start line is absent. Otherwise uses the start line if the end line is missing or earlier.
function toHookFinding(finding: Finding, baselineStatus: string | null): HookFinding {
  const endLine = endLineFor(finding);
  return {
    ruleId: finding.ruleId,
    pillar: finding.pillar,
    severity: finding.severity,
    confidence: finding.confidence,
    scope: scopeForFinding(finding),
    file: finding.filePath,
    ...(finding.line === undefined ? {} : { line: finding.line }),
    ...(endLine === undefined ? {} : { endLine }),
    ...(finding.column === undefined ? {} : { column: finding.column }),
    symbol: finding.symbol ?? null,
    symbolOrdinal: symbolOrdinalOf(finding),
    message: finding.message,
    remediation: finding.remediation ?? DESCRIPTORS.get(finding.ruleId)?.remediation ?? "Review and address this finding.",
    metadata: hookMetadata(finding),
    stableIdentity: finding.baselineIdentity ?? null,
    baselineStatus,
    fingerprint: finding.fingerprint,
  };
}

// Returns the finding's span end for the stable hook contract, using its start when the reported end is absent or earlier than the start.
// Returns undefined when the finding has no start line, so the hook omits the span end.
function endLineFor(finding: Finding): number | undefined {
  if (finding.line === undefined) {
    return undefined;
  }
  return finding.endLine !== undefined && finding.endLine >= finding.line ? finding.endLine : finding.line;
}

// Returns the declaration ordinal the ratified identity hashed, so a consumer can recompute that identity.
// The identity contract uses 0 when the finding has no stored subject or its subject has no ordinal suffix.
function symbolOrdinalOf(finding: Finding): number {
  const trailing = finding.baselineSubject === undefined ? null : TRAILING_ORDINAL.exec(finding.baselineSubject);
  return trailing === null ? 0 : Number(trailing[1]);
}

// Classifies a finding as line/symbol/file/project scope; this choice drives changed-region
// attribution and the port-local hook match key.
// Stable contract: one finding always lands in one scope, so changed-region attribution is deterministic.
function scopeForFinding(finding: Finding): HookScope {
  if (PROJECT_SCOPE_RULE_IDS.has(finding.ruleId)) {
    return "project";
  }
  if (FILE_SCOPE_RULE_IDS.has(finding.ruleId)) {
    return "file";
  }
  if (finding.symbol || (finding.endLine !== undefined && finding.line !== undefined && finding.endLine > finding.line)) {
    return "symbol";
  }
  return "line";
}

// Returns the hook contract's threshold metadata for a supported rule with a numeric measurement and limit.
// Otherwise returns the finding's original metadata.
function hookMetadata(finding: Finding): Record<string, unknown> {
  const thresholdMetadata = thresholdMetadataFor(finding);
  // The hook contract keeps the limit band beside the measurement (FAMILY-CONTRACT.md section 12, The band key).
  if (thresholdMetadata && typeof finding.metadata.limitBand === "string") {
    return { ...thresholdMetadata, limitBand: finding.metadata.limitBand };
  }
  return thresholdMetadata ?? finding.metadata;
}

// Uses the finding's rule ID and metadata to return a stable hook measurement with its threshold, unit, and direction.
// Returns undefined when the rule has no measurement mapping or either numeric value is unavailable.
function thresholdMetadataFor(finding: Finding): Record<string, unknown> | undefined {
  const metadata = finding.metadata;
  switch (finding.ruleId) {
    case "complexity.cyclomatic":
      return metricMetadata(metadata.complexity, metadata.threshold, "points");
    case "design.deep-relative-import":
      return metricMetadata(metadata.parentSegments, metadata.maxParentSegments, "segments");
    case "design.large-module-concentration":
      return metricMetadata(metadata.sharePercent, metadata.maxSharePercent, "percent");
    case "size.file-length":
    case "size.function-length":
      return metricMetadata(metadata.lines, metadata.threshold, "lines");
    case "size.parameter-count":
      return metricMetadata(metadata.parameters, metadata.threshold, "parameters");
  }
  return undefined;
}

// Returns metadata containing measured as the observed value, threshold as its comparison limit, and unit as their label.
// The direction is above; returns undefined unless measured and threshold both have number type.
function metricMetadata(measured: unknown, threshold: unknown, unit: string): Record<string, unknown> | undefined {
  return typeof measured === "number" && typeof threshold === "number"
    ? { measured, threshold, unit, direction: "above" }
    : undefined;
}

/**
 * Build a stable key for matching findings against a base replay so edits above a finding do not make it look new.
 * The published stableIdentity is computed separately.
 *
 * @param finding - occurrence whose rule, path, and scope component identify it for replay matching
 * @returns the 16-character hexadecimal hook match key
 */
function hookMatchKey(finding: Finding): string {
  const scope = scopeForFinding(finding);
  return createHash("sha256")
    .update([finding.ruleId, finding.filePath, matchKeyComponent(finding, scope)].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

// Returns a stable match-key component from finding according to scope, so that occurrences can be matched across edits.
// File scope shares one component. Project scope uses a nonempty symbol when present and otherwise shares its scope token.
// Symbol and line scopes use a nonempty symbol when present. Otherwise they use the message and add the match column when present.
function matchKeyComponent(finding: Finding, scope: HookScope): string {
  if (scope === "file") {
    return scope;
  }
  if (scope === "project") {
    // Project matching ignores measured values.
    // The canonical member list in the design.circular-import symbol distinguishes cycles without relying on line numbers.
    return finding.symbol && finding.symbol.length > 0 ? `project:${finding.symbol}` : scope;
  }
  if (finding.symbol && finding.symbol.length > 0) {
    return `symbol:${finding.symbol}`;
  }
  // For occurrences without a symbol, differing messages distinguish matches of the same rule in a file.
  const messageComponent = `message:${finding.message}`;
  // Fully masked matches on one line can share a message, so the column distinguishes them without using the line number.
  // Without a column, the message is the whole component.
  return finding.column === undefined ? messageComponent : `${messageComponent}\0column:${finding.column}`;
}

// Returns stable match-key counts from the diff base. The runner uses the input's scan settings on paths drawn from the current report.
// Replay spawns Git, writes a temporary tree, and temporarily changes the process working directory.
// An absent diff base returns undefined and skips diff-base filtering. An empty map still lets the hook reconsider whole-file findings.
function hookDiffBaseIdentities(runAnalyse: HookAnalysisRunner, input: HookReportInput, currentReport: AnalysisReport): Map<string, number> | undefined {
  if (input.diffBase === undefined) {
    return undefined;
  }
  return keysFromDiffBase(runAnalyse, input.currentOptions, input.diffBase, currentReport);
}

/**
 * Replays the diff base so new-only filtering can compare stable hook keys by occurrence count.
 * Spawns Git and writes a temporary tree. Changes into it for analysis, then restores the working directory and removes the tree in finally.
 *
 * @param runAnalyse - runner that scans the materialized base files
 * @param options - current scan settings from which to build the replay options
 * @param diffBase - diff selector that identifies the revision or index to replay
 * @param currentReport - current findings that identify which file paths to replay
 * @returns counts by hook match key, empty if there is no replayable base, no eligible path or base file, or no base finding
 */
function keysFromDiffBase(
  runAnalyse: HookAnalysisRunner,
  options: AnalysisOptions,
  diffBase: string,
  currentReport: AnalysisReport,
): Map<string, number> {
  const ref = diffBaseRef(diffBase);
  if (ref === undefined) {
    return new Map();
  }
  const files = [...new Set(currentReport.findings.flatMap(findingBasePaths))];
  if (files.length === 0) {
    return new Map();
  }
  const tempRoot = mkdtempSync(join(tmpdir(), "gruff-ts-hook-base-"));
  const previous = cwd();
  try {
    const baseFiles = materializeBaseFiles(ref, files, tempRoot);
    if (baseFiles.length === 0) {
      return new Map();
    }
    chdir(tempRoot);
    const baseReport = runAnalyse(baseAnalysisOptions(options, baseFiles, previous));
    const counts = new Map<string, number>();
    for (const key of baseReport.findings.map(hookMatchKey)) {
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return counts;
  } finally {
    chdir(previous);
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

/**
 * Select replay paths so that the base scan can reconstruct the complete import cycle for stable matching.
 *
 * @param finding - current occurrence whose file and recorded member paths identify the replay inputs
 * @returns the finding's file path plus string paths in metadata.files, or just its file path when no members qualify
 */
function findingBasePaths(finding: Finding): string[] {
  const memberFiles = finding.metadata.files;
  if (!Array.isArray(memberFiles)) {
    return [finding.filePath];
  }
  return [finding.filePath, ...memberFiles.filter((file): file is string => typeof file === "string")];
}

// Returns the Git revision to replay for new-only filtering. The working-tree and staged selectors use HEAD, and explicit refs pass through.
// Unstaged diffs use the index via an empty revision. A stdin patch has no replayable base, so its selector returns undefined.
function diffBaseRef(diffBase: string): string | undefined {
  if (diffBase === "-") {
    return undefined;
  }
  if (diffBase === "unstaged") {
    return "";
  }
  return diffBase === "working-tree" || diffBase === "staged" ? "HEAD" : diffBase;
}

// Writes each file's blob at the base ref into the temp dir via git; a blob missing at the ref is a
// recover path so that file's findings count as new (filesystem writes).
function materializeBaseFiles(ref: string, files: string[], root: string): string[] {
  const materialized: string[] = [];
  for (const file of files) {
    try {
      const source = execFileSync("git", ["show", `${ref}:${file}`], { encoding: "utf8" });
      const target = join(root, file);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, source);
      materialized.push(file);
    } catch {
      // File is missing at the base ref, so every current finding in it is new.
    }
  }
  return materialized;
}

// Returns base-scan options from options, using paths as scan targets and disabling baseline and changed-region selection.
// Resolves config against originalRoot, or discovers its .gruff-ts.yaml when present unless options.shouldSkipConfig disables discovery.
function baseAnalysisOptions(options: AnalysisOptions, paths: string[], originalRoot: string): AnalysisOptions {
  return {
    ...withoutChangedRegion(options),
    paths,
    ...(options.config ? { config: absolutize(originalRoot, options.config) } : defaultConfigPathOption(originalRoot, options)),
  };
}

// Returns a config option for originalRoot/.gruff-ts.yaml when present unless options.shouldSkipConfig disables it.
// Returns an empty object otherwise, leaving the base scan without this config override.
function defaultConfigPathOption(originalRoot: string, options: AnalysisOptions): Partial<Pick<AnalysisOptions, "config">> {
  const defaultConfigPath = join(originalRoot, ".gruff-ts.yaml");
  return !options.shouldSkipConfig && existsSync(defaultConfigPath) ? { config: defaultConfigPath } : {};
}

// Returns a copy of options for a deterministic full base-ref scan, dropping changedRanges, diff, diffPatch and since.
// Drops the baseline path and generation request and sets shouldSkipBaseline so that default baseline lookup is disabled too.
function withoutChangedRegion(options: AnalysisOptions): AnalysisOptions {
  const { baseline: _baseline, changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, generateBaseline: _generateBaseline, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

// Returns a copy of the supplied hook findings in stable severity, file, line, and rule ID order.
// A finding without a line sorts as line 0.
function sortHookFindings(findings: HookFinding[]): HookFinding[] {
  return [...findings].sort(
    (left, right) =>
      SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
      left.file.localeCompare(right.file) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId),
  );
}
