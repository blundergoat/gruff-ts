// Builds the JSON response that a coding agent receives from `gruff-ts hook`.
//
// Compares the user's edit with a Git base or reviewed baseline when one is supplied.
// Uses published findings and diagnostics to decide whether the edit can proceed.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import { tmpdir } from "node:os";
import { applyBaseline, BASELINE_SCHEMA_VERSION } from "./baseline-file.ts";
import { defaultConfigPath } from "./config.ts";
import { absolutize, displayPath } from "./discovery.ts";
import { VERSION } from "./constants.ts";
import { BUILT_IN_PROFILES } from "./profiles.ts";
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
  isDiffExplicitRef?: boolean;
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
  // File-scoped parse/read diagnostics relevant to the analysed change, reported in-band. A parse diagnostic keeps
  // the default hook exit at 0 unless --fail-on-diagnostics turns it into 1; a missing or unreadable input exits 2.
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
type HookBaselineStatuses = Map<string, string>;

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

/**
 * Builds the `gruff.hook.v2` capability handshake so consumers can use its stable `supports` and `flags` fields before requesting analysis.
 *
 * @returns Pretty-printed JSON with a trailing newline advertising contract version, analyzer info, supported features, and CLI flags.
 */
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
 * Builds the hook response from the findings the integration can act on for this edit.
 *
 * Invariant: the response includes the selected findings and the audits the hook gate will use for this edit.
 * Side effects: replaying a Git base uses a temporary directory and briefly changes the working directory.
 *
 * @param runAnalyse - analysis runner used to obtain the report views and replay an available diff base
 * @param input - hook request. No diff base skips replay. No baseline skips filtering by reviewed findings.
 * @returns newline-terminated JSON with findings and run details. Null baseline statuses mean the user supplied no baseline.
 */
export function renderHookReport(runAnalyse: HookAnalysisRunner, input: HookReportInput): string {
  const views = hookAnalysisViews(runAnalyse, input);
  const { currentReport, scopedReport } = views;
  const statuses = hookBaselineStatuses(views, input.baselinePath);
  const baseIdentities = hookDiffBaseIdentities(runAnalyse, input, currentReport);
  const kept = hookFindings(currentReport, scopedReport, input, baseIdentities, statuses);
  const suppressedCount = hookSuppressedCount(scopedReport, kept, input.hasChangedRegion);
  // A finding with no matching status stays new when the user supplied a baseline. Otherwise it has no review status.
  const findings = kept.map((finding) => toHookFinding(finding, statuses.get(hookOccurrenceKey(finding)) ?? (input.baselinePath === undefined ? null : "new")));
  return JSON.stringify(hookReport(scopedReport, findings, suppressedCount, hookRun(scopedReport, input)), null, 2) + "\n";
}

/**
 * Collects full-scan and edit-scoped analysis views so hook filtering can compare both views.
 *
 * @param runAnalyse - Analysis runner or pre-bundled dual-view provider used to execute the scans.
 * @param input - Hook request containing full-scan options, scoped options, and whether a change selector is active.
 * @returns Current full-scan and scoped analysis reports; without a change selector, both views describe the full scan.
 */
function hookAnalysisViews(runAnalyse: HookAnalysisRunner, input: HookReportInput): HookAnalysisViews {
  // The CLI runner supplies both views from one scan so the user sees a consistent result.
  if (runAnalyse.hookViews) {
    return runAnalyse.hookViews(input.currentOptions, input.scopedOptions, input.hasChangedRegion);
  }
  const currentReport = runAnalyse(input.currentOptions);
  const scopedReport = input.hasChangedRegion ? runAnalyse(input.scopedOptions) : currentReport;
  return { currentReport, scopedReport };
}

/**
 * Applies the review file produced by `analyse --generate-baseline` before narrowing to the edit.
 * Counting reviews across the full scan keeps an unchanged occurrence elsewhere from hiding a new one in the edit.
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
  const findings = views.currentReport.findings;
  const application = applyBaseline(resolved, findings);
  // A matching occurrence keeps the outcome of the original review. An unclassified occurrence stays visible as new.
  findings.forEach((finding, index) => {
    statuses.set(hookOccurrenceKey(finding), application.statuses[index] ?? "new");
  });
  return statuses;
}

/**
 * Builds an occurrence lookup key for baseline matching.
 * Invariant: one occurrence keeps the same key in both views, while different columns distinguish multiple matches on one line.
 *
 * @param finding - Finding whose fingerprint and optional column identify the occurrence.
 * @returns Null-delimited key pairing the finding fingerprint with its column or an empty suffix when absent.
 */
function hookOccurrenceKey(finding: Finding): string {
  return `${finding.fingerprint}\0${finding.column ?? ""}`;
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

/**
 * Formats a configuration failure payload with the loader's message in both the fatal diagnostic and `config.error`, and `schemaOk` set to false.
 *
 * @param message - Configuration failure message recorded in the diagnostic and config error object.
 * @param remediation - Actionable fix guidance; defaults to general advice so callers without a specific fix can still tell the user what to try.
 * @returns Newline-terminated `gruff.hook.v2` JSON string for the fatal config error envelope.
 */
export function renderHookConfigError(message: string, remediation: string = CONFIG_ERROR_REMEDIATION): string {
  const report = fatalReport("config", message);
  report.config = { schemaOk: false, error: { message, remediation } };
  return JSON.stringify(report, null, 2) + "\n";
}

/**
 * Builds a fatal hook envelope so the caller has a payload to publish before exit 2.
 * The stable contract retains the required envelope fields, with no findings or analysed files.
 *
 * @param diagnosticType - Category assigned to the sole fatal diagnostic entry.
 * @param message - Failure description surfaced on the fatal diagnostic.
 * @returns Envelope containing one fatal diagnostic and empty findings, suppressions, and ignored paths.
 */
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

/**
 * Assembles the `gruff.hook.v2` envelope for a completed analysis, keeping findings in stable order.
 * The analysis report supplies diagnostics, the exclusion audit, and skipped paths.
 *
 * @param report - Completed scoped analysis report providing diagnostics, suppressions, and skipped paths.
 * @param findings - Visible hook findings to sort and include in the payload.
 * @param suppressedCount - Total count of suppressed findings for the run.
 * @param run - Run audit metadata describing mode, scope, paths, and baseline application.
 * @returns Completed hook envelope with `schemaOk: true` and sorted findings.
 */
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

/**
 * Builds the run audit so consumers can see what ran and whether a review baseline was applied.
 * Empty scoped paths report as `"."`; without a baseline, `applied` is false with null schema version and path.
 *
 * @param report - Analysis report supplying the project root and analysed-file count.
 * @param input - Hook request supplying selectors, scoped paths, and optional baseline path.
 * @returns Run audit detailing mode, scope, target paths, analysed-file count, and baseline metadata.
 */
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

/**
 * Names which region selector chose the work so a consumer can tell a targeted run from a whole-tree one.
 * Follows the exact precedence of `changedRegionScope` (`changedRanges`, `diffPatch`, `since`, `diff`) so mode never disagrees with scope.
 *
 * @param input - Hook request whose scoped options determine the active selection mode.
 * @returns `"changed-ranges"`, `"diff"`, `"since"`, or `"full"` in selector precedence order.
 */
function hookRunMode(input: HookReportInput): HookRun["mode"] {
  // Explicit ranges are the narrowest selector and win when more than one is given; presence decides, not truthiness.
  if (input.scopedOptions.changedRanges !== undefined) {
    return "changed-ranges";
  }
  // An explicit patch on stdin (even an empty one) takes precedence over Git refs, matching `changedRegionScope`.
  if (input.scopedOptions.diffPatch !== undefined) {
    return "diff";
  }
  if (input.scopedOptions.since) {
    return "since";
  }
  return input.scopedOptions.diff ? "diff" : "full";
}

/**
 * Projects a scan suppression summary into a hook audit row.
 * An empty path list yields an empty path, and a null symbol or undefined source is omitted.
 *
 * @param summary - Suppression summary entry emitted by the analysis run.
 * @returns Hook suppression row with a single path, optional symbol and source, reason, and count.
 */
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

/**
 * Projects a run diagnostic into the hook contract without throwing, omitting unavailable file and line anchors.
 * In the hook contract, an explicit `invalidatesRun` value of false means warning, while unset or true means fatal.
 *
 * @param diagnostic - Run diagnostic from the analysis report.
 * @returns Hook diagnostic with mapped severity, message, and optional file, line, and `invalidatesRun` fields.
 */
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
 * Missing or non-array lists count as empty so they add no gate entries.
 *
 * @param renderedEnvelope - published hook envelope as JSON
 * @param gate - thresholds and options that determine which published entries block the edit
 * @returns 2 for a missing or unreadable target, 1 when a published entry reaches the gate, or 0 when the edit can proceed
 * @throws SyntaxError - if the envelope is invalid JSON
 */
export function hookExitCode(renderedEnvelope: string, gate: HookExitGate): number {
  const payload = JSON.parse(renderedEnvelope) as { findings?: HookFinding[]; diagnostics?: HookDiagnostic[] };
  const diagnostics = Array.isArray(payload.diagnostics) ? payload.diagnostics : [];
  // An editor may request a file that was just deleted or that it cannot read. The hook cannot approve an edit it could not scan.
  // Parse errors stay in-band: the file was read, and FAMILY-CONTRACT.md reserves exit 2 for a run that did not happen.
  if (diagnostics.some((diagnostic) => diagnostic.type === "missing-path" || diagnostic.type === "read-error")) {
    return 2;
  }
  // When the diagnostic gate is enabled, any published diagnostic blocks the edit regardless of the finding thresholds.
  if (gate.shouldFailOnDiagnostics && diagnostics.length > 0) {
    return 1;
  }
  // When there are no published findings, only diagnostics can block the edit.
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  return findings.some((finding) => reachesHookGate(finding, gate)) ? 1 : 0;
}

/**
 * Decides whether a published finding blocks the edit under the user's review or severity settings.
 * Invariant: `--fail-on none` disables severity gating while leaving an explicitly requested review gate active.
 *
 * @param finding - Published hook finding evaluated against the gate.
 * @param gate - Configured severity, confidence, and new-only blocking thresholds.
 * @returns True if the finding triggers the review gate or meets both severity and confidence floors; otherwise false.
 */
function reachesHookGate(finding: HookFinding, gate: HookExitGate): boolean {
  // The review gate blocks unreviewed findings, including those that cannot be recorded. Null means the user supplied no baseline.
  if (gate.shouldFailOnNew && finding.baselineStatus !== null && finding.baselineStatus !== "unchanged") {
    return true;
  }
  // The user can turn off severity gating while still blocking findings that lack a review.
  if (gate.failOn === "none") {
    return false;
  }
  const severity = SEVERITY_GATE_RANK[finding.severity] ?? 0;
  const confidence = CONFIDENCE_GATE_RANK[finding.confidence] ?? CONFIDENCE_GATE_RANK.high;
  return severity >= SEVERITY_GATE_RANK[gate.failOn] && confidence >= CONFIDENCE_GATE_RANK[gate.minConfidence];
}

/**
 * Builds the analyzer identity block shared by the capability and report envelopes.
 *
 * @returns Object identifying the analyzer name (`"gruff-ts"`) and current `VERSION`.
 */
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
 * @param statuses - baseline classifications. An empty map leaves the published list unfiltered by review.
 * @returns the findings shown to the user after scope and review filtering. An empty list means none remain to publish.
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
  // Without replay counts, there is no earlier Git snapshot to match against the current edit.
  const afterNewOnly = baseIdentities
    ? withNewFileAndProject.filter((finding) => !spendCoveredOccurrence(covered, finding))
    : withNewFileAndProject;
  // A finding marked unchanged has already been reviewed against the baseline, so it stays out of the published list.
  return afterNewOnly.filter((finding) => statuses.get(hookOccurrenceKey(finding)) !== "unchanged");
}

/**
 * Selects file-scope and project-scope findings in `currentReport` absent from `scopedFindings` and not covered by the base.
 * Mutates `covered` to spend one count per eligible match so that repeated occurrences compare correctly.
 *
 * @param currentReport - Full-scan report providing candidate file and project findings.
 * @param scopedFindings - Findings already selected from the scoped scan, used to avoid duplicates.
 * @param covered - Remaining base-covered counts keyed by fingerprint; decremented in place for covered matches.
 * @returns Newly attributable file and project findings from the current full scan.
 */
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

/**
 * Tallies how many current findings are covered by the diff base per occurrence key (fingerprint plus column).
 * For each stable hook match key, spends at most its base count in line and column order so same-line findings keep separate credits.
 *
 * @param currentReport - Full-scan report whose findings are matched against the base counts.
 * @param baseCounts - Occurrence counts from the diff base keyed by stable hook match key, or undefined when unavailable.
 * @returns Counts of covered current findings keyed by occurrence key, or an empty map when base counts are missing.
 */
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
    const occurrenceKey = hookOccurrenceKey(finding);
    covered.set(occurrenceKey, (covered.get(occurrenceKey) ?? 0) + 1);
  }
  return covered;
}

/**
 * Consumes one covered occurrence for a finding's occurrence key, mutating the caller's coverage map when nonzero.
 * The stable contract lets each covered occurrence hide one finding across file/project re-admission and the new-only filter.
 *
 * @param covered - Remaining base-covered occurrence counts keyed by occurrence key; decremented on match.
 * @param finding - Finding whose occurrence key is checked against the remaining covered count.
 * @returns True after spending one occurrence when the count is nonzero; false if missing or exhausted.
 */
function spendCoveredOccurrence(covered: Map<string, number>, finding: Finding): boolean {
  const occurrenceKey = hookOccurrenceKey(finding);
  const count = covered.get(occurrenceKey) ?? 0;
  if (count === 0) {
    return false;
  }
  covered.set(occurrenceKey, count - 1);
  return true;
}

/**
 * Computes the stable `suppressed.count` total for changed-region runs by combining scoped suppressions with unemitted file/project findings.
 * Excludes findings re-admitted from outside the scoped view so a newly published file or project finding is never also counted as suppressed.
 *
 * @param scopedReport - Scoped analysis report supplying `suppressedCount` and candidate anchor findings.
 * @param emittedFindings - Findings actually published in the hook response.
 * @param hasChangedRegion - Whether the hook run narrowed analysis to a changed region.
 * @returns Net count of suppressed findings for the changed-region view, or zero for a full scan.
 */
function hookSuppressedCount(scopedReport: AnalysisReport, emittedFindings: Finding[], hasChangedRegion: boolean): number {
  if (!hasChangedRegion) {
    return 0;
  }
  const scopedKeys = new Set(scopedReport.findings.map(hookOccurrenceKey));
  const emittedKeys = new Set(emittedFindings.map(hookOccurrenceKey));
  // Findings absent from `scopedReport.findings` were counted in `scopedReport.suppressedCount`; subtract any that replay or baseline re-admitted.
  const reAdmittedFromSuppressed = emittedFindings.filter((finding) => !scopedKeys.has(hookOccurrenceKey(finding))).length;
  const fileOrProjectAnchorResiduals = scopedReport.findings.filter((finding) => {
    const scope = scopeForFinding(finding);
    return (scope === "file" || scope === "project") && !emittedKeys.has(hookOccurrenceKey(finding));
  }).length;
  return Math.max(0, (scopedReport.suppressedCount ?? 0) - reAdmittedFromSuppressed + fileOrProjectAnchorResiduals);
}

/**
 * Projects an internal finding into a `HookFinding` row for the hook contract, with normalized lines, remediation, metadata, and review status.
 * Contract: omits missing columns and lines when start line is absent; missing symbols, `stableIdentity`, and unclassified statuses are null.
 *
 * @param finding - Internal finding produced by the analyzer.
 * @param baselineStatus - Review status from an applied baseline, or null when no baseline was applied.
 * @returns Hook finding row with 0 ordinal when unstored and rule descriptor or generic fallback remediation.
 */
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

/**
 * Computes the finding's span end for the stable hook contract, falling back to start line when `endLine` is absent or earlier.
 *
 * @param finding - Finding whose optional `line` and `endLine` define the span.
 * @returns Validated end line number, or undefined when the finding has no start line so the hook omits the span end.
 */
function endLineFor(finding: Finding): number | undefined {
  if (finding.line === undefined) {
    return undefined;
  }
  return finding.endLine !== undefined && finding.endLine >= finding.line ? finding.endLine : finding.line;
}

/**
 * Extracts the declaration ordinal the ratified identity hashed so a consumer can recompute that identity.
 * The identity contract uses 0 when the finding has no stored subject or its subject has no ordinal suffix.
 *
 * @param finding - Finding whose optional `baselineSubject` may carry a trailing `#<ordinal>` suffix.
 * @returns Parsed 1-based declaration ordinal, or 0 when absent.
 */
function symbolOrdinalOf(finding: Finding): number {
  const trailing = finding.baselineSubject === undefined ? null : TRAILING_ORDINAL.exec(finding.baselineSubject);
  return trailing === null ? 0 : Number(trailing[1]);
}

/**
 * Classifies a finding as line, symbol, file, or project scope to drive changed-region attribution and the port-local hook match key.
 * Stable contract: one finding always lands in one scope, so changed-region attribution is deterministic.
 *
 * @param finding - Finding whose rule ID, symbol, and line span determine its scope.
 * @returns Deterministic scope classification (`"project"`, `"file"`, `"symbol"`, or `"line"`).
 */
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

/**
 * Returns the hook contract's threshold metadata for a supported rule with a numeric measurement and limit, preserving `limitBand` when present.
 * Otherwise returns the finding's original metadata.
 *
 * @param finding - Finding whose rule ID and metadata are inspected for threshold mapping.
 * @returns Normalized threshold metadata (including `limitBand` if string-valued), or the finding's original metadata otherwise.
 */
function hookMetadata(finding: Finding): Record<string, unknown> {
  const thresholdMetadata = thresholdMetadataFor(finding);
  // The hook contract keeps the limit band beside the measurement (FAMILY-CONTRACT.md section 12, The band key).
  if (thresholdMetadata && typeof finding.metadata.limitBand === "string") {
    return { ...thresholdMetadata, limitBand: finding.metadata.limitBand };
  }
  return thresholdMetadata ?? finding.metadata;
}

/**
 * Maps a finding's rule ID and metadata to a stable hook measurement with its threshold, unit, and direction.
 *
 * @param finding - Finding providing the rule ID and raw metric values.
 * @returns Normalized threshold metadata object, or undefined when the rule has no mapping or either numeric value is unavailable.
 */
function thresholdMetadataFor(finding: Finding): Record<string, unknown> | undefined {
  const metadata = finding.metadata;
  switch (finding.ruleId) {
    case "complexity.cyclomatic":
      return metricMetadata(metadata.complexity, metadata.threshold, "points");
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

/**
 * Builds a normalized threshold metadata record with direction `"above"` when both numeric values are present.
 *
 * @param measured - Observed numeric value from the finding's metadata.
 * @param threshold - Configured numeric comparison limit from the finding's metadata.
 * @param unit - Unit label describing both `measured` and `threshold` (such as `"lines"` or `"points"`).
 * @returns Metadata containing `measured`, `threshold`, `unit`, and `direction: "above"`, or undefined unless both inputs are numbers.
 */
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

/**
 * Builds a stable match-key component from `finding` according to `scope` so occurrences can be matched across edits.
 * File and unsymboled project scopes share a token; symboled entries use the symbol, and unsymboled line entries fall back to message and column.
 *
 * @param finding - Finding contributing symbol, message, and optional column.
 * @param scope - Classified hook scope determining which fields identify the occurrence.
 * @returns Scope-specific string component hashed into the hook match key.
 */
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

/**
 * Computes stable match-key counts from the diff base using scan settings from `input` on paths from `currentReport`.
 * Replay spawns Git, writes a temporary tree, and temporarily changes the process working directory.
 *
 * @param runAnalyse - Analysis runner used to scan materialized base files.
 * @param input - Hook request supplying `diffBase` and `currentOptions`.
 * @param currentReport - Current scan report supplying file paths to replay.
 * @returns Match-key count map (empty map still lets the hook reconsider whole-file findings), or undefined when `diffBase` is absent.
 */
function hookDiffBaseIdentities(runAnalyse: HookAnalysisRunner, input: HookReportInput, currentReport: AnalysisReport): Map<string, number> | undefined {
  if (input.diffBase === undefined) {
    return undefined;
  }
  return keysFromDiffBase(runAnalyse, input.currentOptions, input.diffBase, currentReport, input.isDiffExplicitRef === true);
}

/**
 * Replays the diff base so new-only filtering can compare stable hook keys by occurrence count.
 * Spawns Git and writes a temporary tree. Changes into it for analysis, then restores the working directory and removes the tree in finally.
 *
 * @param runAnalyse - runner that scans the materialized base files
 * @param options - current scan settings from which to build the replay options
 * @param diffBase - diff selector that identifies the revision or index to replay
 * @param currentReport - current findings that identify which file paths to replay
 * @param isExplicitRef - true when `diffBase` came from `--since` or `--diff-base` and names a Git revision directly
 * @returns Counts by hook match key, an empty map when no base files or findings exist, or undefined when the selector has no replayable Git base.
 */
function keysFromDiffBase(
  runAnalyse: HookAnalysisRunner,
  options: AnalysisOptions,
  diffBase: string,
  currentReport: AnalysisReport,
  isExplicitRef = false,
): Map<string, number> | undefined {
  const ref = diffBaseRef(diffBase, isExplicitRef);
  // A patch read from stdin has no Git revision to replay, so return undefined to avoid falsely enabling file-wide re-admission.
  if (ref === undefined) {
    return undefined;
  }
  const files = [...new Set(currentReport.findings.flatMap(findingBasePaths))];
  // With no current finding paths, the agent has nothing to compare with the base.
  if (files.length === 0) {
    return new Map();
  }
  const tempRoot = mkdtempSync(join(tmpdir(), "gruff-ts-hook-base-"));
  const previous = cwd();
  const projectRoot = currentReport.run.projectRoot;
  try {
    const baseFiles = materializeBaseFiles(ref, files, tempRoot, projectRoot);
    // New files may exist only in the current checkout, leaving no prior occurrences to spend.
    if (baseFiles.length === 0) {
      return new Map();
    }
    const baseOptions = baseAnalysisOptions(options, baseFiles, projectRoot);
    chdir(tempRoot);
    const baseReport = runAnalyse(baseOptions);
    const counts = new Map<string, number>();
    // Each prior match covers one occurrence so a duplicate introduced by this edit can still appear.
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

/**
 * Maps a diff-base selector to the Git revision to replay for new-only filtering.
 *
 * An explicit ref passes through as given, and a stdin patch (`"-"`) has no base to replay.
 * Otherwise working-tree and staged use `HEAD`, unstaged uses the index (`""`), and any other value passes through.
 *
 * @param diffBase - Diff selector supplied to the hook request.
 * @param isExplicitRef - true when `diffBase` came from `--since` or `--diff-base`, so even `staged` names a Git ref, not a mode
 * @returns Git revision string for `git show`, empty string for the index, or undefined for a stdin patch.
 */
function diffBaseRef(diffBase: string, isExplicitRef = false): string | undefined {
  // A pasted patch supplies changed lines but no Git snapshot for inherited findings.
  if (diffBase === "-") {
    return undefined;
  }
  // A ref from --since or --diff-base is replayed as given, even a branch named staged or unstaged.
  if (isExplicitRef) {
    return diffBase;
  }
  // For unstaged edits, the user's staged file contents are the comparison point.
  if (diffBase === "unstaged") {
    return "";
  }
  return diffBase === "working-tree" || diffBase === "staged" ? "HEAD" : diffBase;
}

/**
 * Recreates the selected files from Git so the hook can compare what the user had before the edit.
 * Side effects: spawns `git show` and writes available files into the temporary comparison directory.
 *
 * @param ref - Git revision or empty string for the index from which to read prior file contents.
 * @param files - Relative file paths to materialize from the base snapshot.
 * @param root - Temporary comparison directory receiving the materialized files.
 * @param projectRoot - Repository root used as the working directory for `git show`.
 * @returns Relative paths of files that existed in the base snapshot and were written to `root`.
 */
function materializeBaseFiles(ref: string, files: string[], root: string, projectRoot: string): string[] {
  const materialized: string[] = [];
  // Replay the prior versions of files associated with current findings, including related import-cycle files.
  for (const file of files) {
    try {
      const source = execFileSync("git", ["show", "--end-of-options", `${ref}:./${file}`], { cwd: projectRoot, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
      const target = join(root, file);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, source);
      materialized.push(file);
    } catch {
      // For example, a file created in this edit does not exist at HEAD, so there is no earlier match to apply.
    }
  }
  return materialized;
}

/**
 * Derives base-scan options from `options`, targeting `paths` while disabling baseline and changed-region selection.
 * Resolves explicit config and non-built-in profile paths before `chdir(tempRoot)` so replay loads the same rules.
 *
 * @param options - Original full-scan analysis options.
 * @param paths - Materialized base file paths to analyse.
 * @param originalRoot - Original project root used to locate a default config file or resolve a relative profile path.
 * @returns Analysis options configured for a deterministic full scan of the materialized base files.
 */
function baseAnalysisOptions(options: AnalysisOptions, paths: string[], originalRoot: string): AnalysisOptions {
  // Resolve settings from the launch directory before entering the temporary directory. With no selected config, use defaults.
  const config = options.config ? absolutize(cwd(), options.config) : options.shouldSkipConfig ? undefined : defaultConfigPath(originalRoot);
  const profile = options.profile !== undefined && !BUILT_IN_PROFILES.has(options.profile) && !BUILT_IN_PROFILES.has(`gruff.${options.profile}`)
    ? absolutize(cwd(), options.profile)
    : options.profile;
  return {
    ...withoutChangedRegion(options),
    paths,
    ...(config === undefined ? {} : { config }),
    ...(profile === undefined ? {} : { profile }),
  };
}

/**
 * Copies `options` for a deterministic full base-ref scan, dropping changed-region selectors and baseline flags.
 * Sets `shouldSkipBaseline` to true so default baseline lookup is disabled too.
 *
 * @param options - Analysis options from which `changedRanges`, `diff`, `diffPatch`, `since`, `baseline`, and `generateBaseline` are stripped.
 * @returns Cloned options object configured to run a full scan without baseline lookup.
 */
function withoutChangedRegion(options: AnalysisOptions): AnalysisOptions {
  const { baseline: _baseline, changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, generateBaseline: _generateBaseline, isDiffExplicitRef: _isDiffExplicitRef, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

/**
 * Sorts a copy of the supplied hook findings in stable severity, file, line, and rule ID order.
 *
 * @param findings - Hook findings to order; a finding without a line sorts as line 0.
 * @returns New array of hook findings ordered deterministically.
 */
function sortHookFindings(findings: HookFinding[]): HookFinding[] {
  return [...findings].sort(
    (left, right) =>
      SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
      left.file.localeCompare(right.file) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId),
  );
}
