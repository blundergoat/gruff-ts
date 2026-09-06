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

// Emits the gruff.hook.v2 capability handshake so a consumer can resolve flag names before a real
// request; the advertised supports/flags object is the stable gruff.hook.v2 contract.
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

// Runs the analysis and projects it into the gruff.hook.v2 envelope: the run audit, scoped findings,
// suppressed count, the section 13a exclusion audit, ignored paths, and a schema-ok config block.
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

// Selects the optimized hook view when available, otherwise falls back to one or two analyse calls.
function hookAnalysisViews(runAnalyse: HookAnalysisRunner, input: HookReportInput): HookAnalysisViews {
  if (runAnalyse.hookViews) {
    return runAnalyse.hookViews(input.currentOptions, input.scopedOptions, input.hasChangedRegion);
  }
  const currentReport = runAnalyse(input.currentOptions);
  const scopedReport = input.hasChangedRegion ? runAnalyse(input.scopedOptions) : currentReport;
  return { currentReport, scopedReport };
}

/*
 * Classifies this run's findings against the baseline the caller named, so each one can report what the
 * baseline made of it and a reviewed occurrence stays hidden.
 *
 * The hook reads the same `gruff.baseline.v3` file `analyse --generate-baseline` writes, so one review carries
 * across both surfaces; the published view is classified last, because that is the set the agent acts on.
 * Throws when the file is missing, malformed, in the 0.5 schema, or written by another port, so a baseline this
 * port cannot read never suppresses a finding under rules nobody ratified.
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

/*
 * Emits a gruff.hook.v2 envelope for a run that could not happen, so the consumer always receives JSON with a
 * fatal diagnostic instead of a crash and an empty stdout.
 *
 * Every field the contract requires is present and empty, so one shape parses whether the run succeeded or not
 * and the reason is read from the diagnostic rather than scraped from stderr.
 *
 * It reports the failure and never throws: a consumer handed no JSON at all has nothing to act on, and the caller
 * exits 2 after writing what this returns.
 */
export function renderHookFatal(diagnosticType: string, message: string): string {
  return JSON.stringify(fatalReport(diagnosticType, message), null, 2) + "\n";
}

// Emits the fatal envelope for a configuration the loader refuses, which also reports the schema as not ok.
// `remediation` defaults to the general advice, so a failure with no specific fix still tells the user what to try.
export function renderHookConfigError(message: string, remediation: string = CONFIG_ERROR_REMEDIATION): string {
  const report = fatalReport("config", message);
  report.config = { schemaOk: false, error: { message, remediation } };
  return JSON.stringify(report, null, 2) + "\n";
}

// Builds the empty envelope a fatal run publishes, carrying one fatal diagnostic and nothing else.
// It reports the failure rather than throwing it, so the caller always has a payload to write before exiting 2.
// Stable contract: every required key is present and empty, so one shape parses whether the run happened or not.
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

// Assembles the gruff.hook.v2 envelope (run audit, sorted findings, diagnostics, suppressed count,
// exclusion audit, ignored paths, config) as the stable gruff.hook.v2 output contract.
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

// Describes what this run was asked to do and which baseline classified it, which is the audit block.
// Stable contract: `baseline.applied` is true exactly when the caller named a baseline, so a consumer can trust
// that a false there means no review hid anything.
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
  // Explicit ranges are the narrowest selector and win when more than one is given.
  if (input.scopedOptions.changedRanges) {
    return "changed-ranges";
  }
  if (input.scopedOptions.diff || input.scopedOptions.diffPatch) {
    return "diff";
  }
  return input.scopedOptions.since ? "since" : "full";
}

// Projects one configured sensitive exclusion into its section 13a audit row, counted across the whole scan.
function toHookSuppression(summary: SuppressionSummary): HookSuppression {
  return {
    rule: summary.rule,
    // Section 13a gives each entry exactly one path; the native audit carries it in a list shape.
    path: summary.paths[0] ?? "",
    ...(summary.symbol === null ? {} : { symbol: summary.symbol }),
    reason: summary.reason,
    suppressed: summary.suppressed,
  };
}

// Projects one run diagnostic into the hook contract's shape, saying what it means for the run rather than
// leaving a consumer to infer that from the type; never throws - absent anchors are omitted.
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

/*
 * Decides what the hook tells the calling agent, from the findings it actually published.
 *
 * What blocks an edit is exactly what the agent was shown: a finding the changed-region filter or the baseline
 * removed is not in the payload and does not block. Returns 0 when nothing reached the gate and 1 when
 * something did; a run that could not happen at all exits 2 before this is ever called.
 *
 * Stable contract: the verdict is read back from the published payload, so what an agent sees and what blocks it
 * can never drift apart.
 */
export function hookExitCode(renderedEnvelope: string, gate: HookExitGate): number {
  const payload = JSON.parse(renderedEnvelope) as { findings?: HookFinding[]; diagnostics?: HookDiagnostic[] };
  const diagnostics = Array.isArray(payload.diagnostics) ? payload.diagnostics : [];
  // A consumer may ask for any caveat to stop the edit, which is the only way a warning becomes blocking.
  if (gate.shouldFailOnDiagnostics && diagnostics.length > 0) {
    return 1;
  }
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  return findings.some((finding) => reachesHookGate(finding, gate)) ? 1 : 0;
}

// True when one published finding reaches the gate the caller set, by baseline status or by severity and confidence.
// Stable contract: severity and confidence are independent floors, so either one alone can keep a finding away.
function reachesHookGate(finding: HookFinding, gate: HookExitGate): boolean {
  // A run asked to block on new debt blocks on it regardless of how severe the new finding is.
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

// Builds the hook finding list: changed-region scoping drops inherited file findings, new-only filtering
// re-admits file/project findings absent from the base identities, and a baseline hides what it reviewed.
// Invariant: suppressed.count arithmetic must stay exact across every filtering stage.
function hookFindings(
  currentReport: AnalysisReport,
  scopedReport: AnalysisReport,
  input: HookReportInput,
  baseIdentities: Set<string> | undefined,
  statuses: HookBaselineStatuses,
): Finding[] {
  const hasChangedRegion = input.hasChangedRegion;
  // Without a prior base the hook cannot attribute a whole-file issue to this edit, so it stays out of the way.
  // An applied baseline is a prior base as much as a diff ref is: it already knows what the file used to carry.
  const hasPriorBase = baseIdentities !== undefined || input.baselinePath !== undefined;
  const scopedFindings = scopedReport.findings.filter((finding) => !hasChangedRegion || scopeForFinding(finding) !== "file");
  const withNewFileAndProject = hasChangedRegion && hasPriorBase
    ? [...scopedFindings, ...newFileAndProjectFindings(currentReport, scopedFindings, baseIdentities)]
    : scopedFindings;
  const afterNewOnly = baseIdentities
    ? withNewFileAndProject.filter((finding) => !baseIdentities.has(hookMatchKey(finding)))
    : withNewFileAndProject;
  // An occurrence the user already reviewed is debt, not this edit's doing, so it stays out of the agent's way.
  return afterNewOnly.filter((finding) => statuses.get(finding) !== "unchanged");
}

// Collects file- and project-scope findings that are new since the base, excluding any already
// emitted, deduped by fingerprint.
function newFileAndProjectFindings(currentReport: AnalysisReport, scopedFindings: Finding[], baseIdentities: Set<string> | undefined): Finding[] {
  const alreadyIncluded = new Set(scopedFindings.map((finding) => finding.fingerprint));
  return currentReport.findings.filter((finding) => {
    const scope = scopeForFinding(finding);
    // A base that already knew about the finding says this edit did not introduce it, so it stays suppressed.
    const knownAtBase = baseIdentities !== undefined && baseIdentities.has(hookMatchKey(finding));
    return (scope === "file" || scope === "project") && !knownAtBase && !alreadyIncluded.has(finding.fingerprint);
  });
}

// Counts the file/project findings the hook drops under changed-region attribution, excluding any
// re-emitted as new, so the stable suppressed.count contract is never double-counted.
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

// Projects an analyser Finding into the hook shape, attaching scope, remediation, the ratified identity and the
// ordinal that lets a consumer recompute it, plus what a baseline made of it.
// Stable contract: `stableIdentity` carries the one ratified family identity and `fingerprint` the port-local key,
// so a consumer never reads two schemes under one field name.
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

// Returns the span end every v2 finding carries, repeating the start line when the rule reported no span, because
// a consumer locating a finding cannot treat an absent end as a single line by guessing.
// Stable contract: the end is never below the start, so a span is always a range a reader can open.
function endLineFor(finding: Finding): number | undefined {
  if (finding.line === undefined) {
    return undefined;
  }
  return finding.endLine !== undefined && finding.endLine >= finding.line ? finding.endLine : finding.line;
}

// Returns the declaration ordinal the ratified identity hashed, so a consumer can recompute that identity.
// A finding naming no symbol reports 0, which is what the identity contract says a symbol-less subject carries.
// Reads the finding's stored subject only; it mutates nothing and touches no filesystem, process, or network state.
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

// Returns normalized threshold metadata when the rule has one, else the finding's own metadata,
// keeping the contract's metadata shape stable.
function hookMetadata(finding: Finding): Record<string, unknown> {
  const thresholdMetadata = thresholdMetadataFor(finding);
  return thresholdMetadata ?? finding.metadata;
}

// Maps known threshold rules to a measured/threshold/unit triple so the hook exposes a stable,
// machine-readable measurement contract.
function thresholdMetadataFor(finding: Finding): Record<string, unknown> | undefined {
  const metadata = finding.metadata;
  switch (finding.ruleId) {
    case "complexity.cognitive":
    case "complexity.cyclomatic":
      return metricMetadata(metadata.complexity, metadata.threshold, "points");
    case "design.deep-relative-import":
      return metricMetadata(metadata.parentSegments, metadata.maxParentSegments, "segments");
    case "design.large-module-concentration":
      return metricMetadata(metadata.sharePercent, metadata.maxSharePercent, "percent");
    case "sensitive-data.hardcoded-env-value":
    case "sensitive-data.high-entropy-string":
      return metricMetadata(metadata.length, metadata.threshold, "characters");
    case "size.file-length":
    case "size.function-length":
      return metricMetadata(metadata.lines, metadata.threshold, "lines");
    case "size.parameter-count":
      return metricMetadata(metadata.parameters, metadata.threshold, "parameters");
  }
  return undefined;
}

// Builds the normalized measurement object, or undefined when the measured/threshold pair is not
// numeric.
function metricMetadata(measured: unknown, threshold: unknown, unit: string): Record<string, unknown> | undefined {
  return typeof measured === "number" && typeof threshold === "number"
    ? { measured, threshold, unit, direction: "above" }
    : undefined;
}

/*
 * Hashes (ruleId, filePath, scope component) into the port-local key the hook matches a base ref on.
 *
 * It is line-insensitive so an edit above a finding does not make it look new, and it is deliberately not the
 * published identity: `stableIdentity` carries the one ratified family identity and nothing else.
 *
 * Stable contract: the same finding always hashes to the same key, so a base replay and this run compare like for like.
 */
function hookMatchKey(finding: Finding): string {
  const scope = scopeForFinding(finding);
  return createHash("sha256")
    .update([finding.ruleId, finding.filePath, matchKeyComponent(finding, scope)].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

// Derives the per-occurrence component of the match key: scope token, symbol, or message plus match column.
// Stable contract: two occurrences of one rule in one file get different components, so accepting one never hides the other.
function matchKeyComponent(finding: Finding, scope: HookScope): string {
  if (scope === "file") {
    return scope;
  }
  if (scope === "project") {
    // Project rules are value-insensitive on their measurement, but component-level findings still
    // need a stable occurrence key. design.circular-import carries the canonical sorted SCC member
    // list in `symbol`; folding it in keeps independent components distinct without line sensitivity.
    return finding.symbol && finding.symbol.length > 0 ? `project:${finding.symbol}` : scope;
  }
  if (finding.symbol && finding.symbol.length > 0) {
    return `symbol:${finding.symbol}`;
  }
  // Symbol-less line findings (e.g. each hardcoded secret) key on the message so several same-rule
  // findings in one file get distinct keys. A value-insensitive `metric:${scope}` token collapsed
  // them all, letting one accepted finding hide later new ones in the same file. file scope above
  // stays fully value-insensitive; project scope folds in a canonical symbol when present.
  const messageComponent = `message:${finding.message}`;
  // The redacted preview alone stopped separating occurrences once short secrets became fully
  // masked: two 20-character keys on one line produce the same preview, so the same message. The
  // match column separates them and names no line, so an edit above the finding still keeps the
  // key stable. Scanners that report a whole line supply no column and keep the older key.
  return finding.column === undefined ? messageComponent : `${messageComponent}\0column:${finding.column}`;
}

// Builds the base key set a diff or since ref contributes to new-only filtering; undefined when neither
// is requested, because an empty set and "no base at all" mean different things to the filter.
// Stable contract: undefined means no base was replayed, so the filter admits everything rather than suppressing blindly.
function hookDiffBaseIdentities(runAnalyse: HookAnalysisRunner, input: HookReportInput, currentReport: AnalysisReport): Set<string> | undefined {
  if (input.diffBase === undefined) {
    return undefined;
  }
  return keysFromDiffBase(runAnalyse, input.currentOptions, input.diffBase, currentReport);
}

// Replays the diff base ref and returns its findings' port-local hook keys for new-only filtering.
// Writes a temp tree, spawns git to materialize base files, and must clean both up afterward.
function keysFromDiffBase(
  runAnalyse: HookAnalysisRunner,
  options: AnalysisOptions,
  diffBase: string,
  currentReport: AnalysisReport,
): Set<string> {
  const ref = diffBaseRef(diffBase);
  if (ref === undefined) {
    return new Set();
  }
  const files = [...new Set(currentReport.findings.flatMap(findingBasePaths))];
  if (files.length === 0) {
    return new Set();
  }
  const tempRoot = mkdtempSync(join(tmpdir(), "gruff-ts-hook-base-"));
  const previous = cwd();
  try {
    const baseFiles = materializeBaseFiles(ref, files, tempRoot);
    if (baseFiles.length === 0) {
      return new Set();
    }
    chdir(tempRoot);
    const baseReport = runAnalyse(baseAnalysisOptions(options, baseFiles, previous));
    return new Set(baseReport.findings.map(hookMatchKey));
  } finally {
    chdir(previous);
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

/*
 * A finding's base context is its anchor plus any project-relationship members from
 * `metadata.files`. Contract invariant: without every SCC member at the base ref, the replay
 * cannot reconstruct the cycle identity and a pre-existing cycle would be reported as new.
 */
function findingBasePaths(finding: Finding): string[] {
  const memberFiles = finding.metadata.files;
  if (!Array.isArray(memberFiles)) {
    return [finding.filePath];
  }
  return [finding.filePath, ...memberFiles.filter((file): file is string => typeof file === "string")];
}

// Resolves a diff-base selector to the git rev whose blobs are the new-only base. "unstaged" diffs
// the worktree against the index, so its base is the index ("" rev -> `git show :path`); "-" (stdin
// patch) has no materializable base. Returns undefined only when no base can be replayed.
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

// Builds the analysis options for the base-ref scan: drops changed-region flags and resolves the
// config path against the original root.
function baseAnalysisOptions(options: AnalysisOptions, paths: string[], originalRoot: string): AnalysisOptions {
  return {
    ...withoutChangedRegion(options),
    paths,
    ...(options.config ? { config: absolutize(originalRoot, options.config) } : defaultConfigPathOption(originalRoot, options)),
  };
}

// Falls back to the project's default .gruff-ts.yaml for the base scan when one exists and config is
// not skipped.
function defaultConfigPathOption(originalRoot: string, options: AnalysisOptions): Partial<Pick<AnalysisOptions, "config">> {
  const defaultConfigPath = join(originalRoot, ".gruff-ts.yaml");
  return !options.shouldSkipConfig && existsSync(defaultConfigPath) ? { config: defaultConfigPath } : {};
}

// Strips every changed-region and baseline flag so the base-ref scan runs as a plain full scan,
// deterministic regardless of the original changed-region request.
function withoutChangedRegion(options: AnalysisOptions): AnalysisOptions {
  const { baseline: _baseline, changedRanges: _changedRanges, diff: _diff, diffPatch: _diffPatch, generateBaseline: _generateBaseline, since: _since, ...rest } = options;
  return { ...rest, shouldSkipBaseline: true };
}

// Orders findings by severity, then file, line, and rule id, giving the contract a deterministic,
// stable finding order.
function sortHookFindings(findings: HookFinding[]): HookFinding[] {
  return [...findings].sort(
    (left, right) =>
      SEVERITY_RANK[left.severity] - SEVERITY_RANK[right.severity] ||
      left.file.localeCompare(right.file) ||
      (left.line ?? 0) - (right.line ?? 0) ||
      left.ruleId.localeCompare(right.ruleId),
  );
}
