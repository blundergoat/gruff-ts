// gruff.hook.v1 adapter: owns the agent-hook JSON shape without changing gruff.analysis.v2.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { chdir, cwd } from "node:process";
import { tmpdir } from "node:os";
import { absolutize } from "./discovery.ts";
import { VERSION } from "./constants.ts";
import { ruleDescriptors } from "./rules.ts";
import type { AnalysisOptions, AnalysisReport, Finding, Severity, SkippedPath } from "./types.ts";

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

// The gruff.hook.v1 envelope written to stdout; field names are the cross-analyzer contract.
interface HookReport {
  contractVersion: "gruff.hook.v1";
  analyzer: { name: "gruff-ts"; version: string };
  findings: HookFinding[];
  suppressed: { count: number };
  ignored: { paths: SkippedPath[] };
  config: { schemaOk: boolean; error: string | null };
}

// A finding projected into the hook contract, with enum scope and non-null remediation, keyed for
// new-only tracking by the stable identity and fingerprint.
interface HookFinding {
  ruleId: string;
  pillar: string;
  severity: Severity;
  scope: HookScope;
  file: string;
  line?: number;
  endLine?: number;
  symbol: string | null;
  message: string;
  remediation: string;
  metadata: Record<string, unknown>;
  stableIdentity: string;
  fingerprint: string;
}

// A gruff.baseline.v1 entry as read for new-only comparison; every field is optional because older
// baselines predate stableIdentity.
interface BaselineEntry {
  stableIdentity?: string;
  ruleId?: string;
  filePath?: string;
  symbol?: string;
  message?: string;
}

const HOOK_CONTRACT_VERSION = "gruff.hook.v1";
const FILE_SCOPE_RULE_IDS = new Set(["design.large-module-concentration", "docs.missing-file-overview", "size.file-length"]);
const PROJECT_SCOPE_RULE_IDS = new Set(["design.circular-import"]);
const SEVERITY_RANK: Record<Severity, number> = { error: 0, warning: 1, advisory: 2 };
const DESCRIPTORS = new Map(ruleDescriptors().map((descriptor) => [descriptor.ruleId, descriptor]));

// Emits the gruff.hook.v1 capability handshake so a consumer can resolve flag names before a real
// request; the advertised supports/flags object is the stable gruff.hook.v1 contract.
export function renderHookCapabilities(): string {
  return JSON.stringify({
    contractVersion: HOOK_CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    supports: {
      changedRanges: true,
      diff: true,
      baseline: true,
      scopeField: true,
      metadata: true,
      stableIdentity: true,
      ignoreReport: true,
      newOnly: true,
    },
    flags: { changedRanges: "--changed-ranges", diff: "--diff", baseline: "--baseline" },
    flagOrder: "any" satisfies FlagOrder,
  }, null, 2) + "\n";
}

// Runs the analysis and projects it into the gruff.hook.v1 envelope: scoped findings, suppressed
// count, ignored paths, and a schema-ok config block.
export function renderHookReport(runAnalyse: HookAnalysisRunner, input: HookReportInput): string {
  const { currentReport, scopedReport } = hookAnalysisViews(runAnalyse, input);
  const baseIdentities = hookBaseIdentities(runAnalyse, input, currentReport);
  const findings = hookFindings(currentReport, scopedReport, input.hasChangedRegion, baseIdentities);
  const suppressedCount = hookSuppressedCount(scopedReport, findings, input.hasChangedRegion);
  return JSON.stringify(hookReport(scopedReport, findings, suppressedCount, true, null), null, 2) + "\n";
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

// Emits a gruff.hook.v1 envelope for an operational failure (config rejected, bad baseline, git
// error) so the consumer always receives JSON with config.error set instead of a crash.
export function renderHookConfigError(message: string, remediation: string): string {
  const error = `${message}\nSuggested fix: ${remediation}`;
  return JSON.stringify(hookReport(undefined, [], 0, false, error), null, 2) + "\n";
}

// Assembles the gruff.hook.v1 envelope (sorted findings, suppressed count, ignored paths, config)
// as the stable gruff.hook.v1 output contract.
function hookReport(report: AnalysisReport | undefined, findings: HookFinding[], suppressedCount: number, isSchemaOk: boolean, error: string | null): HookReport {
  return {
    contractVersion: HOOK_CONTRACT_VERSION,
    analyzer: analyzerInfo(),
    findings: sortHookFindings(findings),
    suppressed: { count: suppressedCount },
    ignored: { paths: report?.paths.skipped ?? [] },
    config: { schemaOk: isSchemaOk, error },
  };
}

// Analyzer identity block shared by the capability and report envelopes.
function analyzerInfo(): { name: "gruff-ts"; version: string } {
  return { name: "gruff-ts", version: VERSION };
}

function hookFindings(
  currentReport: AnalysisReport,
  scopedReport: AnalysisReport,
  hasChangedRegion: boolean,
  baseIdentities: Set<string> | undefined,
): HookFinding[] {
  const scopedFindings = scopedReport.findings
    .map(toHookFinding)
    .filter((finding) => !hasChangedRegion || finding.scope !== "file");
  const withNewFileAndProject = hasChangedRegion && baseIdentities
    ? [...scopedFindings, ...newFileAndProjectFindings(currentReport, scopedFindings, baseIdentities)]
    : scopedFindings;
  return baseIdentities ? withNewFileAndProject.filter((finding) => !baseIdentities.has(finding.stableIdentity)) : withNewFileAndProject;
}

// Collects file- and project-scope findings that are new since the base, excluding any already
// emitted, deduped by fingerprint.
function newFileAndProjectFindings(currentReport: AnalysisReport, scopedFindings: HookFinding[], baseIdentities: Set<string>): HookFinding[] {
  const alreadyIncluded = new Set(scopedFindings.map((finding) => finding.fingerprint));
  return currentReport.findings
    .map(toHookFinding)
    .filter((finding) => (finding.scope === "file" || finding.scope === "project") && !baseIdentities.has(finding.stableIdentity) && !alreadyIncluded.has(finding.fingerprint));
}

// Counts the file/project findings the hook drops under changed-region attribution, excluding any
// re-emitted as new, so the stable suppressed.count contract is never double-counted.
function hookSuppressedCount(scopedReport: AnalysisReport, emittedFindings: HookFinding[], hasChangedRegion: boolean): number {
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

// Projects an analyser Finding into the hook shape, attaching scope, remediation, and the stable
// identity plus fingerprint.
function toHookFinding(finding: Finding): HookFinding {
  const scope = scopeForFinding(finding);
  return {
    ruleId: finding.ruleId,
    pillar: finding.pillar,
    severity: finding.severity,
    scope,
    file: finding.filePath,
    ...(finding.line === undefined ? {} : { line: finding.line }),
    ...(finding.endLine === undefined ? {} : { endLine: finding.endLine }),
    symbol: finding.symbol ?? null,
    message: finding.message,
    remediation: finding.remediation ?? DESCRIPTORS.get(finding.ruleId)?.remediation ?? "Review and address this finding.",
    metadata: hookMetadata(finding),
    stableIdentity: hookStableIdentity(finding, scope),
    fingerprint: finding.fingerprint,
  };
}

// Classifies a finding as line/symbol/file/project scope; this choice drives changed-region
// attribution and the stable hook identity.
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

// Hashes (ruleId, filePath, scope component) into the 16-hex hook identity; line-insensitive so it
// stays the stable cross-edit key for new-only filtering.
function hookStableIdentity(finding: Finding, scope: HookScope): string {
  const component = stableIdentityComponent(finding, scope);
  return createHash("sha256")
    .update([finding.ruleId, finding.filePath, component].join("\0"))
    .digest("hex")
    .slice(0, 16);
}

// Derives the per-occurrence component of the stable hook identity: scope token, symbol, or message.
function stableIdentityComponent(finding: { message: string; ruleId: string; symbol?: string }, scope: HookScope): string {
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
  // findings in one file get distinct identities. A value-insensitive `metric:${scope}` token
  // collapsed them all, letting one baselined finding suppress later new ones in the same file. The
  // message carries the per-occurrence discriminator (redacted preview) and no line number, so it
  // stays stable across surrounding edits. file scope above stays fully value-insensitive; project
  // scope folds in a canonical symbol when one is present.
  return `message:${finding.message}`;
}

// Builds the base identity set (from a baseline file and/or a diff base) that new-only filtering
// compares against by stable hook identity; undefined when neither source is requested.
function hookBaseIdentities(runAnalyse: HookAnalysisRunner, input: HookReportInput, currentReport: AnalysisReport): Set<string> | undefined {
  const identities = new Set<string>();
  if (input.baselinePath) {
    for (const identity of stableIdentitiesFromBaseline(input.baselinePath)) {
      identities.add(identity);
    }
  }
  if (input.diffBase) {
    for (const identity of stableIdentitiesFromDiffBase(runAnalyse, input.currentOptions, input.diffBase, currentReport)) {
      identities.add(identity);
    }
  }
  return identities.size > 0 || input.baselinePath || input.diffBase ? identities : undefined;
}

// Reads stable identities from a gruff.baseline.v1 file; the schema is the gruff.baseline.v1
// contract and the reader throws on any schemaVersion mismatch.
function stableIdentitiesFromBaseline(path: string): Set<string> {
  const baselinePath = absolutize(cwd(), path);
  const baseline = JSON.parse(readFileSync(baselinePath, "utf8")) as { schemaVersion?: string; entries?: BaselineEntry[] };
  if (baseline.schemaVersion !== "gruff.baseline.v1") {
    throw new Error(`unsupported baseline schema in ${path}`);
  }
  return new Set((baseline.entries ?? []).flatMap(stableIdentityFromBaselineEntry));
}

// Resolves one baseline entry to hook identities: its stored identity, or a recomputed one from
// ruleId, filePath, and scope.
function stableIdentityFromBaselineEntry(entry: BaselineEntry): string[] {
  if (typeof entry.stableIdentity === "string") {
    return [entry.stableIdentity];
  }
  if (typeof entry.ruleId !== "string" || typeof entry.filePath !== "string") {
    return [];
  }
  const scope = baselineScopeForRule(entry.ruleId);
  const component = stableIdentityComponent({
    ruleId: entry.ruleId,
    message: entry.message ?? "",
    ...(typeof entry.symbol === "string" ? { symbol: entry.symbol } : {}),
  }, scope);
  return [
    createHash("sha256")
      .update([entry.ruleId, entry.filePath, component].join("\0"))
      .digest("hex")
      .slice(0, 16),
  ];
}

// Maps a rule id to its baseline scope so entries without a stored identity recompute the right
// component.
function baselineScopeForRule(ruleId: string): HookScope {
  if (PROJECT_SCOPE_RULE_IDS.has(ruleId)) {
    return "project";
  }
  if (FILE_SCOPE_RULE_IDS.has(ruleId)) {
    return "file";
  }
  return "line";
}

function stableIdentitiesFromDiffBase(
  runAnalyse: HookAnalysisRunner,
  options: AnalysisOptions,
  diffBase: string,
  currentReport: AnalysisReport,
): Set<string> {
  const ref = diffBaseRef(diffBase);
  if (ref === undefined) {
    return new Set();
  }
  const files = [...new Set(currentReport.findings.map((finding) => finding.filePath))];
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
    return new Set(baseReport.findings.map((finding) => hookStableIdentity(finding, scopeForFinding(finding))));
  } finally {
    chdir(previous);
    rmSync(tempRoot, { recursive: true, force: true });
  }
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
